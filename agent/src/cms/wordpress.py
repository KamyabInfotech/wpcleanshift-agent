"""
CleanShift CMS Adapter — WordPress
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Concrete :class:`CMSAdapter` implementation for WordPress sites.

Detection relies on the presence of ``wp-config.php``.  Version
extraction parses ``wp-includes/version.php``.  Core-integrity and
extension auditing delegate to WP-CLI subprocess calls with timeouts
and structured error handling.

All subprocess invocations:
    • use ``timeout=30`` to avoid hangs on unresponsive WP-CLI
    • capture both stdout and stderr
    • return graceful empty results on failure
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import CMSAdapter

logger = logging.getLogger("cleanshift.cms.wordpress")

# Pre-compiled regexes (mirrors patterns in platform.py)
_WP_VERSION_RE = re.compile(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]")
_WP_DEFINE_RE = re.compile(
    r"define\s*\(\s*['\"](\w+)['\"]\s*,\s*['\"]([^'\"]*)['\"]",
)
_WP_TABLE_PREFIX_RE = re.compile(
    r"\$table_prefix\s*=\s*['\"]([^'\"]*)['\"]",
)

# Default WP-CLI timeout for every subprocess call (seconds).
_WPCLI_TIMEOUT: int = 30


# ── Helpers ──────────────────────────────────────────────────────────

def _safe_read_text(filepath: Path, max_bytes: int = 262_144) -> str:
    """Read a text file safely, returning empty string on any error."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except (OSError, IOError, PermissionError):
        return ""


def _run_wpcli(
    args: List[str],
    *,
    cwd: Path,
    timeout: int = _WPCLI_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run a WP-CLI command with a timeout.

    Args:
        args:    Arguments to pass after ``wp`` (e.g. ``["core", "version"]``).
        cwd:     Working directory (the WordPress root).
        timeout: Seconds before the subprocess is killed.

    Returns:
        A :class:`subprocess.CompletedProcess`.

    Raises:
        subprocess.TimeoutExpired: if the command exceeds *timeout*.
        FileNotFoundError:         if ``wp`` is not on ``$PATH``.
    """
    cmd = ["wp", "--no-color", "--allow-root", *args]
    logger.debug("Running WP-CLI: %s (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ── Adapter ──────────────────────────────────────────────────────────


class WordPressAdapter(CMSAdapter):
    """CMS adapter for WordPress installations."""

    # ── Identity ─────────────────────────────────────────────────────

    @property
    def name(self) -> str:  # noqa: D401
        """Human-readable CMS name."""
        return "WordPress"

    @property
    def priority(self) -> int:  # noqa: D401
        """Detection priority (high — WordPress is the most common CMS)."""
        return 100

    # ── Detection ────────────────────────────────────────────────────

    def detect(self, path: Path) -> bool:
        """Return ``True`` if *path* contains a ``wp-config.php`` file."""
        target = path / "wp-config.php"
        found = target.is_file()
        if found:
            logger.info("WordPress detected at %s", path)
        else:
            logger.debug("wp-config.php not found at %s", path)
        return found

    # ── Version ──────────────────────────────────────────────────────

    def get_version(self, path: Path) -> Optional[str]:
        """Parse ``wp-includes/version.php`` for ``$wp_version``.

        Falls back to WP-CLI ``core version`` if file parsing fails.
        """
        version_file = path / "wp-includes" / "version.php"
        content = _safe_read_text(version_file)
        if content:
            match = _WP_VERSION_RE.search(content)
            if match:
                version = match.group(1)
                logger.info("WordPress version %s (from version.php)", version)
                return version

        # Fallback: WP-CLI
        try:
            result = _run_wpcli(["core", "version"], cwd=path)
            if result.returncode == 0 and result.stdout.strip():
                version = result.stdout.strip()
                logger.info("WordPress version %s (from WP-CLI)", version)
                return version
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("WP-CLI core version failed: %s", exc)

        logger.debug("Could not determine WordPress version at %s", path)
        return None

    # ── Database config ──────────────────────────────────────────────

    def get_database_config(self, path: Path) -> Dict[str, Any]:
        """Parse ``wp-config.php`` for database connection parameters.

        Extracts ``define()`` calls for ``DB_NAME``, ``DB_USER``,
        ``DB_PASSWORD``, ``DB_HOST``, ``DB_CHARSET``, and the
        ``$table_prefix`` variable.
        """
        config_file = path / "wp-config.php"
        content = _safe_read_text(config_file)
        if not content:
            logger.debug("wp-config.php unreadable at %s", path)
            return {}

        # Collect all define()'d constants
        defines: Dict[str, str] = {}
        for match in _WP_DEFINE_RE.finditer(content):
            defines[match.group(1)] = match.group(2)

        # Table prefix
        prefix_match = _WP_TABLE_PREFIX_RE.search(content)
        table_prefix = prefix_match.group(1) if prefix_match else "wp_"

        config: Dict[str, Any] = {
            "db_host": defines.get("DB_HOST", "localhost"),
            "db_name": defines.get("DB_NAME", ""),
            "db_user": defines.get("DB_USER", ""),
            "db_password": defines.get("DB_PASSWORD", ""),
            "db_charset": defines.get("DB_CHARSET", "utf8mb4"),
            "db_prefix": table_prefix,
        }

        logger.debug(
            "Parsed wp-config.php: db_name=%s, db_user=%s, db_host=%s",
            config["db_name"],
            config["db_user"],
            config["db_host"],
        )
        return config

    # ── Core integrity ───────────────────────────────────────────────

    def verify_core_integrity(self, path: Path) -> List[Dict[str, Any]]:
        """Run ``wp core verify-checksums`` and parse the output.

        Returns a list of anomaly dicts with keys ``file``, ``status``,
        and ``detail``.
        """
        anomalies: List[Dict[str, Any]] = []

        try:
            result = _run_wpcli(["core", "verify-checksums"], cwd=path)
        except subprocess.TimeoutExpired:
            logger.warning("WP-CLI verify-checksums timed out at %s", path)
            return [
                {
                    "file": "<timeout>",
                    "status": "error",
                    "detail": "WP-CLI verify-checksums timed out",
                }
            ]
        except FileNotFoundError:
            logger.warning("WP-CLI not found on PATH; skipping core integrity check")
            return [
                {
                    "file": "<wp-cli>",
                    "status": "error",
                    "detail": "WP-CLI is not installed or not on PATH",
                }
            ]
        except OSError as exc:
            logger.warning("WP-CLI verify-checksums OS error: %s", exc)
            return [
                {
                    "file": "<os-error>",
                    "status": "error",
                    "detail": str(exc),
                }
            ]

        if result.returncode == 0:
            logger.info("WordPress core integrity OK at %s", path)
            return []

        # Parse stderr/stdout for file-level anomalies.
        # WP-CLI outputs lines like:
        #   Warning: File doesn't verify against its checksum: wp-admin/foo.php
        #   Warning: File should not exist: wp-admin/bar.php
        output = (result.stderr or "") + "\n" + (result.stdout or "")
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if "doesn't verify" in line or "doesn't exist" in line.lower():
                # Extract the filename at the end of the message
                parts = line.rsplit(":", 1)
                filename = parts[-1].strip() if len(parts) > 1 else line
                anomalies.append(
                    {
                        "file": filename,
                        "status": "modified",
                        "detail": line,
                    }
                )
            elif "should not exist" in line.lower():
                parts = line.rsplit(":", 1)
                filename = parts[-1].strip() if len(parts) > 1 else line
                anomalies.append(
                    {
                        "file": filename,
                        "status": "unknown",
                        "detail": line,
                    }
                )

        # If we got a non-zero exit but no parsed anomalies, add a
        # generic record so the caller knows something went wrong.
        if not anomalies:
            anomalies.append(
                {
                    "file": "<verify-checksums>",
                    "status": "error",
                    "detail": output.strip()[:500],
                }
            )

        logger.info(
            "WordPress core integrity: %d anomalies at %s",
            len(anomalies),
            path,
        )
        return anomalies

    # ── Extension audit ──────────────────────────────────────────────

    def audit_extensions(self, path: Path) -> List[Dict[str, Any]]:
        """Run ``wp plugin list --format=json`` and return parsed results.

        Each dict contains at least ``name``, ``version``, ``status``,
        ``update``, and ``vulnerabilities`` (always an empty list here;
        cross-referencing with advisory databases is the caller's job).
        """
        plugins: List[Dict[str, Any]] = []

        try:
            result = _run_wpcli(
                ["plugin", "list", "--format=json"],
                cwd=path,
            )
        except subprocess.TimeoutExpired:
            logger.warning("WP-CLI plugin list timed out at %s", path)
            return []
        except FileNotFoundError:
            logger.warning("WP-CLI not found on PATH; skipping extension audit")
            return []
        except OSError as exc:
            logger.warning("WP-CLI plugin list OS error: %s", exc)
            return []

        if result.returncode != 0:
            logger.warning(
                "WP-CLI plugin list failed (rc=%d): %s",
                result.returncode,
                (result.stderr or "").strip()[:200],
            )
            return []

        try:
            raw: List[Dict[str, Any]] = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Failed to parse WP-CLI plugin list JSON: %s", exc)
            return []

        for entry in raw:
            plugins.append(
                {
                    "name": entry.get("name", ""),
                    "version": entry.get("version", ""),
                    "status": entry.get("status", ""),
                    "update": entry.get("update", "none"),
                    "vulnerabilities": [],  # populated downstream
                }
            )

        logger.info(
            "WordPress extension audit: %d plugins at %s",
            len(plugins),
            path,
        )
        return plugins
