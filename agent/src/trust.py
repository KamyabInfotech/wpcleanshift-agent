"""
CleanShift Trust Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~

Unified trust evaluation pipeline for PHP files that merges four
previously separate trust mechanisms:

  1. **ChecksumVerifier** — validates files against official wordpress.org
     checksums.  Files that match receive ``VERIFIED`` status.
  2. **Known-plugins allowlist** — well-known plugins from the official
     repository.  Files belonging to these receive ``KNOWN`` status with
     an ``allowed_capabilities`` whitelist that suppresses false positives.
  3. **Developer acknowledgment** — ``.cleanshift-allow`` files placed
     by site owners to mark intentionally-modified or custom code.
     Files listed receive ``ACKNOWLEDGED`` status.
  4. **Behavioral diff** — for ``MODIFIED`` official files, only *new*
     capabilities (not present in the original) are flagged.

Pipeline order for ``evaluate(filepath, site)``:

  1. Is it a WP/CMS core file? -> ChecksumVerifier -> match? -> VERIFIED
  2. Is it from wordpress.org (or other official repo)? -> VERIFIED
  3. Is it in the known-plugins allowlist? -> KNOWN (reduced scrutiny)
  4. Has a developer acknowledged it? -> .cleanshift-allow -> ACKNOWLEDGED
  5. Is it a modified official file? -> MODIFIED (run behavioral diff)
  6. None of the above -> UNKNOWN (full analysis)

Python 3.6+.  No external dependencies -- stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path

try:
    from typing import Any, Dict, List, Optional, Set, Tuple
except ImportError:
    pass

from .verifier import ChecksumVerifier, VerifyResult

logger = logging.getLogger("cleanshift.trust")


# ─── Trust Levels ───────────────────────────────────────────────────

class TrustLevel(object):
    """
    Trust levels assigned to files during the trust evaluation pipeline.

    Levels (ordered from most trusted to least):
        VERIFIED     — checksum matches official wordpress.org source.
        KNOWN        — belongs to a known-plugins allowlist entry.
        ACKNOWLEDGED — developer explicitly marked as intentional.
        MODIFIED     — official file but content has been changed.
        UNKNOWN      — no verification possible; full analysis required.
    """
    VERIFIED = "verified"
    KNOWN = "known"
    ACKNOWLEDGED = "acknowledged"
    MODIFIED = "modified"
    UNKNOWN = "unknown"


# ─── Trust Result ───────────────────────────────────────────────────

class TrustResult(object):
    """
    Result of trust evaluation for a single file.

    Attributes:
        level:                TrustLevel constant.
        reason:               Human-readable explanation.
        allowed_capabilities: Set of capability names that are expected
                              for this file's plugin context.  Only
                              populated for KNOWN-level files.
        plugin_slug:          If the file belongs to a known plugin,
                              the slug.  Empty string otherwise.
    """

    def __init__(
        self,
        level="unknown",       # type: str
        reason="",             # type: str
        allowed_capabilities=None,  # type: Optional[List[str]]
        plugin_slug="",        # type: str
    ):
        # type: (...) -> None
        self.level = level
        self.reason = reason
        self.allowed_capabilities = allowed_capabilities if allowed_capabilities is not None else []
        self.plugin_slug = plugin_slug

    def __repr__(self):
        # type: () -> str
        return "TrustResult(level=%r, reason=%r, plugin=%r)" % (
            self.level, self.reason, self.plugin_slug,
        )


# ─── Known Plugins Allowlist ────────────────────────────────────────

KNOWN_PLUGINS = {
    "woocommerce": {
        "allowed_capabilities": [
            "accesses_database", "makes_http_calls",
            "reads_http_input", "manipulates_options",
        ],
    },
    "elementor": {
        "allowed_capabilities": [
            "makes_http_calls", "modifies_files",
            "reads_http_input", "filesystem_discovery",
        ],
    },
    "jetpack": {
        "allowed_capabilities": [
            "makes_http_calls", "reads_credentials",
            "manipulates_options", "reads_http_input",
        ],
    },
    "wordfence": {
        "allowed_capabilities": [
            "reads_credentials", "makes_http_calls",
            "filesystem_discovery", "process_execution",
        ],
    },
    "updraftplus": {
        "allowed_capabilities": [
            "makes_http_calls", "modifies_files",
            "filesystem_discovery", "reads_credentials",
        ],
    },
    "contact-form-7": {
        "allowed_capabilities": [
            "reads_http_input", "makes_http_calls",
        ],
    },
    "yoast": {
        "allowed_capabilities": [
            "accesses_database", "makes_http_calls",
            "manipulates_options",
        ],
    },
    "wpforms": {
        "allowed_capabilities": [
            "reads_http_input", "makes_http_calls",
            "accesses_database",
        ],
    },
    "akismet": {
        "allowed_capabilities": [
            "makes_http_calls", "reads_http_input",
            "accesses_database",
        ],
    },
    "sucuri-scanner": {
        "allowed_capabilities": [
            "reads_credentials", "makes_http_calls",
            "filesystem_discovery", "process_execution",
        ],
    },
    "ithemes-security": {
        "allowed_capabilities": [
            "reads_credentials", "makes_http_calls",
            "filesystem_discovery", "accesses_database",
        ],
    },
    "all-in-one-wp-migration": {
        "allowed_capabilities": [
            "modifies_files", "makes_http_calls",
            "filesystem_discovery", "reads_credentials",
        ],
    },
    "duplicator": {
        "allowed_capabilities": [
            "modifies_files", "makes_http_calls",
            "filesystem_discovery", "reads_credentials",
            "accesses_database",
        ],
    },
    "wp-mail-smtp": {
        "allowed_capabilities": [
            "makes_http_calls", "reads_credentials",
        ],
    },
    "advanced-custom-fields": {
        "allowed_capabilities": [
            "accesses_database", "reads_http_input",
            "manipulates_options",
        ],
    },
    "wp-rocket": {
        "allowed_capabilities": [
            "modifies_files", "filesystem_discovery",
            "manipulates_options",
        ],
    },
    "litespeed-cache": {
        "allowed_capabilities": [
            "modifies_files", "makes_http_calls",
            "filesystem_discovery", "manipulates_options",
        ],
    },
    "really-simple-ssl": {
        "allowed_capabilities": [
            "manipulates_options", "modifies_files",
        ],
    },
    "redirection": {
        "allowed_capabilities": [
            "accesses_database", "reads_http_input",
        ],
    },
    "classic-editor": {
        "allowed_capabilities": [],
    },
    "wp-super-cache": {
        "allowed_capabilities": [
            "modifies_files", "filesystem_discovery",
        ],
    },
    "google-analytics-for-wordpress": {
        "allowed_capabilities": [
            "makes_http_calls", "manipulates_options",
        ],
    },
    "w3-total-cache": {
        "allowed_capabilities": [
            "modifies_files", "makes_http_calls",
            "filesystem_discovery",
        ],
    },
    "tablepress": {
        "allowed_capabilities": [
            "accesses_database",
        ],
    },
    "woocommerce-payments": {
        "allowed_capabilities": [
            "makes_http_calls", "reads_http_input",
            "accesses_database",
        ],
    },
    "mailchimp-for-wp": {
        "allowed_capabilities": [
            "makes_http_calls", "reads_http_input",
        ],
    },
    "wp-optimize": {
        "allowed_capabilities": [
            "accesses_database", "modifies_files",
            "filesystem_discovery",
        ],
    },
    "backwpup": {
        "allowed_capabilities": [
            "makes_http_calls", "modifies_files",
            "filesystem_discovery", "reads_credentials",
        ],
    },
    "ninja-forms": {
        "allowed_capabilities": [
            "reads_http_input", "makes_http_calls",
            "accesses_database",
        ],
    },
    "gravityforms": {
        "allowed_capabilities": [
            "reads_http_input", "makes_http_calls",
            "accesses_database", "modifies_files",
        ],
    },
}  # type: Dict[str, Dict[str, Any]]


# ─── Trust Engine ───────────────────────────────────────────────────

class TrustEngine(object):
    """
    Unified trust evaluation for PHP files.

    Pipeline:
      1. Is it a WP/CMS core file?  -> ChecksumVerifier -> match? -> VERIFIED
      2. Is it from wordpress.org (or other official repo)?
         -> ChecksumVerifier -> match? -> VERIFIED
      3. Is it in the known-plugins allowlist? -> KNOWN (reduced scrutiny)
      4. Has a developer acknowledged it?
         -> Check .cleanshift-allow -> ACKNOWLEDGED
      5. Is it a modified official file? -> MODIFIED (run behavioral diff)
      6. None of the above -> UNKNOWN (full analysis)

    Usage::

        engine = TrustEngine()
        result = engine.evaluate('/var/www/html/wp-content/plugins/akismet/akismet.php', site)
        if result.level == TrustLevel.VERIFIED:
            pass  # skip scanning
        elif result.level == TrustLevel.KNOWN:
            # only flag capabilities outside result.allowed_capabilities
            ...
    """

    # Pattern for wp-content/plugins/<slug>/ or wp-content/themes/<slug>/
    _PLUGIN_PATH_RE = re.compile(
        r"wp-content/(?:plugins|themes)/([^/]+)/",
    )

    def __init__(
        self,
        checksum_verifier=None,  # type: Optional[ChecksumVerifier]
        known_plugins=None,      # type: Optional[Dict[str, Dict[str, Any]]]
    ):
        # type: (...) -> None
        """
        Initialise the trust engine.

        Args:
            checksum_verifier: An existing ChecksumVerifier instance.
                               If None, a new one is created.
            known_plugins:     Override the KNOWN_PLUGINS allowlist
                               (mainly for testing).
        """
        if checksum_verifier is not None:
            self._verifier = checksum_verifier
        else:
            try:
                self._verifier = ChecksumVerifier()
            except Exception as exc:
                logger.warning("Could not create ChecksumVerifier: %s", exc)
                self._verifier = None

        self._known_plugins = known_plugins if known_plugins is not None else KNOWN_PLUGINS

        # Cache of parsed .cleanshift-allow files:
        #   dir_path -> (parsed_dict, file_mtime)
        self._allow_cache = {}  # type: Dict[str, Tuple[Dict[str, Any], float]]

    # ── Public API ──────────────────────────────────────────────────

    def evaluate(self, filepath, site):
        # type: (str, Any) -> TrustResult
        """
        Evaluate the trust level of a file.

        Runs the pipeline in order (checksum -> allowlist ->
        acknowledgment -> modified -> unknown) and returns the first
        match.

        Args:
            filepath: Absolute path to the file.
            site:     WordPressSite instance.

        Returns:
            TrustResult with trust level, reason, and allowed capabilities.
        """
        try:
            return self._evaluate_internal(filepath, site)
        except Exception as exc:
            logger.debug("Trust evaluation error for %s: %s", filepath, exc)
            return TrustResult(
                level=TrustLevel.UNKNOWN,
                reason="Trust evaluation failed: %s" % str(exc),
            )

    def _evaluate_internal(self, filepath, site):
        # type: (str, Any) -> TrustResult
        """Internal pipeline — may raise on I/O errors."""

        # Step 1 & 2: Official checksum verification
        checksum_result = self._check_official_checksums(filepath, site)
        if checksum_result is not None:
            return checksum_result

        # Step 3: Known-plugins allowlist
        allowlist_result = self._check_allowlist(filepath)
        if allowlist_result is not None:
            return allowlist_result

        # Step 4: Developer acknowledgment
        ack_result = self._check_acknowledgment(filepath)
        if ack_result is not None:
            return ack_result

        # Step 6: Nothing matched -> UNKNOWN
        return TrustResult(
            level=TrustLevel.UNKNOWN,
            reason="File not matched by any trust mechanism",
        )

    # ── Step 1 & 2: Official Checksums ──────────────────────────────

    def _check_official_checksums(self, filepath, site):
        # type: (str, Any) -> Optional[TrustResult]
        """
        Check the file against official wordpress.org checksums.

        Returns TrustResult if the file is in core or plugin checksums,
        None if not applicable.
        """
        if self._verifier is None:
            return None

        site_path = site.path  # type: str
        try:
            # Compute relative path from site root
            rel_path = os.path.relpath(filepath, site_path)
        except (ValueError, TypeError):
            return None

        # Normalise to forward slashes
        rel_path = rel_path.replace("\\", "/")

        # Skip files outside the site root
        if rel_path.startswith(".."):
            return None

        try:
            result = self._verifier.verify_file(site, rel_path)
        except Exception as exc:
            logger.debug("Checksum verify error for %s: %s", rel_path, exc)
            return None

        if result == VerifyResult.OFFICIAL:
            return TrustResult(
                level=TrustLevel.VERIFIED,
                reason="File matches official wordpress.org checksum",
            )

        if result == VerifyResult.MODIFIED:
            return TrustResult(
                level=TrustLevel.MODIFIED,
                reason="File is in official checksums but has been modified",
            )

        # VerifyResult.CUSTOM or UNKNOWN -> continue pipeline
        return None

    # ── Step 3: Known-plugins Allowlist ─────────────────────────────

    def _check_allowlist(self, filepath):
        # type: (str) -> Optional[TrustResult]
        """
        Check whether the file belongs to a known plugin in the allowlist.

        Matches by extracting the plugin slug from the file path
        (wp-content/plugins/<slug>/ or wp-content/themes/<slug>/).

        Returns TrustResult if matched, None otherwise.
        """
        # Normalise path
        norm_path = filepath.replace("\\", "/")

        match = self._PLUGIN_PATH_RE.search(norm_path)
        if not match:
            return None

        slug = match.group(1).lower()

        if slug in self._known_plugins:
            plugin_info = self._known_plugins[slug]
            allowed = plugin_info.get("allowed_capabilities", [])
            return TrustResult(
                level=TrustLevel.KNOWN,
                reason="File belongs to known plugin: %s" % slug,
                allowed_capabilities=list(allowed),
                plugin_slug=slug,
            )

        return None

    # ── Step 4: Developer Acknowledgment ────────────────────────────

    def _check_acknowledgment(self, filepath):
        # type: (str) -> Optional[TrustResult]
        """
        Check whether the file is covered by a .cleanshift-allow file.

        Walks up from the file's directory looking for
        ``.cleanshift-allow`` files.  If found, checks whether the
        current file is listed (by relative path from the allow-file's
        directory) and whether the acknowledgment has expired.

        Returns TrustResult if acknowledged, None otherwise.
        """
        try:
            file_path = Path(filepath)
            file_dir = file_path.parent
        except (TypeError, ValueError):
            return None

        # Walk up directories looking for .cleanshift-allow
        current_dir = file_dir
        for _ in range(20):  # Safety limit to prevent infinite loop
            allow_file = current_dir / ".cleanshift-allow"
            if allow_file.is_file():
                allow_data = self._parse_allow_file(str(allow_file))
                if allow_data is not None:
                    result = self._check_file_in_allowdata(
                        filepath, str(current_dir), allow_data,
                    )
                    if result is not None:
                        return result

            # Move up one level
            parent = current_dir.parent
            if parent == current_dir:
                break  # Reached filesystem root
            current_dir = parent

        return None

    def _parse_allow_file(self, allow_file_path):
        # type: (str) -> Optional[Dict[str, Any]]
        """
        Parse a .cleanshift-allow file (simple YAML-like key: value).

        Caches results based on file mtime.

        Returns parsed dict or None on error.
        """
        try:
            stat_info = os.stat(allow_file_path)
            mtime = stat_info.st_mtime
        except (OSError, IOError):
            return None

        # Check cache
        cached = self._allow_cache.get(allow_file_path)
        if cached is not None:
            cached_data, cached_mtime = cached
            if cached_mtime == mtime:
                return cached_data

        # Parse the file
        try:
            with open(allow_file_path, "r") as fh:
                content = fh.read(65536)
        except (OSError, IOError) as exc:
            logger.debug("Cannot read allow file %s: %s", allow_file_path, exc)
            return None

        data = self._parse_simple_yaml(content)

        # Cache the result
        self._allow_cache[allow_file_path] = (data, mtime)
        return data

    @staticmethod
    def _parse_simple_yaml(content):
        # type: (str) -> Dict[str, Any]
        """
        Minimal YAML-like parser for .cleanshift-allow files.

        Handles:
          - ``key: value`` pairs
          - ``file_hashes:`` section with indented ``filename: hash`` entries
          - Comments (lines starting with #)
          - Quoted and unquoted values

        This avoids a PyYAML dependency.
        """
        result = {}  # type: Dict[str, Any]
        file_hashes = {}  # type: Dict[str, str]
        in_file_hashes = False

        for line in content.split("\n"):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Check indentation for file_hashes section
            if in_file_hashes and line.startswith(("  ", "\t")):
                # Parse indented key: value
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    k = parts[0].strip()
                    v = parts[1].strip().strip("'\"")
                    file_hashes[k] = v
                continue
            else:
                if in_file_hashes:
                    in_file_hashes = False
                    result["file_hashes"] = file_hashes

            # Parse top-level key: value
            parts = stripped.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip().strip("'\"")

                if key == "file_hashes" and not value:
                    in_file_hashes = True
                    file_hashes = {}
                else:
                    result[key] = value

        # Flush any remaining file_hashes
        if in_file_hashes and file_hashes:
            result["file_hashes"] = file_hashes

        return result

    def _check_file_in_allowdata(self, filepath, allow_dir, allow_data):
        # type: (str, str, Dict[str, Any]) -> Optional[TrustResult]
        """
        Check whether a specific file is covered by an allow-data dict.

        Validates:
          - The file is listed in ``file_hashes`` (if present)
          - The SHA256 hash still matches (if specified)
          - The acknowledgment hasn't expired

        Args:
            filepath:   Absolute path to the file being evaluated.
            allow_dir:  Directory where the .cleanshift-allow was found.
            allow_data: Parsed allow-file dict.

        Returns:
            TrustResult if acknowledged, None if not covered or expired.
        """
        # Check expiry
        expires = allow_data.get("expires", "")
        if expires:
            try:
                # Parse ISO date (YYYY-MM-DD)
                parts = expires.split("-")
                if len(parts) == 3:
                    import datetime
                    exp_date = datetime.date(
                        int(parts[0]), int(parts[1]), int(parts[2]),
                    )
                    today = datetime.date.today()
                    if today > exp_date:
                        logger.info(
                            "Acknowledgment expired (%s) for allow file in %s",
                            expires, allow_dir,
                        )
                        return None
            except (ValueError, TypeError) as exc:
                logger.debug("Invalid expiry date '%s': %s", expires, exc)
                # Treat as not expired if unparseable

        # Get the relative path from allow_dir to the file
        try:
            rel_path = os.path.relpath(filepath, allow_dir)
        except (ValueError, TypeError):
            return None
        rel_path = rel_path.replace("\\", "/")

        # Check file_hashes section
        file_hashes = allow_data.get("file_hashes")
        if isinstance(file_hashes, dict):
            if rel_path not in file_hashes:
                return None

            # Optionally verify SHA256
            expected_hash = file_hashes.get(rel_path, "")
            if expected_hash and len(expected_hash) >= 6:
                actual_hash = self._compute_sha256(filepath)
                if actual_hash and actual_hash != expected_hash:
                    logger.info(
                        "Acknowledgment hash mismatch for %s "
                        "(expected=%s, actual=%s)",
                        rel_path, expected_hash[:12], actual_hash[:12],
                    )
                    return None
        else:
            # No file_hashes section -> the allow file covers
            # ALL files in its directory (legacy / simple mode)
            pass

        acknowledged_by = allow_data.get("acknowledged_by", "unknown")
        reason_text = allow_data.get("reason", "Developer acknowledged")

        return TrustResult(
            level=TrustLevel.ACKNOWLEDGED,
            reason="Acknowledged by %s: %s" % (acknowledged_by, reason_text),
        )

    # ── Step 5: Behavioral Diff ─────────────────────────────────────

    def behavioral_diff(self, filepath, original_caps, current_caps):
        # type: (str, List[str], List[str]) -> List[str]
        """
        Compare original capabilities with current capabilities.

        Only returns capabilities that are NEW -- present in current
        but NOT in the original.  This avoids flagging expected
        capabilities that existed before modification.

        Args:
            filepath:      File path (for logging).
            original_caps: Capabilities expected in the official file.
            current_caps:  Capabilities detected in the current file.

        Returns:
            List of new capability names not present in the original.
        """
        original_set = set(original_caps)
        current_set = set(current_caps)

        new_caps = sorted(current_set - original_set)

        if new_caps:
            logger.info(
                "Behavioral diff for %s: %d new capabilities: %s",
                os.path.basename(filepath),
                len(new_caps),
                ", ".join(new_caps),
            )

        return new_caps

    # ── Utility ─────────────────────────────────────────────────────

    @staticmethod
    def _compute_sha256(filepath):
        # type: (str) -> str
        """
        Compute SHA256 hex digest of a file.

        Returns empty string on error.
        """
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, IOError, PermissionError):
            return ""

    @staticmethod
    def extract_plugin_slug(filepath):
        # type: (str) -> str
        """
        Extract the plugin or theme slug from a file path.

        Looks for ``wp-content/plugins/<slug>/`` or
        ``wp-content/themes/<slug>/`` in the path.

        Args:
            filepath: Absolute or relative file path.

        Returns:
            Plugin/theme slug, or empty string if not found.
        """
        norm = filepath.replace("\\", "/")
        match = re.search(
            r"wp-content/(?:plugins|themes)/([^/]+)/", norm,
        )
        if match:
            return match.group(1).lower()
        return ""
