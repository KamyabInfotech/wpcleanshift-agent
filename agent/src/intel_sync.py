"""
Intelligence Sync Client
~~~~~~~~~~~~~~~~~~~~~~~~~

Pulls threat intelligence updates from the central CleanShift API.
Uses only stdlib (no external dependencies) so the agent can sync
even before pip install.

Features:
    - Hash-based change detection (only download when remote hash differs)
    - Atomic writes (write to .tmp, then os.rename)
    - SHA256 validation of downloaded files before commit
    - Designed for cron / systemd timer via ``auto_sync()``
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("cleanshift.intel_sync")

# Default timeout for all HTTP requests (seconds)
_HTTP_TIMEOUT = 30

# State file stores the last known hash + sync timestamp
_STATE_FILENAME = ".intel_sync_state.json"


class IntelligenceSyncClient:
    """Pull intelligence updates from the central CleanShift API.

    Parameters
    ----------
    api_url : str
        Base URL of the CleanShift API (e.g. ``https://api.cleanshift.example``).
    intel_dir : str | Path
        Local directory where intelligence YAML files are stored.
    api_key : str | None
        Optional API key for authenticated endpoints (file downloads).
    verify_ssl : bool
        Whether to verify SSL certificates (default True).
    """

    def __init__(
        self,
        api_url: str,
        intel_dir: str | Path | None = None,
        api_key: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        # Normalise — strip trailing slash
        self.api_url = api_url.rstrip("/")
        if intel_dir is None:
            intel_dir = Path(__file__).resolve().parent.parent.parent / "intelligence"
        self.intel_dir = Path(intel_dir).resolve()
        self.api_key = api_key
        self.verify_ssl = verify_ssl

        # Ensure the intel directory exists
        self.intel_dir.mkdir(parents=True, exist_ok=True)

        self._state_path = self.intel_dir / _STATE_FILENAME

    # ── Public API ──────────────────────────────────────────────────

    def check_for_updates(self) -> bool:
        """Call ``GET /intelligence/latest`` and compare the combined hash.

        Returns ``True`` if the remote intelligence has changed since the
        last successful sync (or if this is the first check).
        """
        remote = self._fetch_latest()
        if remote is None:
            return False

        local_state = self._load_state()
        remote_hash = remote.get("hash", "")

        if local_state.get("hash") == remote_hash:
            logger.info("Intelligence is up-to-date (hash=%s…)", remote_hash[:12])
            return False

        logger.info(
            "Intelligence update available: remote=%s… local=%s…",
            remote_hash[:12],
            local_state.get("hash", "n/a")[:12],
        )
        return True

    def sync(self) -> dict[str, Any]:
        """Download changed intelligence files and return a sync summary.

        Returns a dict with keys:
            ``downloaded`` — list of filenames that were updated
            ``skipped``   — list of filenames already up-to-date
            ``errors``    — list of {name, error} dicts
            ``version``   — remote version string after sync
        """
        summary: dict[str, Any] = {
            "downloaded": [],
            "skipped": [],
            "errors": [],
            "version": None,
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

        remote = self._fetch_latest()
        if remote is None:
            summary["errors"].append({"name": "_manifest", "error": "Could not fetch remote manifest"})
            return summary

        summary["version"] = remote.get("version")
        remote_files: list[dict] = remote.get("files", [])

        # Build a map of local file hashes for quick comparison
        local_hashes = self._compute_local_hashes()

        for file_info in remote_files:
            name = file_info.get("name", "")
            remote_hash = file_info.get("hash", "")

            if not name:
                continue

            # Skip if local file is already identical
            if local_hashes.get(name) == remote_hash:
                summary["skipped"].append(name)
                continue

            # Download and validate
            try:
                self._download_file(name, remote_hash)
                summary["downloaded"].append(name)
                logger.info("Downloaded: %s", name)
            except Exception as exc:
                summary["errors"].append({"name": name, "error": str(exc)})
                logger.error("Failed to download %s: %s", name, exc)

        # Persist state
        self._save_state({
            "hash": remote.get("hash", ""),
            "version": remote.get("version", ""),
            "last_sync": summary["synced_at"],
            "files_downloaded": len(summary["downloaded"]),
        })

        logger.info(
            "Sync complete: %d downloaded, %d skipped, %d errors",
            len(summary["downloaded"]),
            len(summary["skipped"]),
            len(summary["errors"]),
        )
        return summary

    def auto_sync(self, interval_hours: float = 6) -> dict[str, Any]:
        """Run a single sync cycle (designed for cron/systemd timer).

        If ``interval_hours`` is set, the method checks whether enough
        time has elapsed since the last sync before proceeding.
        """
        local_state = self._load_state()
        last_sync = local_state.get("last_sync")

        if last_sync and interval_hours > 0:
            try:
                last_dt = datetime.fromisoformat(last_sync)
                elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds()
                if elapsed < interval_hours * 3600:
                    logger.info(
                        "Skipping auto-sync — last sync was %.1f hours ago (interval=%.1f)",
                        elapsed / 3600,
                        interval_hours,
                    )
                    return {"updated": False, "files_updated": 0, "skipped": True}
            except (ValueError, TypeError):
                pass  # Corrupted timestamp — proceed with sync

        if self.check_for_updates():
            result = self.sync()
            logger.info("Auto-sync result: %s", json.dumps(result, default=str))
            downloaded = len(result.get("downloaded", []))
            return {
                "updated": downloaded > 0,
                "files_updated": downloaded,
                "skipped": False,
            }
        else:
            logger.info("Auto-sync: no updates available")
            return {"updated": False, "files_updated": 0, "skipped": False}

    def get_status(self) -> dict[str, Any]:
        """Return current sync status information."""
        state = self._load_state()
        local_hashes = self._compute_local_hashes()

        return {
            "intel_dir": str(self.intel_dir),
            "api_url": self.api_url,
            "last_sync": state.get("last_sync", "never"),
            "last_version": state.get("version", "unknown"),
            "last_hash": state.get("hash", "unknown"),
            "local_files": len(local_hashes),
            "files_last_downloaded": state.get("files_downloaded", 0),
        }

    # ── Private Helpers ─────────────────────────────────────────────

    def _fetch_latest(self) -> Optional[dict]:
        """Fetch the ``/intelligence/latest`` manifest from the API."""
        url = f"{self.api_url}/intelligence/latest"
        try:
            data = self._http_get(url, auth=False)
            return json.loads(data)
        except Exception as exc:
            logger.error("Failed to fetch intelligence manifest from %s: %s", url, exc)
            return None

    def _download_file(self, filename: str, expected_hash: str) -> None:
        """Download a single intelligence file with hash validation and atomic write.

        Raises ``ValueError`` if the downloaded file's SHA256 doesn't match.
        """
        url = f"{self.api_url}/intelligence/download/{filename}"
        content = self._http_get(url, auth=True)

        # Validate hash
        actual_hash = hashlib.sha256(content).hexdigest()
        if expected_hash and actual_hash != expected_hash:
            raise ValueError(
                f"Hash mismatch for {filename}: expected {expected_hash[:12]}… got {actual_hash[:12]}…"
            )

        # Determine target path — reconstruct subdirectory from filename
        # Filenames come in as "subdir/file.yaml" from the API
        target = self.intel_dir / filename
        target.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: write to .tmp, then rename
        tmp_path = target.with_suffix(target.suffix + ".tmp")
        try:
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            try:
                os.write(fd, content)
            finally:
                os.close(fd)
            os.rename(str(tmp_path), str(target))
        except Exception:
            # Clean up temp file on failure
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    def _compute_local_hashes(self) -> dict[str, str]:
        """Compute SHA256 hashes for all local YAML files.

        Returns a dict mapping relative path (e.g. ``indicators/ioc-database.yaml``)
        to its hex digest.
        """
        hashes: dict[str, str] = {}
        for subdir in ("indicators", "playbooks", "detection-queries", "cve-db", "attack-chains"):
            dirpath = self.intel_dir / subdir
            if not dirpath.is_dir():
                continue
            for yaml_file in sorted(dirpath.glob("*.yaml")) + sorted(dirpath.glob("*.yml")):
                rel = yaml_file.relative_to(self.intel_dir)
                try:
                    content = yaml_file.read_bytes()
                    hashes[str(rel)] = hashlib.sha256(content).hexdigest()
                except OSError:
                    pass
        return hashes

    def _http_get(self, url: str, auth: bool = False) -> bytes:
        """Perform a GET request using urllib.request (no external deps).

        Parameters
        ----------
        url : str
            Full URL to fetch.
        auth : bool
            If True, include the API key header.

        Returns
        -------
        bytes
            Raw response body.
        """
        headers: dict[str, str] = {
            "User-Agent": "CleanShift-Agent/0.1",
            "Accept": "application/json, application/octet-stream",
        }

        if auth and self.api_key:
            headers["X-API-Key"] = self.api_key

        request = urllib.request.Request(url, headers=headers, method="GET")

        # SSL context
        ctx: Optional[ssl.SSLContext] = None
        if not self.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT, context=ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise ConnectionError(
                f"HTTP {exc.code} from {url}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"Could not reach {url}: {exc.reason}"
            ) from exc

    def _load_state(self) -> dict:
        """Load the local sync state file."""
        try:
            if self._state_path.exists():
                with open(self._state_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read sync state: %s", exc)
        return {}

    def _save_state(self, state: dict) -> None:
        """Persist sync state atomically."""
        tmp = self._state_path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            os.rename(str(tmp), str(self._state_path))
        except OSError as exc:
            logger.error("Could not save sync state: %s", exc)
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass


# Alias for backward compatibility and CLI command imports
IntelSync = IntelligenceSyncClient
