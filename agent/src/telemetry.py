"""Anonymous Threat Telemetry Reporter

Sends anonymized detection data to the central CleanShift API to contribute
to collective threat intelligence. All data is stripped of PII — only file
hashes, detection methods, and general locations are transmitted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("cleanshift.telemetry")


def _anonymize_path(filepath: str, site_path: str = "") -> str:
    """Convert absolute path to anonymized WP-relative location.
    
    /var/www/html/wp-content/uploads/2026/06/evil.php → wp-content/uploads
    /home/user/public_html/wp-includes/admin.php → wp-includes
    """
    path = filepath.replace(site_path, "").lstrip("/")
    parts = Path(path).parts
    # Return up to 2 directory levels
    if len(parts) >= 2:
        return "/".join(parts[:2])
    elif len(parts) == 1:
        return parts[0]
    return "root"


class TelemetryCollector:
    """Collects threat detections during a scan and submits them in batch."""

    def __init__(self, api_url: str, api_key: str, agent_version: str = "1.0.0"):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.agent_version = agent_version
        self.events: list[dict[str, Any]] = []
        self._enabled = os.environ.get("CLEANSHIFT_TELEMETRY", "1") != "0"

    def record(self, filepath: str, threat_type: str, detection_method: str,
               severity: str = "medium", yara_rule: str = "",
               site_path: str = "") -> None:
        """Record a detection event for later submission."""
        if not self._enabled:
            return

        # Hash the file content (not the path — paths are PII)
        try:
            file_hash = hashlib.sha256(Path(filepath).read_bytes()).hexdigest()
        except (OSError, IOError):
            file_hash = hashlib.sha256(filepath.encode()).hexdigest()

        self.events.append({
            "threat_hash": file_hash,
            "threat_type": threat_type,
            "detection_method": detection_method,
            "severity": severity,
            "yara_rule": yara_rule,
            "file_extension": Path(filepath).suffix.lower(),
            "wp_location": _anonymize_path(filepath, site_path),
        })

    def flush(self, scan_type: str = "full") -> bool:
        """Submit collected events to the central API."""
        if not self._enabled or not self.events:
            return True

        import urllib.request
        import urllib.error

        payload = json.dumps({
            "events": self.events[:200],  # Cap at 200 per batch
            "agent_version": self.agent_version,
            "scan_type": scan_type,
        }).encode()

        req = urllib.request.Request(
            f"{self.api_url}/intelligence/telemetry",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                logger.info("Telemetry submitted: %d events accepted", result.get("accepted", 0))
                self.events.clear()
                return True
        except urllib.error.URLError as e:
            logger.debug("Telemetry submission failed (non-fatal): %s", e)
            return False
        except Exception as e:
            logger.debug("Telemetry error (non-fatal): %s", e)
            return False
