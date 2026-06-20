"""CleanShift Agent API Client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Lightweight HTTP client for submitting scan results, polling for
pending scan requests, and acknowledging pickups. Uses only stdlib
(``urllib.request``) so the agent runs on bare servers without
third-party HTTP libraries.

Retry semantics:
    When the central API is unreachable, scan results are written
    to the local ``ResultBuffer`` (SQLite). On the next successful
    connection, ``flush_buffer()`` replays buffered results.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .models import ScanResult
from .result_buffer import ResultBuffer

logger = logging.getLogger("cleanshift.api_client")


class AgentAPIClient:
    """HTTP client the CleanShift agent uses to talk to the central API.

    Parameters:
        api_url: Base URL of the CleanShift API (e.g. ``https://api-cleanshift.osg.co.in``).
        api_key: API key for the ``X-API-Key`` header.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, api_url: str, api_key: str, *, timeout: int = 15) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._buffer = ResultBuffer()

    # ── Internal helpers ────────────────────────────────────────────

    def _headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        """Build common request headers."""
        headers: Dict[str, str] = {"X-API-Key": self.api_key}
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Execute an HTTP request and return the parsed JSON response.

        Returns ``None`` on any network or server error (logged, never raised).
        """
        url = f"{self.api_url}{path}"
        data: Optional[bytes] = None
        content_type: Optional[str] = None

        if body is not None:
            data = json.dumps(body, default=str).encode("utf-8")
            content_type = "application/json"

        req = urllib.request.Request(
            url,
            data=data,
            headers=self._headers(content_type),
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_body = resp.read()
                if resp_body:
                    return json.loads(resp_body)
                return {}
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            logger.warning(
                "API %s %s returned HTTP %d: %s",
                method, path, exc.code, err_body,
            )
            return None
        except urllib.error.URLError as exc:
            logger.warning("API %s %s unreachable: %s", method, path, exc.reason)
            return None
        except Exception as exc:
            logger.warning("API %s %s failed: %s", method, path, exc)
            return None

    # ── Public API ──────────────────────────────────────────────────

    def submit_scan_result(
        self,
        scan_result: ScanResult,
        sites_data: List[Dict[str, Any]],
        scan_type: str = "full",
    ) -> bool:
        """Submit a completed scan to ``POST /scans``.

        Converts the agent-side ``ScanResult`` model into the
        ``ScanSubmission`` schema expected by the API:

        .. code-block:: json

            {
                "scan_type": "full",
                "started_at": "...",
                "completed_at": "...",
                "sites": [...],
                "threats": [...]
            }

        On failure the payload is stored in the local
        :class:`ResultBuffer` for later retry.

        Returns:
            ``True`` if the API accepted the submission, ``False``
            otherwise (result is buffered).
        """
        threats_payload: List[Dict[str, Any]] = []
        for threat in scan_result.threats:
            threats_payload.append({
                "site_path": threat.site_path,
                "site_domain": self._domain_for_site(
                    threat.site_path, sites_data,
                ),
                "threat_type": (
                    threat.threat_type.value
                    if hasattr(threat.threat_type, "value")
                    else str(threat.threat_type)
                ),
                "severity": (
                    threat.severity.value
                    if hasattr(threat.severity, "value")
                    else str(threat.severity)
                ),
                "title": threat.title,
                "description": threat.description,
                "location": threat.location,
                "evidence": threat.details if threat.details else {},
            })

        payload: Dict[str, Any] = {
            "scan_type": scan_type,
            "started_at": scan_result.scan_started,
            "completed_at": scan_result.scan_completed or scan_result.scan_started,
            "sites": sites_data,
            "threats": threats_payload,
            "system_metrics": self._collect_system_metrics(),
        }

        resp = self._request("POST", "/scans", body=payload)

        if resp is not None:
            logger.info(
                "Scan results submitted successfully (%d threats, %d sites)",
                len(threats_payload),
                len(sites_data),
            )
            return True

        # API unreachable — buffer for retry
        logger.info("Buffering scan results for later submission")
        self._buffer.store(payload)
        return False

    def poll_pending_scans(self) -> List[Dict[str, Any]]:
        """Check for pending scan requests from the dashboard.

        ``GET /scans/pending``

        Returns:
            List of pending request dicts, each with at least
            ``id``, ``scan_type``, and ``requested_by`` keys.
            Returns an empty list on any error.
        """
        resp = self._request("GET", "/scans/pending")

        if resp is None:
            return []

        # The API may wrap results in a top-level key
        if isinstance(resp, dict):
            pending = resp.get("pending", resp.get("data", []))
            if isinstance(pending, list):
                return pending
            # Response is the list itself (bare dict — shouldn't happen
            # but be defensive)
            return [resp]

        if isinstance(resp, list):
            return resp

        return []

    def ack_scan_request(self, request_id: str) -> bool:
        """Acknowledge a pending scan request.

        ``POST /scans/pending/{request_id}/ack``

        Returns:
            ``True`` on success, ``False`` on failure.
        """
        resp = self._request("POST", f"/scans/pending/{request_id}/ack")
        if resp is not None:
            logger.info("Acknowledged scan request %s", request_id)
            return True
        logger.warning("Failed to acknowledge scan request %s", request_id)
        return False

    def flush_buffer(self) -> int:
        """Retry submitting any locally buffered scan results.

        Returns:
            Number of successfully flushed results.
        """
        pending = self._buffer.get_pending()
        if not pending:
            return 0

        logger.info("Flushing %d buffered scan result(s)", len(pending))
        flushed = 0

        for row_id, payload in pending:
            resp = self._request("POST", "/scans", body=payload)
            if resp is not None:
                self._buffer.mark_sent(row_id)
                flushed += 1
                logger.info("Flushed buffered result id=%d", row_id)
            else:
                self._buffer.mark_failed(row_id, "API still unreachable")

        # Housekeeping — remove old/abandoned entries
        self._buffer.cleanup_old()
        return flushed

    # ── Private helpers ─────────────────────────────────────────────

    @staticmethod
    def _domain_for_site(
        site_path: str,
        sites_data: List[Dict[str, Any]],
    ) -> str:
        """Look up the domain for a given site path from sites_data."""
        for site in sites_data:
            if site.get("path") == site_path:
                return site.get("domain", "")
        return ""

    @staticmethod
    def _collect_system_metrics() -> Dict[str, float]:
        """Collect CPU, memory, and disk usage using stdlib only.

        Uses /proc/ on Linux (where agents run). Returns zeros on
        non-Linux systems or on any read failure.
        """
        metrics: Dict[str, float] = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
        }

        try:
            # CPU: read /proc/loadavg — 1-min load average / number of CPUs
            if os.path.exists("/proc/loadavg"):
                with open("/proc/loadavg", "r") as f:
                    load_1m = float(f.read().split()[0])
                cpu_count = os.cpu_count() or 1
                # Convert load average to percentage (capped at 100)
                metrics["cpu_usage"] = round(min(load_1m / cpu_count * 100, 100.0), 1)
        except Exception:
            pass

        try:
            # Memory: read /proc/meminfo
            if os.path.exists("/proc/meminfo"):
                meminfo: Dict[str, int] = {}
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            key = parts[0].rstrip(":")
                            meminfo[key] = int(parts[1])
                total = meminfo.get("MemTotal", 0)
                available = meminfo.get("MemAvailable", 0)
                if total > 0:
                    used_pct = (total - available) / total * 100
                    metrics["memory_usage"] = round(used_pct, 1)
        except Exception:
            pass

        try:
            # Disk: use os.statvfs on root partition
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            if total > 0:
                used_pct = (total - free) / total * 100
                metrics["disk_usage"] = round(used_pct, 1)
        except Exception:
            pass

        return metrics

