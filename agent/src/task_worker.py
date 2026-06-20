"""
Background worker that polls the Dashboard API for pending remediation tasks.
Executes the physical remediation using RemediationEngine and reports status.

Uses only stdlib (urllib.request) — no third-party HTTP libraries.

Features:
- Retry queue: failed status reports are retried on each poll cycle
- Idempotency: tracks completed threat IDs to prevent duplicate remediation
- Deduplication: same threat won't be processed concurrently
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("wpcleanshift.worker")

# Maximum number of retries for a failed status report before giving up
MAX_REPORT_RETRIES = 10
# Persistent file to survive worker restarts
IDEMPOTENCY_FILE = "/var/lib/cleanshift/worker_state.json"


class _PendingReport:
    """A status report that failed to send and needs to be retried."""

    __slots__ = ("threat_id", "status", "logs", "retries", "last_attempt")

    def __init__(
        self,
        threat_id: str,
        status: str,
        logs: List[Dict[str, Any]],
    ) -> None:
        self.threat_id = threat_id
        self.status = status
        self.logs = logs
        self.retries = 0
        self.last_attempt = time.monotonic()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "status": self.status,
            "logs": self.logs,
            "retries": self.retries,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "_PendingReport":
        report = cls(d["threat_id"], d["status"], d.get("logs", []))
        report.retries = d.get("retries", 0)
        return report


class TaskWorker:
    """Polls the central API for pending remediation tasks and executes them.

    The worker:
    1. Calls ``GET /threats/pending-remediation?server_id=...``
    2. For each pending threat, calls :meth:`_execute_remediation`
    3. Reports status back via ``PATCH /threats/{id}/status``

    Idempotency & resilience:
    - A retry queue stores failed status reports and replays them each cycle
    - A completed-set prevents re-processing threats that were already remediated
    - Persistent state file survives worker restarts
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        server_id: str,
        agent_id: str = "",
        poll_interval: int = 15,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.server_id = server_id
        self.agent_id = agent_id
        self.poll_interval = poll_interval
        self._engine: Optional[Any] = None  # Lazy-initialised RemediationEngine
        self._last_remediation_logs: List[Dict[str, Any]] = []

        # Retry queue for failed status reports
        self._pending_reports: List[_PendingReport] = []

        # Idempotency: set of threat IDs we've already processed this session
        # Prevents re-running remediation on a threat that the API still
        # returns as "in_progress" because our status report hasn't landed yet
        self._processed_threats: Set[str] = set()

        # Track currently-executing threat ID for deduplication
        self._executing: Optional[str] = None

        # Heartbeat counter — send metrics every Nth cycle to reduce chatter
        self._heartbeat_counter = 0
        self._heartbeat_every = 4  # every 4 cycles = ~60s at 15s interval

        # Load persistent state
        self._load_state()

    # ── Persistent state ────────────────────────────────────────────

    def _state_file(self) -> Path:
        return Path(IDEMPOTENCY_FILE)

    def _load_state(self) -> None:
        """Load pending reports and processed set from disk."""
        path = self._state_file()
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for entry in data.get("pending_reports", []):
                self._pending_reports.append(_PendingReport.from_dict(entry))
            for tid in data.get("processed_threats", []):
                self._processed_threats.add(tid)
            logger.info(
                "Loaded persistent state: %d pending reports, %d processed threats",
                len(self._pending_reports), len(self._processed_threats),
            )
        except Exception as exc:
            logger.warning("Failed to load worker state: %s", exc)

    def _save_state(self) -> None:
        """Persist pending reports and processed set to disk."""
        path = self._state_file()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "pending_reports": [r.to_dict() for r in self._pending_reports],
                # Only keep the last 500 processed IDs to prevent unbounded growth
                "processed_threats": list(self._processed_threats)[-500:],
                "last_saved": datetime.now(timezone.utc).isoformat(),
            }
            path.write_text(json.dumps(data, indent=2))
        except Exception as exc:
            logger.warning("Failed to save worker state: %s", exc)

    # ── HTTP helpers (stdlib only) ──────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

    def _api_request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Make an HTTP request to the central API.  Returns parsed JSON or None."""
        url = f"{self.api_url}{path}"
        data: Optional[bytes] = None

        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            headers=self._headers(),
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read()
                return json.loads(resp_body) if resp_body else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None  # Endpoint not ready yet
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            logger.warning("API %s %s returned HTTP %d: %s", method, path, exc.code, err_body)
            return None
        except urllib.error.URLError as exc:
            logger.warning("API %s %s unreachable: %s", method, path, exc.reason)
            return None
        except Exception as exc:
            logger.warning("API %s %s failed: %s", method, path, exc)
            return None

    # ── Lazy engine init ────────────────────────────────────────────

    def _get_engine(self) -> Any:
        """Lazily initialise the RemediationEngine with IntelligenceDB."""
        if self._engine is None:
            try:
                from .intelligence import IntelligenceDB
                from .cleaner import RemediationEngine, RemediationMode

                intel = IntelligenceDB()
                self._engine = RemediationEngine(
                    intel=intel,
                    mode=RemediationMode.AUTO,
                    dry_run=False,
                    backup_before_clean=True,
                )
                logger.info("RemediationEngine initialised successfully")
            except Exception as exc:
                logger.error("Failed to initialise RemediationEngine: %s", exc)
                return None
        return self._engine

    # ── Main loop ───────────────────────────────────────────────────

    def run(self) -> None:
        logger.info(
            "Starting TaskWorker polling %s every %ds for server %s",
            self.api_url, self.poll_interval, self.server_id,
        )
        while True:
            try:
                # Phase 0: Send heartbeat + system metrics periodically
                self._heartbeat_counter += 1
                if self._heartbeat_counter >= self._heartbeat_every:
                    self._send_heartbeat()
                    self._heartbeat_counter = 0

                # Phase 1: Retry any failed status reports first
                self._flush_pending_reports()

                # Phase 2: Poll for new tasks
                self._poll_tasks()
            except Exception as exc:
                logger.error("Error during task polling: %s", exc)

            # Save state after each cycle
            self._save_state()
            time.sleep(self.poll_interval)

    # ── Heartbeat & Metrics ─────────────────────────────────────────

    @staticmethod
    def _collect_system_metrics() -> Dict[str, float]:
        """Collect CPU, memory, and disk usage using /proc/ (Linux only)."""
        metrics: Dict[str, float] = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
        }

        try:
            if os.path.exists("/proc/loadavg"):
                with open("/proc/loadavg", "r") as f:
                    load_1m = float(f.read().split()[0])
                cpu_count = os.cpu_count() or 1
                metrics["cpu_usage"] = round(min(load_1m / cpu_count * 100, 100.0), 1)
        except Exception:
            pass

        try:
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
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            if total > 0:
                used_pct = (total - free) / total * 100
                metrics["disk_usage"] = round(used_pct, 1)
        except Exception:
            pass

        return metrics

    def _send_heartbeat(self) -> None:
        """Send heartbeat with system metrics to the API."""
        if not self.agent_id:
            return

        metrics = self._collect_system_metrics()
        body = {"system_metrics": metrics}

        result = self._api_request(
            "PATCH",
            f"/agents/{self.agent_id}/heartbeat",
            body=body,
        )

        if result is not None:
            logger.debug(
                "Heartbeat sent: cpu=%.1f%% mem=%.1f%% disk=%.1f%%",
                metrics["cpu_usage"], metrics["memory_usage"], metrics["disk_usage"],
            )
        else:
            logger.debug("Heartbeat failed — will retry next cycle")

    # ── Retry queue ─────────────────────────────────────────────────

    def _flush_pending_reports(self) -> None:
        """Retry all pending status reports. Remove successful ones."""
        if not self._pending_reports:
            return

        logger.info("Retrying %d pending status report(s)...", len(self._pending_reports))
        still_pending: List[_PendingReport] = []

        for report in self._pending_reports:
            report.retries += 1
            report.last_attempt = time.monotonic()

            body: Dict[str, Any] = {"remediation_status": report.status}
            if report.logs:
                body["remediation_logs"] = report.logs

            result = self._api_request(
                "PATCH",
                f"/threats/{report.threat_id}/status",
                body=body,
            )

            if result is not None:
                logger.info(
                    "✅ Retry succeeded: threat %s marked as %s (attempt %d)",
                    report.threat_id, report.status, report.retries,
                )
            elif report.retries >= MAX_REPORT_RETRIES:
                logger.error(
                    "❌ Giving up on threat %s after %d retries. "
                    "Status '%s' was never reported to API. "
                    "MANUAL INTERVENTION REQUIRED.",
                    report.threat_id, report.retries, report.status,
                )
                # TODO: Write to a dead-letter file for manual review
                dead_letter = Path("/var/log/cleanshift/dead_letters.jsonl")
                try:
                    dead_letter.parent.mkdir(parents=True, exist_ok=True)
                    with dead_letter.open("a") as f:
                        f.write(json.dumps({
                            "threat_id": report.threat_id,
                            "status": report.status,
                            "logs": report.logs,
                            "retries": report.retries,
                            "given_up_at": datetime.now(timezone.utc).isoformat(),
                        }) + "\n")
                except Exception:
                    pass
            else:
                still_pending.append(report)
                logger.warning(
                    "Retry %d/%d failed for threat %s — will retry next cycle",
                    report.retries, MAX_REPORT_RETRIES, report.threat_id,
                )

        self._pending_reports = still_pending

    # ── Task polling ────────────────────────────────────────────────

    def _poll_tasks(self) -> None:
        """Fetch pending remediations and execute them."""
        tasks = self._api_request(
            "GET",
            f"/threats/pending-remediation?server_id={self.server_id}",
        )

        if not tasks or not isinstance(tasks, list):
            return

        for task in tasks:
            threat_id = task.get("id", "unknown")

            # ── Idempotency check ──
            # Skip threats we've already processed this session.
            # This prevents double-remediation when the API still returns
            # the threat as "in_progress" because our status report is
            # queued for retry.
            if threat_id in self._processed_threats:
                logger.debug(
                    "Skipping threat %s — already processed (status report may be pending)",
                    threat_id,
                )
                continue

            # Skip if there's already a pending retry for this threat
            if any(r.threat_id == threat_id for r in self._pending_reports):
                logger.debug(
                    "Skipping threat %s — status report retry pending",
                    threat_id,
                )
                continue

            logger.info(
                "Picked up task for threat %s (%s)",
                threat_id, task.get("threat_type"),
            )

            self._executing = threat_id
            try:
                success = self._execute_remediation(task)
                status = "completed" if success else "failed"
                self._report_status(threat_id, status)

                # Send Telegram alert for remediation result
                self._send_remediation_telegram(task, status)
            finally:
                self._executing = None

            # Mark as processed regardless of report success — the retry
            # queue handles report delivery
            self._processed_threats.add(threat_id)

    # ── Remediation dispatch ────────────────────────────────────────

    def _execute_remediation(self, task: Dict[str, Any]) -> bool:
        """Execute remediation for a single threat task.

        The RemediationEngine uses its internal ``_remediate_single_threat``
        method which dispatches to the correct handler based on threat_type.
        We construct a minimal Threat-like object to pass in.
        """
        engine = self._get_engine()
        if engine is None:
            logger.error("RemediationEngine not available — skipping task %s", task.get("id"))
            return False

        threat_type = task.get("threat_type", "")
        location = task.get("location", "")
        site_id = task.get("site_id", "")

        if not location:
            logger.warning("No location for threat %s — cannot remediate", task.get("id"))
            return False

        try:
            # Derive site_path from the location (everything up to /wp-content/, /wp-admin/, etc.)
            # or fall back to the directory containing the file
            site_path = location
            for marker in ("/wp-content/", "/wp-admin/", "/wp-includes/"):
                idx = location.find(marker)
                if idx > 0:
                    site_path = location[:idx]
                    break
            else:
                # Fallback: use parent directory
                site_path = os.path.dirname(location)

            site_path_obj = Path(site_path)

            # ── Pre-flight idempotency check ──
            # For file-based threats, check if the target file is already
            # gone (quarantined/deleted by a previous run). This prevents
            # the engine from erroring on a missing file or doing duplicate work.
            if threat_type in ("backdoor_file", "suspicious_file", "script_injection"):
                target = Path(location)
                if not target.exists():
                    logger.info(
                        "Idempotency: file %s already removed — marking threat %s as completed",
                        location, task.get("id"),
                    )
                    self._last_remediation_logs = [{
                        "action_type": "idempotency_check",
                        "command": None,
                        "status": "completed",
                        "output": f"File {location} already removed (likely by previous remediation run).",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "performed_by": f"agent-worker/{self.server_id[:8]}",
                    }]
                    return True

            # Build a minimal threat-like object matching what RemediationEngine expects
            from .models import Threat as AgentThreat, ThreatType, Severity
            evidence_raw = task.get("evidence")
            details = evidence_raw if isinstance(evidence_raw, dict) else {}
            try:
                threat_obj = AgentThreat(
                    threat_type=threat_type,
                    severity=task.get("severity", "medium"),
                    title=task.get("title", f"Remediation: {threat_type}"),
                    description=task.get("description", ""),
                    location=location,
                    site_path=str(site_path),
                    details=details,
                )
            except (ValueError, KeyError) as e:
                logger.warning("Cannot create threat from task — invalid enum: %s", e)
                return False

            # Dispatch based on threat type — use the engine's internal dispatch
            method_map = {
                "core_modified": engine._remediate_core_modified,
                "backdoor_file": engine._remediate_backdoor_file,
                "script_injection": engine._remediate_script_injection,
                "vulnerable_plugin": engine._remediate_vulnerable_plugin,
                "rogue_admin": engine._remediate_rogue_admin,
                "db_marker": engine._remediate_db_marker,
                "permission_issue": engine._remediate_permissions,
                "php_config_risk": engine._remediate_htaccess,
                "wp_cron_abuse": engine._remediate_wp_cron_abuse,
                "db_injection": engine._remediate_db_injection,
                "suspicious_file": engine._remediate_backdoor_file,
            }

            # Types requiring manual/host-level intervention — mark as skipped
            MANUAL_TYPES = {"php_outdated", "mysql_config_risk", "mysql_rogue_user"}

            handler = method_map.get(threat_type)
            if handler is None:
                if threat_type in MANUAL_TYPES:
                    logger.info(
                        "Threat type '%s' requires manual intervention — marking as skipped",
                        threat_type,
                    )
                    self._last_remediation_logs = [{
                        "action_type": "manual_skip",
                        "command": None,
                        "status": "skipped",
                        "output": f"Threat type '{threat_type}' requires manual intervention.",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "performed_by": f"agent-worker/{self.server_id[:8]}",
                    }]
                    self._report_status(task.get("id", ""), "skipped")
                    return True
                logger.warning("No remediation handler for threat type: %s", threat_type)
                return False

            handler(threat_obj, site_path_obj)

            # Capture remediation details from the engine
            self._last_remediation_logs = []
            for action in engine.actions:
                self._last_remediation_logs.append({
                    "action_type": action.action_type,
                    "command": action.command,
                    "status": action.status.value if hasattr(action.status, 'value') else str(action.status),
                    "output": action.output[:2000] if action.output else None,
                    "started_at": action.started_at or datetime.now(timezone.utc).isoformat(),
                    "completed_at": action.completed_at or datetime.now(timezone.utc).isoformat(),
                    "performed_by": f"agent-worker/{self.server_id[:8]}",
                })

            # Check if any individual action failed
            any_failed = any(
                (action.status.value if hasattr(action.status, 'value') else str(action.status))
                in ('failed', 'error')
                for action in engine.actions
            )
            if any_failed:
                failed_actions = [
                    a.action_type for a in engine.actions
                    if (a.status.value if hasattr(a.status, 'value') else str(a.status)) in ('failed', 'error')
                ]
                logger.warning(
                    "Partial remediation failure for threat %s — failed actions: %s",
                    task.get('id'), failed_actions,
                )
                return False

            for entry in engine.audit_log:
                self._last_remediation_logs.append({
                    "action_type": entry.get("event", "audit"),
                    "command": None,
                    "status": "completed",
                    "output": entry.get("message", ""),
                    "started_at": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "completed_at": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "performed_by": f"agent-worker/{self.server_id[:8]}",
                })

            logger.info("Remediation fully succeeded for threat %s (all %d actions passed)", task.get("id"), len(engine.actions))
            return True

        except Exception as exc:
            logger.error("Failed to execute remediation for %s: %s", task.get("id"), exc)
            # Capture failure details for the log
            self._last_remediation_logs = [{
                "action_type": "remediation_error",
                "command": None,
                "status": "failed",
                "output": f"Exception: {str(exc)[:2000]}",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "performed_by": f"agent-worker/{self.server_id[:8]}",
            }]
            return False

    # ── Status reporting with retry queue ───────────────────────────

    def _report_status(self, threat_id: str, status: str) -> None:
        """Report remediation status back to the API.

        If the API is unreachable, the report is queued for retry.
        Reports are idempotent — sending the same status twice is safe.
        """
        # Capture logs before they're cleared
        logs = list(self._last_remediation_logs) if self._last_remediation_logs else []
        self._last_remediation_logs = []  # Clear after capturing

        body: Dict[str, Any] = {"remediation_status": status}
        if logs:
            body["remediation_logs"] = logs

        result = self._api_request(
            "PATCH",
            f"/threats/{threat_id}/status",
            body=body,
        )

        if result is not None:
            logger.info("Successfully marked threat %s as %s", threat_id, status)
        else:
            logger.warning(
                "Failed to report status %s for %s — queuing for retry",
                status, threat_id,
            )
            self._pending_reports.append(_PendingReport(threat_id, status, logs))
            # Immediately persist so we don't lose it on crash
            self._save_state()

    def _send_remediation_telegram(self, task: Dict[str, Any], status: str) -> None:
        """Send a Telegram alert summarizing the remediation result.

        Uses the same TelegramAlerter as scan alerts. If Telegram is
        not configured or the send fails, the error is logged and swallowed.
        """
        try:
            from .alerter import TelegramAlerter
            from .agent import load_config
            config = load_config()
            alerter = TelegramAlerter.from_config(config)
            if not alerter or not alerter.bot_token:
                return  # Telegram not configured

            emoji = "✅" if status == "completed" else "❌"
            severity = task.get("severity", "medium")
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

            title = task.get("title", "Unknown threat")
            threat_type = task.get("threat_type", "unknown")
            location = task.get("location", "N/A")

            # Truncate location for readability
            if len(location) > 80:
                location = "..." + location[-77:]

            msg = (
                f"{emoji} *Remediation {TelegramAlerter._escape_md(status.upper())}*\n\n"
                f"{sev_emoji} *{TelegramAlerter._escape_md(title)}*\n"
                f"Type: `{TelegramAlerter._escape_md(threat_type)}`\n"
                f"Location: `{TelegramAlerter._escape_md(location)}`\n"
                f"Server: `{TelegramAlerter._escape_md(self.server_id[:8])}`"
            )
            alerter._send_message(msg)
            logger.debug("Telegram remediation alert sent for %s", task.get("id"))

        except Exception as exc:
            logger.debug("Telegram remediation alert skipped: %s", exc)
