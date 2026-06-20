"""
CleanShift Data Models
~~~~~~~~~~~~~~~~~~~~~~~~

Shared data contracts between the server agent, API, and dashboard.
All models use dataclasses with JSON serialization support for transport.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ─── Enumerations ───────────────────────────────────────────────────

class ThreatType(str, Enum):
    """Categorization of detected threats."""
    ROGUE_ADMIN = "rogue_admin"
    BACKDOOR_FILE = "backdoor_file"
    DB_MARKER = "db_marker"
    SCRIPT_INJECTION = "script_injection"
    VULNERABLE_PLUGIN = "vulnerable_plugin"
    CORE_MODIFIED = "core_modified"
    PERMISSION_ISSUE = "permission_issue"
    SUSPICIOUS_FILE = "suspicious_file"
    # PHP stack-level threats
    PHP_CONFIG_RISK = "php_config_risk"
    PHP_OUTDATED = "php_outdated"
    # MySQL / database-level threats
    MYSQL_CONFIG_RISK = "mysql_config_risk"
    MYSQL_ROGUE_USER = "mysql_rogue_user"
    DB_INJECTION = "db_injection"
    WP_CRON_ABUSE = "wp_cron_abuse"
    # API-managed types
    SITE_RESTORE = "site_restore"


class Severity(str, Enum):
    """Threat severity levels, ordered from highest to lowest."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationStatus(str, Enum):
    """Status of a remediation action or threat's resolution state."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_APPROVAL = "requires_approval"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"


class ReportTier(str, Enum):
    """Client billing tiers controlling report depth."""
    FREE = "free"
    PAID = "paid"


class RemediationMode(str, Enum):
    """How the agent should handle discovered threats."""
    AUTO = "auto"              # Execute remediation automatically
    MANUAL = "manual"          # Require approval for each action
    REPORT_ONLY = "report_only"  # Scan + report, no remediation


# ─── Data Models ────────────────────────────────────────────────────

@dataclass
class PluginInfo:
    """A WordPress plugin with version and status metadata."""
    slug: str
    name: str
    version: str
    status: str = "active"       # active, inactive, must-use, dropin
    update_available: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThemeInfo:
    """A WordPress theme with version and status metadata."""
    slug: str
    name: str
    version: str
    status: str = "inactive"     # active, inactive, parent
    update_available: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WordPressSite:
    """
    Represents a discovered WordPress installation on the server.

    Parsed from wp-config.php and wp-cli introspection. Holds all the
    information needed to scan and remediate a single site.
    """
    path: str                              # Absolute filesystem path to the WP root
    domain: str = ""                       # Site URL (from wp option siteurl)
    wp_version: str = ""
    db_host: str = "localhost"
    db_name: str = ""
    db_user: str = ""
    db_pass: str = ""
    db_prefix: str = "wp_"
    plugins: List[PluginInfo] = field(default_factory=list)
    themes: List[ThemeInfo] = field(default_factory=list)
    site_owner: str = ""                   # Owning system user/account
    hosting_panel: str = ""                 # cpanel, plesk, or custom

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "domain": self.domain,
            "wp_version": self.wp_version,
            "db_host": self.db_host,
            "db_name": self.db_name,
            "db_user": self.db_user,
            "db_pass": "***REDACTED***",
            "db_prefix": self.db_prefix,
            "plugins": [p.to_dict() for p in self.plugins],
            "themes": [t.to_dict() for t in self.themes],
            "site_owner": self.site_owner,
            "hosting_panel": self.hosting_panel,
        }


@dataclass
class NonWPSite:
    """Represents a non-WordPress CMS/framework installation discovered on the server."""
    path: str                              # Absolute filesystem path
    platform_type: str = ""                # PlatformType constant (e.g. 'joomla', 'drupal')
    version: str = ""                      # Detected version
    config_file: str = ""                  # Path to primary config file
    detection_confidence: float = 0.0      # 0.0-1.0
    site_owner: str = ""                   # Owning system user/account

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "platform_type": self.platform_type,
            "version": self.version,
            "config_file": self.config_file,
            "detection_confidence": self.detection_confidence,
            "site_owner": self.site_owner,
        }


@dataclass
class Threat:
    """
    A single detected security threat.

    Each threat maps to one entry in the IoC database or was detected
    by a scanner heuristic. Threats are collected per-site and can be
    mapped to playbook remediation steps.

    Confidence scores:
        - 1.0 = Exact IOC match (known backdoor hash)
        - 0.8 = Heuristic match (PHP in uploads)
        - 0.3 = Structural anomaly (cagefs symlink)
        - 0.1 = Informational (mu-plugin from hosting provider)
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: ThreatType = ThreatType.BACKDOOR_FILE
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    location: str = ""             # File path, DB table, or URL
    evidence: str = ""             # Raw evidence (file content snippet, SQL row)
    site_path: str = ""            # Which WP site this belongs to
    remediation_status: RemediationStatus = RemediationStatus.PENDING
    remediated_at: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    cve: Optional[str] = None
    confidence: float = 1.0        # Detection confidence (0.0–1.0)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["severity"] = self.severity.value
        d["remediation_status"] = self.remediation_status.value
        d["confidence"] = self.confidence
        return d


@dataclass
class RemediationAction:
    """
    A single remediation step executed (or to-be-executed) by the cleaner.

    Links back to the threat it addresses and records the full audit trail
    including the command run, its output, and whether approval was needed.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str = ""
    action_type: str = ""          # e.g. "delete_user", "delete_file", "run_sql"
    target: str = ""               # What the action operates on
    command: str = ""              # The actual command or SQL executed
    status: RemediationStatus = RemediationStatus.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    output: str = ""
    requires_approval: bool = False
    dry_run: bool = False
    playbook_step: str = ""        # Which playbook step this came from

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ScanResult:
    """
    Aggregated output of a full server or single-site scan.

    This is the top-level data object sent to the API and used to
    generate reports. Contains all discovered sites, threats, and
    summary statistics.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    server_hostname: str = ""
    scan_started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_completed: Optional[str] = None
    sites: List[WordPressSite] = field(default_factory=list)
    non_wp_sites: List[NonWPSite] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> None:
        """Compute summary statistics and mark scan as complete."""
        self.scan_completed = datetime.now(timezone.utc).isoformat()
        severity_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}
        for threat in self.threats:
            sev = threat.severity.value
            tt = threat.threat_type.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            type_counts[tt] = type_counts.get(tt, 0) + 1

        self.summary = {
            "total_sites_scanned": len(self.sites),
            "total_non_wp_sites_scanned": len(self.non_wp_sites),
            "total_threats": len(self.threats),
            "threats_by_severity": severity_counts,
            "threats_by_type": type_counts,
            "sites_with_threats": len(
                {t.site_path for t in self.threats}
            ),
            "scan_duration_seconds": self._duration_seconds(),
        }

    @staticmethod
    def _parse_iso(s: str) -> 'Optional[datetime]':
        """Parse ISO datetime string, compatible with Python 3.7+."""
        if not s:
            return None
        # Remove timezone suffix that Python <3.11 can't handle
        s = s.replace('+00:00', '').replace('Z', '')
        try:
            return datetime.fromisoformat(s)
        except (ValueError, AttributeError):
            return None

    def _duration_seconds(self) -> float:
        """Calculate scan duration in seconds."""
        try:
            start = self._parse_iso(self.scan_started)
            end = self._parse_iso(self.scan_completed or self.scan_started)
            if start is None or end is None:
                return 0.0
            return (end - start).total_seconds()
        except (ValueError, TypeError):
            return 0.0

    @classmethod
    def diff(cls, old: 'ScanResult', new: 'ScanResult') -> Dict[str, Any]:
        """Compare two scan results and return differences.

        Compares threats by (location, threat_type) key and sites by path.

        Returns:
            Dict with keys:
                - new_threats: threats in *new* but not in *old*
                - resolved_threats: threats in *old* but not in *new*
                - sites_added: site paths present only in *new*
                - sites_removed: site paths present only in *old*
        """
        def _threat_key(t: Threat) -> tuple:
            return (t.location, t.threat_type.value)

        old_keys = {_threat_key(t): t for t in old.threats}
        new_keys = {_threat_key(t): t for t in new.threats}

        new_threats = [
            new_keys[k].to_dict()
            for k in new_keys
            if k not in old_keys
        ]
        resolved_threats = [
            old_keys[k].to_dict()
            for k in old_keys
            if k not in new_keys
        ]

        old_site_paths = {s.path for s in old.sites}
        new_site_paths = {s.path for s in new.sites}

        return {
            "new_threats": new_threats,
            "resolved_threats": resolved_threats,
            "sites_added": sorted(new_site_paths - old_site_paths),
            "sites_removed": sorted(old_site_paths - new_site_paths),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "server_hostname": self.server_hostname,
            "scan_started": self.scan_started,
            "scan_completed": self.scan_completed,
            "sites": [s.to_dict() for s in self.sites],
            "non_wp_sites": [s.to_dict() for s in self.non_wp_sites],
            "threats": [t.to_dict() for t in self.threats],
            "summary": self.summary,
        }
