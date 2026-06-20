"""
CleanShift Report Generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generates scan and remediation reports in Markdown format.
Supports two tiers:
  - FREE:  Scan results + threat summary (what's wrong)
  - PAID:  Full report + remediation actions taken + recommendations
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    RemediationAction,
    ReportTier,
    ScanResult,
    Severity,
    Threat,
    ThreatType,
)

logger = logging.getLogger("cleanshift.reporter")

# ─── Severity display helpers ──────────────────────────────────────

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

_THREAT_TYPE_LABELS = {
    ThreatType.ROGUE_ADMIN: "Rogue Admin Account",
    ThreatType.BACKDOOR_FILE: "Backdoor File",
    ThreatType.DB_MARKER: "Database Marker",
    ThreatType.SCRIPT_INJECTION: "Script Injection",
    ThreatType.VULNERABLE_PLUGIN: "Vulnerable Plugin",
    ThreatType.CORE_MODIFIED: "Modified Core File",
    ThreatType.PERMISSION_ISSUE: "Permission Issue",
}


def _sanitize_evidence(text: str, max_length: int = 500) -> str:
    """Sanitize evidence content for safe inclusion inside markdown code fences."""
    if not text:
        return ''
    # Truncate to max length
    sanitized = str(text)[:max_length]
    # Strip code fence breakers to prevent escaping the ``` block
    sanitized = sanitized.replace('```', '` ` `')
    # Don't HTML-escape: evidence is inside a code fence where content
    # renders literally. html.escape() would show &lt; instead of <,
    # making forensic analysis of malicious code impossible.
    return sanitized


class ReportGenerator:
    """
    Generates comprehensive scan reports in Markdown format.

    The report depth varies by tier:
      - FREE tier shows threats and severity — enough to understand risk
      - PAID tier adds full evidence, remediation details, and recommendations
    """

    def __init__(self, tier: ReportTier = ReportTier.FREE) -> None:
        self.tier = tier

    def generate(
        self,
        scan_result: ScanResult,
        remediation_actions: Optional[List[RemediationAction]] = None,
    ) -> str:
        """
        Generate a complete scan report.

        Args:
            scan_result: The scan results to report on.
            remediation_actions: Optional list of remediation actions (PAID only).

        Returns:
            Markdown-formatted report string.
        """
        sections: List[str] = []

        sections.append(self._header(scan_result))
        sections.append(self._executive_summary(scan_result))
        sections.append(self._threat_overview(scan_result))

        if self.tier == ReportTier.PAID:
            sections.append(self._detailed_findings(scan_result))
            sections.append(self._site_details(scan_result))
            if remediation_actions:
                sections.append(self._remediation_details(remediation_actions))
            sections.append(self._recommendations(scan_result))
        else:
            sections.append(self._free_tier_cta(scan_result))

        sections.append(self._footer(scan_result))

        return "\n\n".join(sections)

    def generate_json(
        self,
        scan_result: ScanResult,
        remediation_actions: Optional[List[RemediationAction]] = None,
    ) -> str:
        """
        Generate scan results as a JSON string.

        Args:
            scan_result: The scan results.
            remediation_actions: Optional remediation actions.

        Returns:
            JSON string.
        """
        data = scan_result.to_dict()
        if remediation_actions and self.tier == ReportTier.PAID:
            data["remediation_actions"] = [a.to_dict() for a in remediation_actions]
        return json.dumps(data, indent=2, default=str)

    # ── Report Sections ─────────────────────────────────────────

    def _header(self, result: ScanResult) -> str:
        """Report header with scan metadata."""
        lines = [
            "# 🛡️ CleanShift Security Scan Report",
            "",
            "---",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Report ID** | `{result.id}` |",
            f"| **Server** | {result.server_hostname} |",
            f"| **Scan Started** | {result.scan_started} |",
            f"| **Scan Completed** | {result.scan_completed or 'In progress'} |",
            f"| **Sites Scanned** | {len(result.sites)} |",
            f"| **Report Tier** | {self.tier.value.upper()} |",
        ]
        if result.summary.get("scan_duration_seconds"):
            lines.append(
                f"| **Duration** | {result.summary['scan_duration_seconds']:.1f}s |"
            )
        return "\n".join(lines)

    def _executive_summary(self, result: ScanResult) -> str:
        """High-level summary for quick scanning."""
        total = result.summary.get("total_threats", len(result.threats))
        by_severity = result.summary.get("threats_by_severity", {})
        sites_affected = result.summary.get("sites_with_threats", 0)

        # Determine overall risk level
        if by_severity.get("critical", 0) > 0:
            risk_level = "🔴 CRITICAL"
            risk_msg = "Immediate action required. Active compromise indicators detected."
        elif by_severity.get("high", 0) > 0:
            risk_level = "🟠 HIGH"
            risk_msg = "Significant security issues found. Remediation recommended."
        elif by_severity.get("medium", 0) > 0:
            risk_level = "🟡 MEDIUM"
            risk_msg = "Moderate security issues detected. Review and address."
        elif total > 0:
            risk_level = "🔵 LOW"
            risk_msg = "Minor issues found. Schedule for review."
        else:
            risk_level = "🟢 CLEAN"
            risk_msg = "No threats detected. Server appears clean."

        lines = [
            "## Executive Summary",
            "",
            f"> **Overall Risk Level: {risk_level}**",
            f">",
            f"> {risk_msg}",
            "",
            f"- **{total}** threat(s) detected across **{sites_affected}** of **{len(result.sites)}** site(s)",
        ]

        if by_severity:
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_severity.get(sev, 0)
                if count > 0:
                    icon = _SEVERITY_ICONS.get(Severity(sev), "")
                    lines.append(f"| {icon} {sev.upper()} | {count} |")

        return "\n".join(lines)

    def _threat_overview(self, result: ScanResult) -> str:
        """Threat summary table — shown in both tiers."""
        if not result.threats:
            return "## Threats\n\nNo threats detected. ✅"

        lines = [
            "## Threat Overview",
            "",
            "| # | Severity | Type | Title | Site |",
            "|---|----------|------|-------|------|",
        ]

        # Sort threats: critical first, then by type
        sorted_threats = sorted(
            result.threats,
            key=lambda t: (
                list(Severity).index(t.severity),
                t.threat_type.value,
            ),
        )

        for i, threat in enumerate(sorted_threats, 1):
            icon = _SEVERITY_ICONS.get(threat.severity, "")
            sev = _SEVERITY_LABELS.get(threat.severity, "")
            ttype = _THREAT_TYPE_LABELS.get(threat.threat_type, threat.threat_type.value)
            site = Path(threat.site_path).name if threat.site_path else ""

            # Truncate title for table
            title = threat.title[:60] + "..." if len(threat.title) > 60 else threat.title

            lines.append(f"| {i} | {icon} {sev} | {ttype} | {title} | {site} |")

        return "\n".join(lines)

    def _detailed_findings(self, result: ScanResult) -> str:
        """Detailed threat information — PAID tier only."""
        if not result.threats:
            return ""

        lines = ["## Detailed Findings", ""]

        # Group threats by site
        by_site: Dict[str, List[Threat]] = {}
        for threat in result.threats:
            site_key = threat.site_path or "Unknown"
            by_site.setdefault(site_key, []).append(threat)

        for site_path, threats in by_site.items():
            site_name = Path(site_path).name if site_path else "Unknown"
            lines.append(f"### 📁 {site_name}")
            lines.append(f"*Path: `{site_path}`*")
            lines.append("")

            for threat in sorted(threats, key=lambda t: list(Severity).index(t.severity)):
                icon = _SEVERITY_ICONS.get(threat.severity, "")
                ttype = _THREAT_TYPE_LABELS.get(threat.threat_type, threat.threat_type.value)

                lines.append(f"#### {icon} {html.escape(threat.title)}")
                lines.append(f"- **Type:** {ttype}")
                lines.append(f"- **Severity:** {_SEVERITY_LABELS.get(threat.severity, '')}")
                if threat.cve:
                    lines.append(f"- **CVE:** [{html.escape(threat.cve)}](https://nvd.nist.gov/vuln/detail/{html.escape(threat.cve)})")
                lines.append(f"- **Location:** `{html.escape(threat.location)}`")
                lines.append(f"- **Description:** {html.escape(threat.description)}")

                if threat.evidence:
                    lines.append(f"- **Evidence:**")
                    lines.append(f"  ```")
                    lines.append(f"  {_sanitize_evidence(threat.evidence)}")
                    lines.append(f"  ```")

                if threat.details:
                    lines.append(f"- **Details:**")
                    for k, v in threat.details.items():
                        if v and k not in ("patterns",):  # Skip verbose fields
                            lines.append(f"  - {html.escape(str(k))}: `{html.escape(str(v)[:100])}`")

                lines.append("")

        return "\n".join(lines)

    def _site_details(self, result: ScanResult) -> str:
        """Per-site configuration details — PAID tier only."""
        if not result.sites:
            return ""

        lines = ["## Site Details", ""]

        for site in result.sites:
            lines.append(f"### 🌐 {site.domain or site.path}")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Path | `{site.path}` |")
            lines.append(f"| WordPress Version | {site.wp_version} |")
            lines.append(f"| Database | {site.db_name} |")
            lines.append(f"| Table Prefix | `{site.db_prefix}` |")
            lines.append(f"| Site Owner | {site.site_owner} |")
            lines.append(f"| Plugins | {len(site.plugins)} |")
            lines.append(f"| Themes | {len(site.themes)} |")
            lines.append("")

            if site.plugins:
                lines.append("**Plugins:**")
                lines.append("")
                lines.append("| Plugin | Version | Status |")
                lines.append("|--------|---------|--------|")
                for plugin in site.plugins:
                    lines.append(f"| {plugin.name} | {plugin.version} | {plugin.status} |")
                lines.append("")

        return "\n".join(lines)

    def _remediation_details(self, actions: List[RemediationAction]) -> str:
        """Remediation actions taken — PAID tier only."""
        if not actions:
            return ""

        lines = [
            "## Remediation Actions",
            "",
            "| # | Action | Target | Status | Output |",
            "|---|--------|--------|--------|--------|",
        ]

        status_icons = {
            "completed": "✅",
            "failed": "❌",
            "skipped": "⏭️",
            "pending": "⏳",
            "in_progress": "🔄",
            "requires_approval": "🔒",
        }

        for i, action in enumerate(actions, 1):
            icon = status_icons.get(action.status.value, "❓")
            output = action.output[:60] + "..." if len(action.output) > 60 else action.output
            output = output.replace("\n", " ").replace("|", "\\|")
            target = action.target[:40] + "..." if len(action.target) > 40 else action.target
            lines.append(
                f"| {i} | {action.action_type} | {target} | {icon} {action.status.value} | {output} |"
            )

        return "\n".join(lines)

    def _recommendations(self, result: ScanResult) -> str:
        """Security recommendations — PAID tier only."""
        lines = ["## Recommendations", ""]

        recs: List[str] = []

        # Analyze threats to generate targeted recommendations
        threat_types = {t.threat_type for t in result.threats}
        cves = {t.cve for t in result.threats if t.cve}

        if ThreatType.ROGUE_ADMIN in threat_types:
            recs.append(
                "1. **Reset all administrator passwords** — Attackers may have "
                "captured credentials. Use `wp config shuffle-salts` to invalidate "
                "all existing sessions."
            )

        if ThreatType.VULNERABLE_PLUGIN in threat_types:
            recs.append(
                "2. **Remove vulnerable plugins** — Deactivate and delete any "
                "plugins flagged as vulnerable. Consider alternatives that are "
                "appropriate for your server type (e.g., don't use LiteSpeed Cache "
                "on Apache servers)."
            )

        if ThreatType.BACKDOOR_FILE in threat_types:
            recs.append(
                "3. **Verify core integrity** — Run `wp core verify-checksums` to "
                "ensure no core files have been modified. Re-download core files if needed."
            )

        if ThreatType.SCRIPT_INJECTION in threat_types:
            recs.append(
                "4. **Audit database options** — Review wp_options for injected scripts. "
                "Clean any LiteSpeed Cache artifacts with "
                "`DELETE FROM wp_options WHERE option_name LIKE 'litespeed%'`."
            )

        if ThreatType.PERMISSION_ISSUE in threat_types:
            recs.append(
                "5. **Fix file permissions** — Directories should be 755, files 644, "
                "and wp-config.php should be 600."
            )

        # General recommendations
        recs.extend([
            "",
            "### General Hardening",
            "- Block XML-RPC (`xmlrpc.php`) unless explicitly needed",
            "- Disable file editing from WP admin: `define('DISALLOW_FILE_EDIT', true);`",
            "- Install a security monitoring plugin (Wordfence, Sucuri, or similar)",
            "- Keep WordPress core, plugins, and themes updated",
            "- Use unique, strong passwords for all admin accounts",
            "- Consider implementing 2FA for administrator accounts",
        ])

        if "CVE-2024-28000" in cves:
            recs.extend([
                "",
                "### CVE-2024-28000 Specific",
                "- Remove LiteSpeed Cache from all sites on this server",
                "- Check ALL sites on the server — lateral movement is common",
                "- Verify your server actually runs LiteSpeed before installing cache plugins",
                "- Clean up LiteSpeed database artifacts (200-255 entries per site in wp_options)",
            ])

        for rec in recs:
            lines.append(rec)

        return "\n".join(lines)

    def _free_tier_cta(self, result: ScanResult) -> str:
        """Call-to-action for free tier users to upgrade."""
        if not result.threats:
            return ""

        critical_count = sum(
            1 for t in result.threats if t.severity == Severity.CRITICAL
        )

        lines = [
            "## 🔒 Detailed Report Available",
            "",
            f"Your scan found **{len(result.threats)} threats** "
            f"{'including **' + str(critical_count) + ' critical** issues' if critical_count else ''}.",
            "",
            "The **free tier** shows you what's wrong. To see:",
            "- 📋 Full threat evidence and file paths",
            "- 🛠️ Automated remediation actions",
            "- 📖 Step-by-step fix instructions",
            "- 🔍 Per-site configuration analysis",
            "- 📊 Security hardening recommendations",
            "",
            "**Upgrade to the paid tier** for full access.",
            "",
            "---",
            "*Run with `--tier paid` or configure via API.*",
        ]

        return "\n".join(lines)

    def _footer(self, result: ScanResult) -> str:
        """Report footer."""
        return (
            "---\n"
            f"*Generated by CleanShift v0.1.0 • "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC • "
            f"Report ID: {result.id}*"
        )

    # ── File Output ─────────────────────────────────────────────

    def save(
        self,
        content: str,
        output_path: Path,
        format: str = "markdown",
    ) -> Path:
        """
        Save report to a file.

        Args:
            content: Report content string.
            output_path: Directory or file path to save to.
            format: Output format ("markdown" or "json").

        Returns:
            Path to the saved report file.
        """
        output = Path(output_path)

        if output.is_dir():
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            ext = "md" if format == "markdown" else "json"
            output = output / f"cleanshift_report_{timestamp}.{ext}"

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")

        logger.info("Report saved to %s", output)
        return output
