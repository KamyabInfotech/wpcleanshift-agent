"""
CleanShift Concordance Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cross-references CleanShift scan findings with third-party security
tools installed on the server (Imunify360, ClamAV, CPGuard, etc.).

This enables:
  - Double-validation confidence scoring
  - "CleanShift caught it, Imunify missed it" reporting
  - False positive reduction (if 2+ tools agree, higher confidence)
  - Gap analysis (threats only one tool catches)

Python 3.6+.  No external dependencies -- stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime

try:
    from typing import Any, Dict, List, Optional, Set, Tuple
except ImportError:
    pass

logger = logging.getLogger("cleanshift.concordance")


# ─── Third-Party Tool Adapters ──────────────────────────────────

class ImunifyAdapter(object):
    """
    Adapter for Imunify360 / ImunifyAV.

    Reads malware scan results from Imunify's database/API and
    normalises them into a common finding format.
    """

    IMUNIFY_DB = "/var/imunify360/files.db"
    IMUNIFY_CLI = "/usr/bin/imunify360-agent"

    def __init__(self):
        # type: () -> None
        self.available = os.path.exists(self.IMUNIFY_CLI)

    def get_findings(self, site_path):
        # type: (str) -> List[Dict[str, Any]]
        """Get Imunify360 findings for a site path."""
        if not self.available:
            return []

        findings = []
        try:
            cmd = [
                self.IMUNIFY_CLI, "malware", "malicious", "list",
                "--json", "--limit", "500",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                items = data.get("items", data.get("result", []))
                for item in items:
                    file_path = item.get("file", "")
                    if file_path.startswith(site_path):
                        findings.append({
                            "source": "imunify360",
                            "file": file_path,
                            "signature": item.get("signature", ""),
                            "status": item.get("status", ""),
                            "severity": self._map_severity(item),
                            "detected_at": item.get("created", ""),
                        })
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as e:
            logger.debug("Imunify360 query failed: %s", e)

        return findings

    @staticmethod
    def _map_severity(item):
        # type: (Dict[str, Any]) -> str
        sig = item.get("signature", "").lower()
        if "webshell" in sig or "backdoor" in sig:
            return "critical"
        if "malware" in sig or "trojan" in sig:
            return "high"
        return "medium"


class ClamAVAdapter(object):
    """
    Adapter for ClamAV (clamscan / clamdscan).

    Runs or reads ClamAV scan results for a site.
    """

    CLAMSCAN = "/usr/bin/clamscan"
    CLAMDSCAN = "/usr/bin/clamdscan"

    def __init__(self):
        # type: () -> None
        self.available = (
            os.path.exists(self.CLAMDSCAN) or os.path.exists(self.CLAMSCAN)
        )
        self._scanner = self.CLAMDSCAN if os.path.exists(self.CLAMDSCAN) else self.CLAMSCAN

    def get_findings(self, site_path):
        # type: (str) -> List[Dict[str, Any]]
        """Get ClamAV findings for a site path."""
        if not self.available:
            return []

        findings = []
        try:
            cmd = [
                self._scanner, "-r", "--infected", "--no-summary",
                site_path,
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
            # ClamAV returns 1 if infections found
            for line in result.stdout.strip().split("\n"):
                if ": " in line and "FOUND" in line:
                    parts = line.split(": ", 1)
                    file_path = parts[0].strip()
                    signature = parts[1].replace(" FOUND", "").strip()
                    findings.append({
                        "source": "clamav",
                        "file": file_path,
                        "signature": signature,
                        "status": "infected",
                        "severity": "high",
                        "detected_at": datetime.now().isoformat(),
                    })
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug("ClamAV scan failed: %s", e)

        return findings


class CPGuardAdapter(object):
    """
    Adapter for CPGuard malware scanner.

    Reads CPGuard scan logs.
    """

    LOG_PATH = "/var/cpguard/logs/malware.log"

    def __init__(self):
        # type: () -> None
        self.available = os.path.exists(self.LOG_PATH)

    def get_findings(self, site_path):
        # type: (str) -> List[Dict[str, Any]]
        """Get CPGuard findings for a site path."""
        if not self.available:
            return []

        findings = []
        try:
            with open(self.LOG_PATH, "r") as f:
                for line in f:
                    if site_path in line:
                        # CPGuard log format: timestamp|file|signature|action
                        parts = line.strip().split("|")
                        if len(parts) >= 3:
                            findings.append({
                                "source": "cpguard",
                                "file": parts[1].strip(),
                                "signature": parts[2].strip(),
                                "status": parts[3].strip() if len(parts) > 3 else "detected",
                                "severity": "high",
                                "detected_at": parts[0].strip(),
                            })
        except (OSError, IOError) as e:
            logger.debug("CPGuard log read failed: %s", e)

        return findings


class WordfenceAdapter(object):
    """
    Adapter for Wordfence scan results.

    Reads Wordfence scan data from the WordPress database or
    the wfIssues table.
    """

    def __init__(self):
        # type: () -> None
        self.available = True  # Always try — detection is per-site

    def get_findings(self, site_path):
        # type: (str) -> List[Dict[str, Any]]
        """
        Get Wordfence findings for a site.

        Reads the wf_scan_issues option or wfIssues table.
        """
        findings = []
        wf_issues_file = os.path.join(
            site_path, "wp-content", "wflogs", "scan-issues.json",
        )
        if not os.path.exists(wf_issues_file):
            return findings

        try:
            with open(wf_issues_file, "r") as f:
                data = json.load(f)

            for issue in data if isinstance(data, list) else data.get("issues", []):
                file_path = issue.get("data", {}).get("file", "")
                if file_path:
                    full_path = os.path.join(site_path, file_path)
                else:
                    full_path = ""

                findings.append({
                    "source": "wordfence",
                    "file": full_path,
                    "signature": issue.get("shortMsg", issue.get("type", "")),
                    "status": issue.get("status", "new"),
                    "severity": self._map_severity(issue),
                    "detected_at": issue.get("time", ""),
                })
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.debug("Wordfence issues read failed: %s", e)

        return findings

    @staticmethod
    def _map_severity(issue):
        # type: (Dict[str, Any]) -> str
        severity = issue.get("severity", 0)
        if isinstance(severity, int):
            if severity >= 4:
                return "critical"
            if severity >= 3:
                return "high"
            if severity >= 2:
                return "medium"
        return "low"


# ─── Concordance Finding ────────────────────────────────────────

class ConcordanceFinding(object):
    """
    A single concordance result linking a CleanShift finding to
    third-party tool findings for the same file.
    """

    def __init__(
        self,
        file_path,          # type: str
        cleanshift_threat,  # type: Optional[Any]
        external_findings,  # type: List[Dict[str, Any]]
    ):
        # type: (...) -> None
        self.file_path = file_path
        self.cleanshift_threat = cleanshift_threat
        self.external_findings = external_findings

        # Concordance analysis
        self.sources = set()  # type: Set[str]
        self.agreement_count = 0
        self.confidence_score = 0.0
        self.status = ""  # 'confirmed', 'cleanshift_only', 'external_only', 'disputed'

        self._analyze()

    def _analyze(self):
        # type: () -> None
        """Compute concordance metrics."""
        cs_flagged = self.cleanshift_threat is not None
        ext_count = len(self.external_findings)

        for ef in self.external_findings:
            self.sources.add(ef.get("source", "unknown"))

        if cs_flagged:
            self.sources.add("cleanshift")

        self.agreement_count = len(self.sources)

        if cs_flagged and ext_count > 0:
            # Both CleanShift and external tools flagged this
            self.status = "confirmed"
            # Base confidence from CleanShift + bonus per external source
            self.confidence_score = min(
                0.99, 0.7 + (0.1 * ext_count),
            )
        elif cs_flagged and ext_count == 0:
            # Only CleanShift found this
            self.status = "cleanshift_only"
            self.confidence_score = 0.6
        elif not cs_flagged and ext_count > 0:
            # Only external tools found this
            self.status = "external_only"
            self.confidence_score = 0.5 + (0.1 * ext_count)
        else:
            self.status = "clean"
            self.confidence_score = 0.0

    def to_dict(self):
        # type: () -> Dict[str, Any]
        cs_data = None
        if self.cleanshift_threat is not None:
            t = self.cleanshift_threat
            cs_data = {
                "type": str(getattr(t, "threat_type", "")),
                "severity": str(getattr(t, "severity", "")),
                "description": getattr(t, "description", ""),
            }

        return {
            "file": self.file_path,
            "status": self.status,
            "confidence": round(self.confidence_score, 2),
            "agreement_count": self.agreement_count,
            "sources": sorted(self.sources),
            "cleanshift": cs_data,
            "external": self.external_findings,
        }


# ─── Concordance Engine ─────────────────────────────────────────

class ConcordanceEngine(object):
    """
    Cross-references CleanShift scan results with third-party
    security tools (Imunify360, ClamAV, CPGuard, Wordfence).

    Usage::

        engine = ConcordanceEngine()
        report = engine.concordance(site_path, cleanshift_threats)
        print(report.summary)
    """

    def __init__(self):
        # type: () -> None
        self.adapters = [
            ImunifyAdapter(),
            ClamAVAdapter(),
            CPGuardAdapter(),
            WordfenceAdapter(),
        ]
        self._available = [a for a in self.adapters if a.available]

        if self._available:
            names = [type(a).__name__.replace("Adapter", "") for a in self._available]
            logger.info("Concordance: detected %s", ", ".join(names))
        else:
            logger.info("Concordance: no third-party tools detected (standalone mode)")

    def concordance(self, site_path, cleanshift_threats=None):
        # type: (str, Optional[List[Any]]) -> ConcordanceReport
        """
        Run concordance analysis for a site.

        Args:
            site_path:           Absolute path to site root.
            cleanshift_threats:  List of Threat objects from CleanShift scan.

        Returns:
            ConcordanceReport with findings, stats, and gap analysis.
        """
        threats = cleanshift_threats or []
        start_time = time.monotonic()

        # Collect external findings
        all_external = []  # type: List[Dict[str, Any]]
        for adapter in self._available:
            try:
                findings = adapter.get_findings(site_path)
                all_external.extend(findings)
                logger.info(
                    "Concordance: %s returned %d findings for %s",
                    type(adapter).__name__, len(findings), site_path,
                )
            except Exception as e:
                logger.warning(
                    "Concordance adapter %s failed: %s",
                    type(adapter).__name__, e,
                )

        # Index external findings by file path
        external_by_file = {}  # type: Dict[str, List[Dict[str, Any]]]
        for ef in all_external:
            fp = ef.get("file", "")
            if fp:
                external_by_file.setdefault(fp, []).append(ef)

        # Index CleanShift threats by file path
        cs_by_file = {}  # type: Dict[str, Any]
        for t in threats:
            fp = getattr(t, "location", "") or ""
            if fp:
                cs_by_file[fp] = t

        # Build concordance findings for all unique files
        all_files = set(list(cs_by_file.keys()) + list(external_by_file.keys()))
        concordance_findings = []  # type: List[ConcordanceFinding]

        for fp in sorted(all_files):
            cs_threat = cs_by_file.get(fp)
            ext_findings = external_by_file.get(fp, [])
            finding = ConcordanceFinding(fp, cs_threat, ext_findings)
            concordance_findings.append(finding)

        elapsed = time.monotonic() - start_time

        return ConcordanceReport(
            site_path=site_path,
            findings=concordance_findings,
            tools_available=[type(a).__name__.replace("Adapter", "") for a in self._available],
            elapsed_seconds=elapsed,
        )


# ─── Concordance Report ─────────────────────────────────────────

class ConcordanceReport(object):
    """
    Report produced by the ConcordanceEngine.

    Contains findings, statistics, and gap analysis.
    """

    def __init__(
        self,
        site_path,        # type: str
        findings,         # type: List[ConcordanceFinding]
        tools_available,  # type: List[str]
        elapsed_seconds,  # type: float
    ):
        # type: (...) -> None
        self.site_path = site_path
        self.findings = findings
        self.tools_available = tools_available
        self.elapsed_seconds = elapsed_seconds

        # Compute stats
        self.stats = self._compute_stats()

    def _compute_stats(self):
        # type: () -> Dict[str, Any]
        """Compute concordance statistics."""
        total = len(self.findings)
        confirmed = sum(1 for f in self.findings if f.status == "confirmed")
        cs_only = sum(1 for f in self.findings if f.status == "cleanshift_only")
        ext_only = sum(1 for f in self.findings if f.status == "external_only")

        avg_confidence = 0.0
        if total > 0:
            avg_confidence = sum(f.confidence_score for f in self.findings) / total

        return {
            "total_findings": total,
            "confirmed": confirmed,
            "cleanshift_only": cs_only,
            "external_only": ext_only,
            "average_confidence": round(avg_confidence, 2),
            "tools_available": len(self.tools_available),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
        }

    @property
    def summary(self):
        # type: () -> str
        """Human-readable summary."""
        lines = [
            "Concordance Report: %s" % self.site_path,
            "Tools: %s" % (", ".join(self.tools_available) if self.tools_available else "none (standalone)"),
            "",
            "Findings:",
            "  Confirmed (multi-tool):     %d" % self.stats["confirmed"],
            "  CleanShift-only:            %d" % self.stats["cleanshift_only"],
            "  External-only:              %d" % self.stats["external_only"],
            "  Total:                      %d" % self.stats["total_findings"],
            "",
            "Confidence: %.0f%% average" % (self.stats["average_confidence"] * 100),
            "Time: %.2fs" % self.stats["elapsed_seconds"],
        ]
        return "\n".join(lines)

    def gap_analysis(self):
        # type: () -> Dict[str, List[ConcordanceFinding]]
        """
        Identify gaps in detection.

        Returns dict with:
          - 'missed_by_external': Files only CleanShift caught
          - 'missed_by_cleanshift': Files only external tools caught
          - 'confirmed': Files both sides agree on
        """
        return {
            "missed_by_external": [
                f for f in self.findings if f.status == "cleanshift_only"
            ],
            "missed_by_cleanshift": [
                f for f in self.findings if f.status == "external_only"
            ],
            "confirmed": [
                f for f in self.findings if f.status == "confirmed"
            ],
        }

    def to_dict(self):
        # type: () -> Dict[str, Any]
        """Full report as a JSON-serialisable dict."""
        return {
            "site_path": self.site_path,
            "tools_available": self.tools_available,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent=2):
        # type: (int) -> str
        """Full report as JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
