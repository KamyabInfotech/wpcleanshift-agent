"""
Tests for the CleanShift Concordance Engine.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.concordance import (
    ConcordanceEngine,
    ConcordanceFinding,
    ConcordanceReport,
    ClamAVAdapter,
    CPGuardAdapter,
    ImunifyAdapter,
    WordfenceAdapter,
)


class FakeThreat(object):
    """Minimal Threat-like object for testing."""
    def __init__(self, location, severity="high", description="test threat", threat_type="malware"):
        self.location = location
        self.severity = severity
        self.description = description
        self.threat_type = threat_type


class TestConcordanceFinding(unittest.TestCase):
    """Tests for individual ConcordanceFinding analysis."""

    def test_confirmed_finding(self):
        """Both CleanShift and external tool flag the same file."""
        threat = FakeThreat("/var/www/html/backdoor.php")
        ext = [{"source": "imunify360", "file": "/var/www/html/backdoor.php", "signature": "webshell"}]
        finding = ConcordanceFinding("/var/www/html/backdoor.php", threat, ext)

        self.assertEqual(finding.status, "confirmed")
        self.assertGreater(finding.confidence_score, 0.7)
        self.assertEqual(finding.agreement_count, 2)
        self.assertIn("cleanshift", finding.sources)
        self.assertIn("imunify360", finding.sources)

    def test_cleanshift_only_finding(self):
        """Only CleanShift flagged the file."""
        threat = FakeThreat("/var/www/html/obfuscated.php")
        finding = ConcordanceFinding("/var/www/html/obfuscated.php", threat, [])

        self.assertEqual(finding.status, "cleanshift_only")
        self.assertAlmostEqual(finding.confidence_score, 0.6)
        self.assertEqual(finding.agreement_count, 1)

    def test_external_only_finding(self):
        """Only external tools flagged the file."""
        ext = [{"source": "clamav", "file": "/var/www/html/malware.php", "signature": "Trojan.PHP"}]
        finding = ConcordanceFinding("/var/www/html/malware.php", None, ext)

        self.assertEqual(finding.status, "external_only")
        self.assertEqual(finding.agreement_count, 1)

    def test_multi_external_confirmation(self):
        """Multiple external tools agree — higher confidence."""
        threat = FakeThreat("/var/www/html/backdoor.php")
        ext = [
            {"source": "imunify360", "file": "/var/www/html/backdoor.php", "signature": "webshell"},
            {"source": "clamav", "file": "/var/www/html/backdoor.php", "signature": "PHP.Shell"},
            {"source": "wordfence", "file": "/var/www/html/backdoor.php", "signature": "Backdoor"},
        ]
        finding = ConcordanceFinding("/var/www/html/backdoor.php", threat, ext)

        self.assertEqual(finding.status, "confirmed")
        self.assertEqual(finding.agreement_count, 4)
        self.assertGreater(finding.confidence_score, 0.9)

    def test_to_dict(self):
        """Finding serializes to dict properly."""
        threat = FakeThreat("/test.php", severity="critical", description="backdoor found")
        finding = ConcordanceFinding("/test.php", threat, [])
        d = finding.to_dict()

        self.assertEqual(d["file"], "/test.php")
        self.assertEqual(d["status"], "cleanshift_only")
        self.assertIn("confidence", d)
        self.assertIn("sources", d)
        self.assertIsNotNone(d["cleanshift"])

    def test_clean_finding(self):
        """No flags from anyone — clean."""
        finding = ConcordanceFinding("/clean.php", None, [])
        self.assertEqual(finding.status, "clean")
        self.assertEqual(finding.confidence_score, 0.0)


class TestConcordanceEngine(unittest.TestCase):
    """Tests for the ConcordanceEngine orchestration."""

    def test_standalone_mode(self):
        """Engine works with no external tools available."""
        engine = ConcordanceEngine()
        threats = [
            FakeThreat("/var/www/html/backdoor.php"),
            FakeThreat("/var/www/html/shell.php"),
        ]
        report = engine.concordance("/var/www/html", threats)

        self.assertIsInstance(report, ConcordanceReport)
        self.assertEqual(report.stats["total_findings"], 2)
        self.assertEqual(report.stats["cleanshift_only"], 2)
        self.assertEqual(report.stats["confirmed"], 0)

    def test_empty_scan(self):
        """No threats from any source produces empty report."""
        engine = ConcordanceEngine()
        report = engine.concordance("/var/www/html", [])

        self.assertEqual(report.stats["total_findings"], 0)
        self.assertEqual(report.stats["confirmed"], 0)
        # Summary should contain the report header
        self.assertIn("Concordance Report", report.summary)

    def test_gap_analysis(self):
        """Gap analysis correctly categorises findings."""
        engine = ConcordanceEngine()
        threats = [
            FakeThreat("/var/www/html/backdoor.php"),
        ]
        report = engine.concordance("/var/www/html", threats)
        gaps = report.gap_analysis()

        self.assertEqual(len(gaps["missed_by_external"]), 1)
        self.assertEqual(len(gaps["missed_by_cleanshift"]), 0)
        self.assertEqual(len(gaps["confirmed"]), 0)


class TestConcordanceReport(unittest.TestCase):
    """Tests for report generation."""

    def test_summary_format(self):
        """Summary produces readable text."""
        findings = [
            ConcordanceFinding("/a.php", FakeThreat("/a.php"), []),
            ConcordanceFinding("/b.php", FakeThreat("/b.php"),
                              [{"source": "clamav", "file": "/b.php", "signature": "test"}]),
        ]
        report = ConcordanceReport("/var/www", findings, ["ClamAV"], 0.5)

        summary = report.summary
        self.assertIn("Concordance Report", summary)
        self.assertIn("ClamAV", summary)
        self.assertIn("Confirmed", summary)
        self.assertIn("CleanShift-only", summary)

    def test_to_json(self):
        """Report serializes to valid JSON."""
        findings = [
            ConcordanceFinding("/test.php", FakeThreat("/test.php"), []),
        ]
        report = ConcordanceReport("/var/www", findings, [], 0.1)
        json_str = report.to_json()

        parsed = json.loads(json_str)
        self.assertEqual(parsed["site_path"], "/var/www")
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertIn("stats", parsed)

    def test_stats_accuracy(self):
        """Stats correctly count by status."""
        confirmed = ConcordanceFinding(
            "/a.php", FakeThreat("/a.php"),
            [{"source": "imunify360", "file": "/a.php", "signature": "x"}],
        )
        cs_only = ConcordanceFinding("/b.php", FakeThreat("/b.php"), [])
        ext_only = ConcordanceFinding(
            "/c.php", None,
            [{"source": "clamav", "file": "/c.php", "signature": "y"}],
        )

        report = ConcordanceReport("/var/www", [confirmed, cs_only, ext_only], ["Imunify", "ClamAV"], 0.2)

        self.assertEqual(report.stats["total_findings"], 3)
        self.assertEqual(report.stats["confirmed"], 1)
        self.assertEqual(report.stats["cleanshift_only"], 1)
        self.assertEqual(report.stats["external_only"], 1)
        self.assertEqual(report.stats["tools_available"], 2)


class TestAdapters(unittest.TestCase):
    """Tests for third-party tool adapters."""

    def test_imunify_not_available(self):
        """ImunifyAdapter gracefully handles missing installation."""
        adapter = ImunifyAdapter()
        # On non-server machines, this should return empty
        findings = adapter.get_findings("/nonexistent/path")
        self.assertIsInstance(findings, list)

    def test_clamav_not_available(self):
        """ClamAVAdapter gracefully handles missing installation."""
        adapter = ClamAVAdapter()
        findings = adapter.get_findings("/nonexistent/path")
        self.assertIsInstance(findings, list)

    def test_cpguard_not_available(self):
        """CPGuardAdapter gracefully handles missing log file."""
        adapter = CPGuardAdapter()
        findings = adapter.get_findings("/nonexistent/path")
        self.assertIsInstance(findings, list)

    def test_wordfence_no_scan_file(self):
        """WordfenceAdapter returns empty when no scan issues file exists."""
        adapter = WordfenceAdapter()
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = adapter.get_findings(tmpdir)
            self.assertEqual(findings, [])

    def test_wordfence_with_scan_file(self):
        """WordfenceAdapter reads Wordfence scan issues JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wflogs_dir = os.path.join(tmpdir, "wp-content", "wflogs")
            os.makedirs(wflogs_dir)

            issues = [
                {
                    "type": "file",
                    "severity": 4,
                    "shortMsg": "Known malicious file",
                    "status": "new",
                    "time": "2026-06-07T00:00:00",
                    "data": {"file": "wp-content/uploads/backdoor.php"},
                },
            ]
            with open(os.path.join(wflogs_dir, "scan-issues.json"), "w") as f:
                json.dump(issues, f)

            adapter = WordfenceAdapter()
            findings = adapter.get_findings(tmpdir)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["source"], "wordfence")
            self.assertEqual(findings[0]["severity"], "critical")
            self.assertIn("backdoor", findings[0]["file"])


if __name__ == "__main__":
    unittest.main()
