"""
CleanShift Test Suite — Scanner Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the scanning engine including:
- FileScanner: backdoor detection, upload PHP scanning, permissions
- ScanMode: quick vs deep behavior
- Timeouts: per-file and site-level timeouts
- Memory guard: resource limit checks
- SHA256 computation
- Dynamic IOC filename loading
"""

import hashlib
import os
import stat
import tempfile
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.src.scanner import (
    FileScanner,
    FileScanTimeout,
    MemoryLimitExceeded,
    ScanMode,
    SiteScanner,
    _check_memory,
    _compute_sha256,
    _run_with_file_timeout,
)
from agent.src.intelligence import (
    BackdoorFilename,
    IntelligenceDB,
    IoC,
    MalwareDomain,
    RogueAdminPattern,
    VulnerablePlugin,
)
from agent.src.models import (
    PluginInfo,
    ScanResult,
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def mock_intel():
    """Create a mock IntelligenceDB with basic IoCs loaded."""
    intel = MagicMock(spec=IntelligenceDB)

    # Backdoor filenames
    intel.backdoor_filenames = [
        BackdoorFilename(name="shell.php", location="any", risk="critical", note="Always malicious"),
        BackdoorFilename(name="defaults.php", location="wp-admin/", risk="high", note="Known backdoor"),
        BackdoorFilename(name="wp-img.php", location="wp-includes/", risk="high"),
        BackdoorFilename(name="c99.php", location="any", risk="critical", note="c99 webshell"),
        BackdoorFilename(name="about.php", location="webroot", risk="high"),
        BackdoorFilename(name="*.ico", location="any", size=">50KB", risk="critical"),
    ]

    # Malware domains
    intel.malware_domains = [
        MalwareDomain(domain="wplicense.org", type="script_injection", cve="CVE-2024-28000"),
        MalwareDomain(domain="dijasa.com", type="script_injection"),
    ]

    # Vulnerable plugins
    intel.vulnerable_plugins = [
        VulnerablePlugin(
            name="LiteSpeed Cache", slug="litespeed-cache",
            vulnerable_versions="<6.4.1", patched_version="6.4.1",
            cve="CVE-2024-28000", severity="critical",
        ),
    ]

    # Rogue admin patterns
    intel.rogue_admin_patterns = [
        RogueAdminPattern(username_pattern="GuaUserWa5", email_pattern="*@org.com", cve="CVE-2024-28000"),
    ]

    # Matching functions
    intel.match_filename.return_value = None
    intel.match_domain.return_value = None
    intel.match_plugin.return_value = None
    intel.match_db_option.return_value = None
    intel.get_rogue_admin_patterns.return_value = intel.rogue_admin_patterns
    intel.get_detection_queries.return_value = []
    intel.db_markers = []

    return intel


@pytest.fixture
def wp_site(tmp_path):
    """Create a minimal WordPress site structure for testing."""
    site_path = tmp_path / "public_html"
    site_path.mkdir()

    # Core directories
    (site_path / "wp-admin").mkdir()
    (site_path / "wp-includes").mkdir()
    (site_path / "wp-content").mkdir()
    (site_path / "wp-content" / "uploads").mkdir(parents=True)
    (site_path / "wp-content" / "plugins").mkdir()
    (site_path / "wp-content" / "themes").mkdir()
    (site_path / "wp-content" / "mu-plugins").mkdir()

    # wp-config.php
    (site_path / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'testdb');\n"
        "define('DB_USER', 'testuser');\n"
        "define('DB_PASSWORD', 'testpass');\n"
        "define('DB_HOST', 'localhost');\n"
        "$table_prefix = 'wp_';\n"
    )

    # Legitimate files
    (site_path / "index.php").write_text("<?php // Main index")
    (site_path / "wp-admin" / "index.php").write_text("<?php // Admin")
    (site_path / "wp-includes" / "version.php").write_text(
        "<?php $wp_version = '6.5.2';"
    )

    return WordPressSite(
        path=str(site_path),
        domain="example.com",
        wp_version="6.5.2",
        db_host="localhost",
        db_name="testdb",
        db_user="testuser",
        db_pass="testpass",
        db_prefix="wp_",
        site_owner="testuser",
    )


# ─── SHA256 Tests ───────────────────────────────────────────────────

class TestSHA256:
    """Tests for _compute_sha256 helper function."""

    def test_compute_sha256_correct(self, tmp_path):
        """SHA256 should match hashlib computation."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"Hello, CleanShift!")

        expected = hashlib.sha256(b"Hello, CleanShift!").hexdigest()
        assert _compute_sha256(test_file) == expected

    def test_compute_sha256_empty_file(self, tmp_path):
        """SHA256 of an empty file should be the known empty hash."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        expected = hashlib.sha256(b"").hexdigest()
        assert _compute_sha256(test_file) == expected

    def test_compute_sha256_nonexistent(self, tmp_path):
        """SHA256 of a nonexistent file should return empty string."""
        result = _compute_sha256(tmp_path / "nonexistent.txt")
        assert result == ""

    def test_compute_sha256_large_file(self, tmp_path):
        """SHA256 should work for files larger than 64KB chunk size."""
        test_file = tmp_path / "large.bin"
        data = b"x" * (128 * 1024)  # 128KB
        test_file.write_bytes(data)

        expected = hashlib.sha256(data).hexdigest()
        assert _compute_sha256(test_file) == expected


# ─── Per-File Timeout Tests ─────────────────────────────────────────

class TestFileTimeout:
    """Tests for _run_with_file_timeout."""

    def test_fast_function_succeeds(self):
        """Fast function should complete within timeout."""
        result = _run_with_file_timeout(lambda: 42, timeout_seconds=5)
        assert result == 42

    def test_slow_function_times_out(self):
        """Slow function should raise FileScanTimeout."""
        def slow():
            time.sleep(10)
            return "never"

        with pytest.raises(FileScanTimeout):
            _run_with_file_timeout(slow, timeout_seconds=1)

    def test_function_exception_propagates(self):
        """Exceptions from the scanned function should propagate."""
        def failing():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            _run_with_file_timeout(failing, timeout_seconds=5)

    def test_returns_none_correctly(self):
        """Function returning None should not be treated as timeout."""
        result = _run_with_file_timeout(lambda: None, timeout_seconds=5)
        assert result is None


# ─── Memory Guard Tests ────────────────────────────────────────────

class TestMemoryGuard:
    """Tests for _check_memory."""

    def test_memory_check_passes_with_high_limit(self):
        """Memory check should pass with a very high limit."""
        # 10GB limit — should always pass
        _check_memory(limit_mb=10240)

    def test_memory_check_fails_with_zero_limit(self):
        """Memory check should fail with a zero limit."""
        with pytest.raises(MemoryLimitExceeded):
            _check_memory(limit_mb=0)

    @patch("agent.src.scanner.resource")
    def test_memory_check_graceful_on_error(self, mock_resource):
        """Memory check should not crash on platform errors."""
        mock_resource.getrusage.side_effect = AttributeError("not available")
        # Should not raise
        _check_memory(limit_mb=512)


# ─── FileScanner Tests ─────────────────────────────────────────────

class TestFileScanner:
    """Tests for the FileScanner class."""

    def test_detects_known_backdoor(self, mock_intel, wp_site):
        """FileScanner should detect files matching known backdoor names."""
        site_path = Path(wp_site.path)
        # Plant a backdoor
        (site_path / "shell.php").write_text("<?php system($_GET['cmd']); ?>")

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        backdoor_threats = [t for t in threats if t.threat_type == ThreatType.BACKDOOR_FILE]
        assert len(backdoor_threats) >= 1
        assert any("shell.php" in t.title for t in backdoor_threats)

    def test_detects_php_in_uploads(self, mock_intel, wp_site):
        """FileScanner should detect PHP files in wp-content/uploads/."""
        site_path = Path(wp_site.path)
        uploads = site_path / "wp-content" / "uploads"
        (uploads / "backdoor.php").write_text("<?php eval(base64_decode($_POST['cmd'])); ?>")

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        upload_threats = [t for t in threats if "uploads" in str(t.location)]
        assert len(upload_threats) >= 1

    def test_skips_legitimate_index_php_in_uploads(self, mock_intel, wp_site):
        """FileScanner should skip small index.php files in uploads."""
        site_path = Path(wp_site.path)
        uploads = site_path / "wp-content" / "uploads"
        (uploads / "index.php").write_text("<?php // Silence is golden.")

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        # index.php should NOT be flagged
        index_threats = [t for t in threats if "index.php" in str(t.location)]
        assert len(index_threats) == 0

    def test_wp_config_perms_not_in_file_scanner(self, mock_intel, wp_site):
        """FileScanner should NOT check wp-config.php permissions (handled by ConfigScanner)."""
        site_path = Path(wp_site.path)
        wp_config = site_path / "wp-config.php"
        # Make world-readable
        wp_config.chmod(0o644)

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        # wp-config.php permission check is now in ConfigScanner (extended_scanners.py)
        # FileScanner should NOT produce permission issues for wp-config.php
        wp_config_perm_threats = [
            t for t in threats
            if t.threat_type == ThreatType.PERMISSION_ISSUE
            and "wp-config" in (t.title or "").lower()
        ]
        assert len(wp_config_perm_threats) == 0

    def test_detects_suspicious_content_patterns(self, mock_intel, wp_site):
        """FileScanner should flag PHP files with multiple suspicious patterns."""
        site_path = Path(wp_site.path)
        malicious_content = (
            '<?php\n'
            'eval(base64_decode($_POST["cmd"]));\n'
            'system($cmd);\n'
            'passthru($x);\n'
        )
        (site_path / "evil.php").write_text(malicious_content)

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        content_threats = [t for t in threats if "evil.php" in str(t.location)]
        assert len(content_threats) >= 1

    def test_quick_mode_skips_content_heuristics(self, mock_intel, wp_site):
        """Quick mode should NOT run content heuristic analysis."""
        site_path = Path(wp_site.path)
        malicious_content = (
            '<?php\n'
            'eval(base64_decode($_POST["cmd"]));\n'
            'system($cmd);\n'
            'passthru($x);\n'
        )
        (site_path / "sneaky.php").write_text(malicious_content)

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.QUICK, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        # sneaky.php should NOT be detected in quick mode (not a known IOC filename)
        content_threats = [t for t in threats if "sneaky.php" in str(t.location)]
        assert len(content_threats) == 0

    def test_sha256_added_to_threats(self, mock_intel, wp_site):
        """All file-based threats should include SHA256 in details."""
        site_path = Path(wp_site.path)
        (site_path / "shell.php").write_text("<?php // malware")

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        for threat in threats:
            if threat.location and Path(threat.location).is_file():
                assert "sha256" in threat.details, f"Missing SHA256 for {threat.location}"
                assert len(threat.details["sha256"]) == 64  # SHA256 hex length

    def test_progress_callback_is_called(self, mock_intel, wp_site):
        """Progress callback should be invoked during scan."""
        progress_calls = []

        def callback(phase, detail, current, total):
            progress_calls.append((phase, detail, current, total))

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, progress_callback=callback, memory_limit_mb=99999)
        scanner.scan(wp_site)

        assert len(progress_calls) > 0
        phases = {call[0] for call in progress_calls}
        assert "file_scan" in phases

    def test_handles_nonexistent_site_path(self, mock_intel):
        """FileScanner should return empty list for nonexistent paths."""
        site = WordPressSite(
            path="/nonexistent/path/wp",
            domain="ghost.com",
            wp_version="6.5.2",
        )
        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(site)
        assert threats == []

    def test_detects_large_ico_file(self, mock_intel, wp_site):
        """FileScanner should flag .ico files larger than 50KB."""
        site_path = Path(wp_site.path)
        large_ico = site_path / "favicon.ico"
        large_ico.write_bytes(b"x" * (60 * 1024))  # 60KB

        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        threats = scanner.scan(wp_site)

        ico_threats = [t for t in threats if "ico" in t.title.lower()]
        assert len(ico_threats) >= 1

    def test_dynamic_check_paths_from_ioc(self, mock_intel, wp_site):
        """_build_dynamic_check_paths should generate paths from IOC database."""
        site_path = Path(wp_site.path)
        scanner = FileScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        paths = scanner._build_dynamic_check_paths(site_path)

        # Should include paths from mock IOC backdoor_filenames
        path_names = {p.name for p, _ in paths}
        assert "shell.php" in path_names
        assert "defaults.php" in path_names
        assert "wp-img.php" in path_names


# ─── SiteScanner Tests ─────────────────────────────────────────────

class TestSiteScanner:
    """Tests for the SiteScanner orchestrator."""

    @patch("agent.src.scanner.DatabaseScanner")
    @patch("agent.src.scanner.PluginAuditor")
    @patch("agent.src.scanner.CoreIntegrityChecker")
    def test_site_scanner_runs_all_layers(self, mock_core, mock_plugin, mock_db, mock_intel, wp_site):
        """SiteScanner should run file, DB, plugin, and core checks."""
        # Make mocked scanner layers return empty lists
        mock_db.return_value.scan.return_value = []
        mock_plugin.return_value.scan.return_value = []
        mock_core.return_value.scan.return_value = []

        scanner = SiteScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        # Replace internal scanners with mocks
        scanner.db_scanner = mock_db.return_value
        scanner.plugin_auditor = mock_plugin.return_value
        scanner.core_checker = mock_core.return_value
        # Also mock the file scanner to avoid memory checks
        scanner.file_scanner = MagicMock()
        scanner.file_scanner.scan.return_value = []

        threats = scanner.scan(wp_site)

        # All layers should have been called
        mock_db.return_value.scan.assert_called_once_with(wp_site)
        mock_plugin.return_value.scan.assert_called_once_with(wp_site)
        mock_core.return_value.scan.assert_called_once_with(wp_site)

    @patch("agent.src.scanner.DatabaseScanner")
    @patch("agent.src.scanner.PluginAuditor")
    @patch("agent.src.scanner.CoreIntegrityChecker")
    def test_quick_mode_skips_core_integrity(self, mock_core, mock_plugin, mock_db, mock_intel, wp_site):
        """Quick mode should skip the core integrity check."""
        mock_db.return_value.scan.return_value = []
        mock_plugin.return_value.scan.return_value = []
        mock_core.return_value.scan.return_value = []

        scanner = SiteScanner(mock_intel, scan_mode=ScanMode.QUICK, memory_limit_mb=99999)
        scanner.db_scanner = mock_db.return_value
        scanner.plugin_auditor = mock_plugin.return_value
        scanner.core_checker = mock_core.return_value
        scanner.file_scanner = MagicMock()
        scanner.file_scanner.scan.return_value = []

        scanner.scan(wp_site)

        # Core checker should NOT be called in quick mode
        mock_core.return_value.scan.assert_not_called()

    @patch("agent.src.scanner.DatabaseScanner")
    def test_resilience_layer_crash_continues(self, mock_db, mock_intel, wp_site):
        """If one scanner layer crashes, others should still run."""
        mock_db.return_value.scan.side_effect = RuntimeError("DB connection failed")

        scanner = SiteScanner(mock_intel, scan_mode=ScanMode.DEEP, memory_limit_mb=99999)
        scanner.db_scanner = mock_db.return_value
        scanner.file_scanner = MagicMock()
        scanner.file_scanner.scan.return_value = []

        # Should not raise — catches errors per layer
        threats = scanner.scan(wp_site)
        assert isinstance(threats, list)


# ─── Intelligence Matching Tests ────────────────────────────────────

class TestIntelligenceMatching:
    """Tests for IntelligenceDB matching functions."""

    def test_match_filename_known_backdoor(self):
        """match_filename should identify known backdoor files."""
        intel = IntelligenceDB()
        intel.backdoor_filenames = [
            BackdoorFilename(name="shell.php", location="any", risk="critical"),
        ]
        intel._loaded = True

        result = intel.match_filename("shell.php")
        assert result is not None
        assert result.indicator_type == "backdoor_file"
        assert result.severity == "critical"

    def test_match_filename_no_match(self):
        """match_filename should return None for legitimate files."""
        intel = IntelligenceDB()
        intel.backdoor_filenames = [
            BackdoorFilename(name="shell.php", location="any", risk="critical"),
        ]
        intel._loaded = True

        result = intel.match_filename("legitimate-plugin.php")
        assert result is None

    def test_match_domain_known_malware(self):
        """match_domain should identify known malware domains."""
        intel = IntelligenceDB()
        intel.malware_domains = [
            MalwareDomain(domain="wplicense.org", type="script_injection", cve="CVE-2024-28000"),
        ]
        intel._loaded = True

        result = intel.match_domain("https://wplicense.org/admin-bar.js")
        assert result is not None
        assert result.cve == "CVE-2024-28000"

    def test_match_domain_no_match(self):
        """match_domain should return None for legitimate domains."""
        intel = IntelligenceDB()
        intel.malware_domains = [
            MalwareDomain(domain="wplicense.org"),
        ]
        intel._loaded = True

        result = intel.match_domain("https://wordpress.org/plugins/")
        assert result is None

    def test_version_comparison_lt(self):
        """Version comparison should correctly identify older versions."""
        assert IntelligenceDB._version_lt("6.4.0", "6.4.1") is True
        assert IntelligenceDB._version_lt("6.4.1", "6.4.1") is False
        assert IntelligenceDB._version_lt("6.4.2", "6.4.1") is False
        assert IntelligenceDB._version_lt("5.9", "6.0") is True
        assert IntelligenceDB._version_lt("6.5.2", "6.4.1") is False

    def test_match_plugin_vulnerable(self):
        """match_plugin should flag vulnerable plugin versions."""
        intel = IntelligenceDB()
        intel.vulnerable_plugins = [
            VulnerablePlugin(
                slug="litespeed-cache",
                patched_version="6.4.1",
                cve="CVE-2024-28000",
                severity="critical",
            ),
        ]
        intel._loaded = True

        result = intel.match_plugin("litespeed-cache", "6.3.0")
        assert result is not None
        assert result.cve == "CVE-2024-28000"

    def test_match_plugin_patched(self):
        """match_plugin should not flag patched plugin versions."""
        intel = IntelligenceDB()
        intel.vulnerable_plugins = [
            VulnerablePlugin(
                slug="litespeed-cache",
                patched_version="6.4.1",
                cve="CVE-2024-28000",
            ),
        ]
        intel._loaded = True

        result = intel.match_plugin("litespeed-cache", "6.5.0")
        assert result is None


# ─── IOC Database Loading Tests ─────────────────────────────────────

class TestIOCDatabaseLoading:
    """Tests for loading the actual IOC database."""

    def test_load_ioc_database(self):
        """The real IOC database should load without errors."""
        intel_dir = Path(__file__).resolve().parent.parent.parent / "intelligence"
        if not (intel_dir / "indicators" / "ioc-database.yaml").exists():
            pytest.skip("IOC database not found")

        intel = IntelligenceDB(intel_dir)
        intel.load()

        # Verify substantial data was loaded
        assert len(intel.malware_domains) >= 20, f"Expected 20+ domains, got {len(intel.malware_domains)}"
        assert len(intel.backdoor_filenames) >= 20, f"Expected 20+ backdoor patterns, got {len(intel.backdoor_filenames)}"
        assert len(intel.vulnerable_plugins) >= 10, f"Expected 10+ vulnerable plugins, got {len(intel.vulnerable_plugins)}"
        assert len(intel.detection_queries) >= 5, f"Expected 5+ detection queries, got {len(intel.detection_queries)}"
        assert len(intel.rogue_admin_patterns) >= 5, f"Expected 5+ rogue patterns, got {len(intel.rogue_admin_patterns)}"

    def test_ioc_database_has_cve_entries(self):
        """IOC database should contain CVE references."""
        intel_dir = Path(__file__).resolve().parent.parent.parent / "intelligence"
        if not (intel_dir / "indicators" / "ioc-database.yaml").exists():
            pytest.skip("IOC database not found")

        intel = IntelligenceDB(intel_dir)
        intel.load()

        cves = set()
        for vp in intel.vulnerable_plugins:
            if vp.cve:
                cves.add(vp.cve)
        for md in intel.malware_domains:
            if md.cve:
                cves.add(md.cve)

        assert "CVE-2024-28000" in cves, "CVE-2024-28000 should be in the IOC database"
        assert len(cves) >= 5, f"Expected 5+ unique CVEs, got {len(cves)}"
