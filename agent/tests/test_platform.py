"""
CleanShift Test Suite — Platform Detection & Universal Scanners
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for:
- PlatformDetector  — CMS/framework detection from filesystem signatures
- PlatformInfo      — metadata correctness
- UniversalScanner  — all platform-agnostic security scanners

Uses pytest fixtures with tmp_path for isolated filesystem tests.
Python 3.6+ compatible.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.src.models import (
    Severity,
    Threat,
    ThreatType,
)
from agent.src.platform import (
    PlatformDetector,
    PlatformInfo,
    PlatformType,
)
from agent.src.universal import (
    AdminExposureScanner,
    BackupFileScanner,
    ComposerAuditScanner,
    DebugModeScanner,
    EnvFileScanner,
    GitExposureScanner,
    PHPConfigScanner,
    PlatformConfigScanner,
    SymlinkScanner,
    UniversalScanner,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def detector():
    """Create a PlatformDetector instance."""
    return PlatformDetector()


@pytest.fixture
def wp_site_dir(tmp_path):
    """Create a minimal WordPress site structure for detection tests."""
    site = tmp_path / "public_html"
    site.mkdir()

    # Core WordPress files
    (site / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'testdb');\n"
        "define('DB_USER', 'testuser');\n"
        "define('DB_PASSWORD', 'testpass');\n"
        "define('DB_HOST', 'localhost');\n"
        "$table_prefix = 'wp_';\n"
        "define('AUTH_KEY', 'unique-key-here');\n"
        "define('SECURE_AUTH_KEY', 'unique-key-here');\n"
        "define('LOGGED_IN_KEY', 'unique-key-here');\n"
        "define('NONCE_KEY', 'unique-key-here');\n"
        "define('AUTH_SALT', 'unique-salt-here');\n"
        "define('SECURE_AUTH_SALT', 'unique-salt-here');\n"
        "define('LOGGED_IN_SALT', 'unique-salt-here');\n"
        "define('NONCE_SALT', 'unique-salt-here');\n"
    )

    (site / "wp-admin").mkdir()
    (site / "wp-admin" / "admin.php").write_text("<?php // admin")
    (site / "wp-includes").mkdir()
    (site / "wp-includes" / "version.php").write_text(
        "<?php\n"
        "$wp_version = '6.5.2';\n"
        "$wp_db_version = 57155;\n"
    )
    (site / "wp-content").mkdir()
    (site / "wp-content" / "uploads").mkdir()
    (site / "wp-content" / "plugins").mkdir()
    (site / "wp-content" / "themes").mkdir()

    return site


@pytest.fixture
def joomla_site_dir(tmp_path):
    """Create a minimal Joomla site structure."""
    site = tmp_path / "joomla"
    site.mkdir()

    (site / "configuration.php").write_text(
        "<?php\n"
        "class JConfig {\n"
        "    public $host = 'localhost';\n"
        "    public $db = 'joomladb';\n"
        "    public $user = 'juser';\n"
        "    public $password = 'jpass';\n"
        "    public $dbprefix = 'j4x_';\n"
        "    public $secret = 'joomla-secret-key';\n"
        "}\n"
    )
    (site / "administrator").mkdir()
    (site / "administrator" / "index.php").write_text("<?php // admin")

    # Joomla 4+ signature
    libs_dir = site / "libraries" / "src"
    libs_dir.mkdir(parents=True)
    (libs_dir / "Version.php").write_text("<?php // Joomla version")

    return site


@pytest.fixture
def drupal_site_dir(tmp_path):
    """Create a minimal Drupal site structure."""
    site = tmp_path / "drupal"
    site.mkdir()

    settings_dir = site / "sites" / "default"
    settings_dir.mkdir(parents=True)
    (settings_dir / "settings.php").write_text(
        "<?php\n"
        "$databases['default']['default'] = array(\n"
        "    'database' => 'drupaldb',\n"
        "    'username' => 'duser',\n"
        "    'password' => 'dpass',\n"
        "    'host' => 'localhost',\n"
        ");\n"
        "$settings['hash_salt'] = 'drupal-hash-salt';\n"
    )

    core_dir = site / "core" / "lib"
    core_dir.mkdir(parents=True)
    (core_dir / "Drupal.php").write_text(
        "<?php\n"
        "class Drupal {\n"
        "    const VERSION = '10.2.3';\n"
        "}\n"
    )

    return site


@pytest.fixture
def laravel_site_dir(tmp_path):
    """Create a minimal Laravel site structure."""
    site = tmp_path / "laravel"
    site.mkdir()

    (site / "artisan").write_text("#!/usr/bin/env php\n<?php // artisan")
    http_dir = site / "app" / "Http"
    http_dir.mkdir(parents=True)
    (http_dir / "Kernel.php").write_text("<?php // Kernel")
    bootstrap_dir = site / "bootstrap"
    bootstrap_dir.mkdir()
    (bootstrap_dir / "app.php").write_text("<?php // bootstrap")

    (site / ".env").write_text(
        "APP_NAME=Laravel\n"
        "APP_DEBUG=false\n"
        "APP_KEY=base64:somekey\n"
        "DB_HOST=127.0.0.1\n"
        "DB_DATABASE=laraveldb\n"
        "DB_USERNAME=luser\n"
        "DB_PASSWORD=lpass\n"
    )

    return site


@pytest.fixture
def magento2_site_dir(tmp_path):
    """Create a minimal Magento 2 site structure."""
    site = tmp_path / "magento"
    site.mkdir()

    (site / "bin").mkdir()
    (site / "bin" / "magento").write_text("#!/usr/bin/env php\n<?php // magento")
    env_dir = site / "app" / "etc"
    env_dir.mkdir(parents=True)
    (env_dir / "env.php").write_text(
        "<?php\n"
        "return array(\n"
        "    'db' => array(\n"
        "        'connection' => array(\n"
        "            'default' => array(\n"
        "                'host' => 'localhost',\n"
        "                'dbname' => 'magentodb',\n"
        "                'username' => 'muser',\n"
        "                'password' => 'mpass',\n"
        "            ),\n"
        "        ),\n"
        "    ),\n"
        "    'crypt' => array(\n"
        "        'key' => 'magento-crypt-key',\n"
        "    ),\n"
        ");\n"
    )

    return site


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestPlatformDetector
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPlatformDetector:
    """Tests for CMS/framework platform detection."""

    def test_detect_wordpress(self, detector, wp_site_dir):
        """WordPress site should be detected from wp-config.php + wp-includes."""
        info = detector.detect(str(wp_site_dir))
        assert info.platform_type == PlatformType.WORDPRESS
        assert info.detection_confidence > 0.5
        assert info.admin_path == "wp-admin"

    def test_detect_joomla(self, detector, joomla_site_dir):
        """Joomla site should be detected from configuration.php + administrator/."""
        info = detector.detect(str(joomla_site_dir))
        assert info.platform_type == PlatformType.JOOMLA
        assert info.detection_confidence > 0.5

    def test_detect_drupal(self, detector, drupal_site_dir):
        """Drupal site should be detected from sites/default/settings.php."""
        info = detector.detect(str(drupal_site_dir))
        assert info.platform_type == PlatformType.DRUPAL
        assert info.detection_confidence > 0.5

    def test_detect_laravel(self, detector, laravel_site_dir):
        """Laravel app should be detected from artisan + app/Http/Kernel.php."""
        info = detector.detect(str(laravel_site_dir))
        assert info.platform_type == PlatformType.LARAVEL
        assert info.detection_confidence > 0.5

    def test_detect_magento2(self, detector, magento2_site_dir):
        """Magento 2 should be detected from bin/magento + app/etc/env.php."""
        info = detector.detect(str(magento2_site_dir))
        assert info.platform_type == PlatformType.MAGENTO2
        assert info.detection_confidence > 0.5

    def test_detect_unknown_empty_dir(self, detector, tmp_path):
        """Empty directory should fall back to STATIC."""
        site = tmp_path / "empty"
        site.mkdir()
        info = detector.detect(str(site))
        assert info.platform_type in (PlatformType.STATIC, PlatformType.CUSTOM_PHP)
        assert info.detection_confidence < 0.5

    def test_detect_custom_php(self, detector, tmp_path):
        """Directory with PHP files but no CMS should be CUSTOM_PHP."""
        site = tmp_path / "custom"
        site.mkdir()
        (site / "index.php").write_text("<?php echo 'hello';")
        (site / "about.php").write_text("<?php echo 'about';")

        info = detector.detect(str(site))
        assert info.platform_type == PlatformType.CUSTOM_PHP

    def test_detect_version_wordpress(self, detector, wp_site_dir):
        """WordPress version should be extracted from wp-includes/version.php."""
        info = detector.detect(str(wp_site_dir))
        assert info.version == "6.5.2"

    def test_detect_version_drupal(self, detector, drupal_site_dir):
        """Drupal version should be extracted from core/lib/Drupal.php."""
        info = detector.detect(str(drupal_site_dir))
        assert info.version == "10.2.3"

    def test_multiple_platforms_highest_confidence_wins(self, detector, tmp_path):
        """When multiple platforms match, highest confidence should win."""
        site = tmp_path / "hybrid"
        site.mkdir()

        # Add WordPress signatures (high confidence)
        (site / "wp-config.php").write_text("<?php // wp")
        (site / "wp-includes").mkdir()
        (site / "wp-includes" / "version.php").write_text(
            "<?php $wp_version = '6.5.0';"
        )
        (site / "wp-admin").mkdir()
        (site / "wp-admin" / "admin.php").write_text("<?php // admin")

        # Add a generic file that could match Joomla (low confidence)
        (site / "configuration.php").write_text("<?php // config")

        info = detector.detect(str(site))
        # WordPress should win because it has more high-confidence matches
        assert info.platform_type == PlatformType.WORDPRESS

    def test_confidence_scoring(self, detector, tmp_path):
        """Confidence should increase with more matching signatures."""
        site = tmp_path / "scoring"
        site.mkdir()

        # Only wp-config.php (0.9 weight out of 2.65 total)
        (site / "wp-config.php").write_text("<?php // wp")

        info = detector.detect(str(site))
        low_confidence = info.detection_confidence

        # Add wp-includes/version.php (0.95 additional)
        (site / "wp-includes").mkdir()
        (site / "wp-includes" / "version.php").write_text(
            "<?php $wp_version = '6.5.0';"
        )

        info2 = detector.detect(str(site))
        high_confidence = info2.detection_confidence

        assert high_confidence > low_confidence

    def test_detect_nonexistent_path(self, detector):
        """Non-existent path should return STATIC with zero confidence."""
        info = detector.detect("/nonexistent/path/that/does/not/exist")
        assert info.platform_type == PlatformType.STATIC
        assert info.detection_confidence == 0.0

    def test_writable_dirs(self, detector, wp_site_dir):
        """WordPress should return expected writable directories."""
        info = detector.detect(str(wp_site_dir))
        assert "wp-content/uploads" in info.writable_dirs
        assert "wp-content/cache" in info.writable_dirs

    def test_db_prefix_extraction(self, detector, wp_site_dir):
        """DB prefix should be extracted from wp-config.php."""
        info = detector.detect(str(wp_site_dir))
        assert info.db_prefix == "wp_"

    def test_config_secrets_wordpress(self, detector, wp_site_dir):
        """Config secrets extraction for WordPress."""
        info = detector.detect(str(wp_site_dir))
        secrets = detector.get_config_secrets(str(wp_site_dir), info)
        assert secrets["db_name"] == "testdb"
        assert secrets["db_user"] == "testuser"
        assert secrets["db_pass"] == "testpass"
        assert secrets["db_host"] == "localhost"

    def test_config_secrets_laravel(self, detector, laravel_site_dir):
        """Config secrets extraction for Laravel (.env)."""
        info = detector.detect(str(laravel_site_dir))
        secrets = detector.get_config_secrets(str(laravel_site_dir), info)
        assert secrets["db_name"] == "laraveldb"
        assert secrets["db_user"] == "luser"
        assert secrets["db_pass"] == "lpass"

    def test_backdoor_paths_wordpress(self, detector, wp_site_dir):
        """Backdoor paths should include WordPress-specific locations."""
        info = detector.detect(str(wp_site_dir))
        paths = detector.get_backdoor_paths(info)
        assert any("mu-plugins" in p for p in paths)
        assert any("uploads" in p for p in paths)

    def test_platform_info_to_dict(self):
        """PlatformInfo.to_dict() should produce a serializable dict."""
        info = PlatformInfo()
        info.platform_type = PlatformType.WORDPRESS
        info.version = "6.5.2"
        info.detection_confidence = 0.95
        info.writable_dirs = ["wp-content/uploads"]

        d = info.to_dict()
        assert d["platform_type"] == "wordpress"
        assert d["version"] == "6.5.2"
        assert d["detection_confidence"] == 0.95
        assert "wp-content/uploads" in d["writable_dirs"]

    def test_check_config_permissions_world_readable(self, detector, wp_site_dir):
        """Should flag world-readable config file."""
        config = wp_site_dir / "wp-config.php"
        config.chmod(0o644)  # world-readable

        info = detector.detect(str(wp_site_dir))
        issues = detector.check_config_permissions(str(wp_site_dir), info)

        world_readable = [i for i in issues if "world-readable" in i.get("title", "")]
        assert len(world_readable) >= 1

    def test_check_config_backup_detected(self, detector, wp_site_dir):
        """Should detect wp-config.php.bak."""
        (wp_site_dir / "wp-config.php.bak").write_text("<?php // backup")

        info = detector.detect(str(wp_site_dir))
        issues = detector.check_config_permissions(str(wp_site_dir), info)

        backup_issues = [i for i in issues if "backup" in i.get("title", "").lower()]
        assert len(backup_issues) >= 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestEnvFileScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnvFileScanner:
    """Tests for .env file detection."""

    def test_env_file_with_secrets(self, tmp_path):
        """Should detect .env file with real credentials as CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        (site / ".env").write_text(
            "APP_NAME=MyApp\n"
            "DB_PASSWORD=s3cr3t_p@ss\n"
            "APP_KEY=base64:abcdef1234567890\n"
            "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        )

        scanner = EnvFileScanner()
        threats = scanner.scan(str(site))

        assert len(threats) >= 1
        assert threats[0].severity == Severity.CRITICAL
        assert threats[0].details["has_real_secrets"] is True
        assert threats[0].details["secret_count"] >= 2

    def test_env_example_no_secrets(self, tmp_path):
        """Template .env.example without real secrets should be LOW."""
        site = tmp_path / "site"
        site.mkdir()
        (site / ".env.example").write_text(
            "APP_NAME=MyApp\n"
            "DB_PASSWORD=\n"
            "APP_KEY=\n"
        )

        scanner = EnvFileScanner()
        threats = scanner.scan(str(site))

        assert len(threats) == 1
        assert threats[0].severity == Severity.LOW

    def test_no_env_file(self, tmp_path):
        """No .env file should produce no threats."""
        site = tmp_path / "site"
        site.mkdir()

        scanner = EnvFileScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestGitExposureScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGitExposureScanner:
    """Tests for .git exposure detection."""

    def test_git_exposure_detected(self, tmp_path):
        """Should detect .git/HEAD in webroot as HIGH."""
        site = tmp_path / "site"
        site.mkdir()
        git_dir = site / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n")

        scanner = GitExposureScanner()
        threats = scanner.scan(str(site))

        assert len(threats) >= 1
        assert threats[0].severity == Severity.HIGH
        assert ".git" in threats[0].title.lower()

    def test_git_with_token_is_critical(self, tmp_path):
        """Git config with embedded token should be CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        git_dir = site / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
        (git_dir / "config").write_text(
            "[remote \"origin\"]\n"
            "    url = https://ghp_AbCdEf1234567890@github.com/user/repo.git\n"
        )

        scanner = GitExposureScanner()
        threats = scanner.scan(str(site))

        assert len(threats) >= 1
        assert threats[0].severity == Severity.CRITICAL
        assert threats[0].details["has_token_in_config"] is True

    def test_svn_exposure(self, tmp_path):
        """Should detect .svn directory."""
        site = tmp_path / "site"
        site.mkdir()
        svn_dir = site / ".svn"
        svn_dir.mkdir()
        (svn_dir / "entries").write_text("12\n")

        scanner = GitExposureScanner()
        threats = scanner.scan(str(site))

        assert len(threats) >= 1
        assert ".svn" in threats[0].title.lower()

    def test_no_vcs_exposure(self, tmp_path):
        """No VCS directories should produce no threats."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.php").write_text("<?php echo 'hello';")

        scanner = GitExposureScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestBackupFileScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestBackupFileScanner:
    """Tests for backup file detection."""

    def test_db_dump_detection(self, tmp_path):
        """Should detect .sql file as CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "dump.sql").write_text("CREATE TABLE users (id INT);")

        scanner = BackupFileScanner()
        threats = scanner.scan(str(site))

        assert len(threats) >= 1
        db_threats = [t for t in threats if t.details.get("type") == "db_dump"]
        assert len(db_threats) == 1
        assert db_threats[0].severity == Severity.CRITICAL

    def test_large_archive_detection(self, tmp_path):
        """Should detect large archive files as HIGH."""
        site = tmp_path / "site"
        site.mkdir()
        # Create a file larger than 1MB
        archive = site / "backup.tar.gz"
        archive.write_bytes(b"\x00" * (1024 * 1024 + 1))

        scanner = BackupFileScanner()
        threats = scanner.scan(str(site))

        archive_threats = [t for t in threats if t.details.get("type") == "archive"]
        assert len(archive_threats) == 1
        assert archive_threats[0].severity == Severity.HIGH

    def test_small_archive_ignored(self, tmp_path):
        """Archive under 1MB should not be flagged."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "small.zip").write_bytes(b"\x00" * 100)

        scanner = BackupFileScanner()
        threats = scanner.scan(str(site))

        archive_threats = [t for t in threats if t.details.get("type") == "archive"]
        assert len(archive_threats) == 0

    def test_php_backup_detection(self, tmp_path):
        """Should detect .php.bak files."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "config.php.bak").write_text("<?php // backup")

        scanner = BackupFileScanner()
        threats = scanner.scan(str(site))

        php_threats = [t for t in threats if t.details.get("type") == "php_backup"]
        assert len(php_threats) == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestDebugModeScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDebugModeScanner:
    """Tests for debug mode detection."""

    def test_wordpress_debug_mode(self, tmp_path):
        """Should detect WP_DEBUG = true."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "wp-config.php").write_text(
            "<?php\n"
            "define('WP_DEBUG', true);\n"
            "define('WP_DEBUG_DISPLAY', true);\n"
        )

        info = PlatformInfo()
        info.platform_type = PlatformType.WORDPRESS

        scanner = DebugModeScanner()
        threats = scanner.scan(str(site), info)

        debug_threats = [t for t in threats if "wp_debug" in str(t.details.get("check", ""))]
        assert len(debug_threats) >= 1
        assert any(t.severity == Severity.MEDIUM for t in debug_threats)

    def test_laravel_debug_mode(self, tmp_path):
        """Should detect APP_DEBUG=true in .env."""
        site = tmp_path / "site"
        site.mkdir()
        (site / ".env").write_text(
            "APP_NAME=Laravel\n"
            "APP_DEBUG=true\n"
        )

        info = PlatformInfo()
        info.platform_type = PlatformType.LARAVEL

        scanner = DebugModeScanner()
        threats = scanner.scan(str(site), info)

        laravel_threats = [t for t in threats if t.details.get("platform") == "laravel"]
        assert len(laravel_threats) >= 1
        assert laravel_threats[0].severity == Severity.MEDIUM

    def test_phpinfo_file_detection(self, tmp_path):
        """Should detect phpinfo.php file."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "phpinfo.php").write_text("<?php phpinfo(); ?>")

        scanner = DebugModeScanner()
        threats = scanner.scan(str(site))

        phpinfo_threats = [t for t in threats if "phpinfo" in t.title.lower()]
        assert len(phpinfo_threats) >= 1
        assert phpinfo_threats[0].severity == Severity.HIGH

    def test_no_debug_no_threats(self, tmp_path):
        """Clean site should produce no debug threats."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.php").write_text("<?php echo 'hello';")

        scanner = DebugModeScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestPHPConfigScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPHPConfigScanner:
    """Tests for PHP configuration scanning."""

    def test_allow_url_include(self, tmp_path):
        """Should flag allow_url_include = On as CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        (site / ".user.ini").write_text("allow_url_include = On\n")

        scanner = PHPConfigScanner()
        threats = scanner.scan(str(site))

        url_include = [t for t in threats if "allow_url_include" in t.title]
        assert len(url_include) == 1
        assert url_include[0].severity == Severity.CRITICAL

    def test_display_errors(self, tmp_path):
        """Should flag display_errors = On as MEDIUM."""
        site = tmp_path / "site"
        site.mkdir()
        (site / ".user.ini").write_text("display_errors = On\n")

        scanner = PHPConfigScanner()
        threats = scanner.scan(str(site))

        display_errs = [t for t in threats if "display_errors" in t.title]
        assert len(display_errs) == 1
        assert display_errs[0].severity == Severity.MEDIUM

    def test_no_ini_no_threats(self, tmp_path):
        """No .user.ini or php.ini should produce no threats."""
        site = tmp_path / "site"
        site.mkdir()

        scanner = PHPConfigScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestComposerAuditScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestComposerAuditScanner:
    """Tests for composer.lock vulnerability scanning."""

    def test_vulnerable_phpunit(self, tmp_path):
        """PHPUnit < 9.0 should be CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "composer.lock").write_text(json.dumps({
            "packages": [],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "4.8.36"},
            ],
        }))

        scanner = ComposerAuditScanner()
        threats = scanner.scan(str(site))

        phpunit_threats = [t for t in threats if "phpunit" in t.title.lower()]
        assert len(phpunit_threats) >= 1
        assert phpunit_threats[0].severity == Severity.CRITICAL

    def test_vulnerable_phpmailer(self, tmp_path):
        """PHPMailer < 6.5.0 should be HIGH."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "composer.lock").write_text(json.dumps({
            "packages": [
                {"name": "phpmailer/phpmailer", "version": "v6.1.0"},
            ],
        }))

        scanner = ComposerAuditScanner()
        threats = scanner.scan(str(site))

        mailer_threats = [t for t in threats if "phpmailer" in t.title.lower()]
        assert len(mailer_threats) == 1
        assert mailer_threats[0].severity == Severity.HIGH

    def test_clean_dependencies(self, tmp_path):
        """Up-to-date dependencies should produce no threats."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "composer.lock").write_text(json.dumps({
            "packages": [
                {"name": "phpmailer/phpmailer", "version": "v6.9.1"},
                {"name": "guzzlehttp/guzzle", "version": "v7.8.0"},
                {"name": "twig/twig", "version": "v3.8.0"},
            ],
        }))

        scanner = ComposerAuditScanner()
        threats = scanner.scan(str(site))

        vuln_threats = [t for t in threats if t.threat_type == ThreatType.VULNERABLE_PLUGIN]
        assert len(vuln_threats) == 0

    def test_abandoned_package_faker(self, tmp_path):
        """Abandoned fzaninotto/faker should be flagged as MEDIUM."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "composer.lock").write_text(json.dumps({
            "packages": [
                {"name": "fzaninotto/faker", "version": "v1.9.2"},
            ],
        }))

        scanner = ComposerAuditScanner()
        threats = scanner.scan(str(site))

        faker_threats = [t for t in threats if "faker" in t.title.lower()]
        assert len(faker_threats) == 1
        assert faker_threats[0].severity == Severity.MEDIUM
        assert faker_threats[0].details["status"] == "abandoned"

    def test_missing_composer_lock(self, tmp_path):
        """No composer.lock should produce no threats."""
        site = tmp_path / "site"
        site.mkdir()

        scanner = ComposerAuditScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0

    def test_phpunit_eval_stdin_on_disk(self, tmp_path):
        """PHPUnit eval-stdin.php on disk should be CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        eval_dir = (
            site / "vendor" / "phpunit" / "phpunit" / "src" / "Util" / "PHP"
        )
        eval_dir.mkdir(parents=True)
        (eval_dir / "eval-stdin.php").write_text("<?php eval($code);")

        # composer.lock must exist for the scan method to proceed
        (site / "composer.lock").write_text(json.dumps({
            "packages": [],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "4.8.36"},
            ],
        }))

        scanner = ComposerAuditScanner()
        threats = scanner.scan(str(site))

        eval_threats = [t for t in threats if "eval-stdin" in t.title.lower()]
        assert len(eval_threats) == 1
        assert eval_threats[0].severity == Severity.CRITICAL
        assert eval_threats[0].cve == "CVE-2017-9841"

    def test_version_comparison(self):
        """Version comparison logic should correctly identify vulnerable versions."""
        scanner = ComposerAuditScanner()

        # Should match (vulnerable)
        assert scanner._version_matches_spec("5.7.3", "<6.5.0") is True
        assert scanner._version_matches_spec("1.0.0", "<2.0.0") is True
        assert scanner._version_matches_spec("6.4.9", "<6.5.0") is True

        # Should not match (safe)
        assert scanner._version_matches_spec("6.5.0", "<6.5.0") is False
        assert scanner._version_matches_spec("7.0.0", "<6.5.0") is False
        assert scanner._version_matches_spec("9.5.0", "<9.0.0") is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestAdminExposureScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAdminExposureScanner:
    """Tests for exposed admin tool detection."""

    def test_adminer_detection(self, tmp_path):
        """Should detect adminer.php as CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "adminer.php").write_text("<?php // adminer")

        scanner = AdminExposureScanner()
        threats = scanner.scan(str(site))

        adminer_threats = [t for t in threats if "adminer" in t.title.lower()]
        assert len(adminer_threats) >= 1
        assert adminer_threats[0].severity == Severity.CRITICAL

    def test_phpmyadmin_directory(self, tmp_path):
        """Should detect phpmyadmin directory as HIGH."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "phpmyadmin").mkdir()

        scanner = AdminExposureScanner()
        threats = scanner.scan(str(site))

        pma_threats = [t for t in threats if "phpmyadmin" in t.title.lower()]
        assert len(pma_threats) >= 1
        assert pma_threats[0].severity == Severity.HIGH

    def test_no_admin_tools(self, tmp_path):
        """Clean site should have no admin tool threats."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.php").write_text("<?php echo 'hello';")

        scanner = AdminExposureScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestSymlinkScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSymlinkScanner:
    """Tests for symlink detection."""

    def test_symlink_outside_home(self, tmp_path):
        """Symlink pointing to sensitive system file should be CRITICAL."""
        site = tmp_path / "site"
        site.mkdir()

        # Create a symlink to /etc/passwd (a sensitive target)
        link = site / "passwd_link"
        try:
            link.symlink_to("/etc/passwd")
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")

        scanner = SymlinkScanner()
        threats = scanner.scan(str(site))

        # The symlink should be detected since it targets a sensitive system file
        symlink_threats = [t for t in threats if "symlink" in t.title.lower()]
        assert len(symlink_threats) >= 1
        assert symlink_threats[0].severity == Severity.CRITICAL

    def test_no_symlinks_is_clean(self, tmp_path):
        """Site with no symlinks should produce no threats."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.php").write_text("<?php echo 'hello';")

        scanner = SymlinkScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0

    def test_safe_symlink_within_home(self, tmp_path):
        """Symlink within same home dir should not be flagged."""
        home = tmp_path / "home" / "user"
        site = home / "public_html"
        site.mkdir(parents=True)

        # Target within the same home directory
        target = home / "shared" / "file.txt"
        target.parent.mkdir(parents=True)
        target.write_text("shared data")

        link = site / "shared_link"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")

        scanner = SymlinkScanner()
        threats = scanner.scan(str(site))

        # Should not be flagged because target is within /home/user
        assert len(threats) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestUniversalScanner (Integration)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestUniversalScanner:
    """Integration tests for the UniversalScanner façade."""

    def test_clean_site_no_threats(self, tmp_path):
        """Clean site should have zero or minimal threats."""
        site = tmp_path / "clean"
        site.mkdir()
        (site / "index.html").write_text("<html><body>Hello</body></html>")

        scanner = UniversalScanner()
        threats = scanner.scan(str(site))

        # A static site with no issues should have no high/critical threats
        critical_threats = [
            t for t in threats
            if t.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(critical_threats) == 0

    def test_full_scan_with_multiple_issues(self, tmp_path):
        """Site with multiple issues should produce threats from multiple scanners."""
        site = tmp_path / "bad"
        site.mkdir()

        # .env with secrets
        (site / ".env").write_text(
            "DB_PASSWORD=real_password\n"
            "APP_KEY=base64:realkey123\n"
        )

        # .git exposure
        git_dir = site / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n")

        # SQL dump
        (site / "database.sql").write_text("CREATE TABLE users;")

        # adminer.php
        (site / "adminer.php").write_text("<?php // adminer")

        # phpinfo.php
        (site / "phpinfo.php").write_text("<?php phpinfo(); ?>")

        scanner = UniversalScanner()
        threats = scanner.scan(str(site))

        # Should have threats from multiple scanners
        assert len(threats) >= 4

        # Verify different threat sources
        titles_lower = [t.title.lower() for t in threats]
        assert any("env" in t for t in titles_lower)
        assert any("git" in t for t in titles_lower)
        assert any("dump" in t or "database" in t or "sql" in t for t in titles_lower)
        assert any("adminer" in t for t in titles_lower)

    def test_platform_auto_detection(self, wp_site_dir):
        """UniversalScanner should auto-detect WordPress."""
        scanner = UniversalScanner()
        # Pass without explicit platform info
        threats = scanner.scan(str(wp_site_dir))

        # Should not crash and should return a list
        assert isinstance(threats, list)

    def test_scan_with_explicit_platform_info(self, tmp_path):
        """Passing explicit PlatformInfo should skip auto-detection."""
        site = tmp_path / "site"
        site.mkdir()

        info = PlatformInfo()
        info.platform_type = PlatformType.STATIC
        info.detection_confidence = 1.0

        scanner = UniversalScanner()
        threats = scanner.scan(str(site), platform_info=info)
        assert isinstance(threats, list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestPlatformConfigScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPlatformConfigScanner:
    """Tests for platform config auditing."""

    def test_wordpress_empty_password(self, tmp_path):
        """Should flag empty DB password in WordPress config."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "wp-config.php").write_text(
            "<?php\n"
            "define('DB_NAME', 'testdb');\n"
            "define('DB_USER', 'root');\n"
            "define('DB_PASSWORD', '');\n"
            "define('DB_HOST', 'localhost');\n"
        )
        (site / "wp-includes").mkdir()
        (site / "wp-includes" / "version.php").write_text(
            "<?php $wp_version = '6.5.0';"
        )
        (site / "wp-admin").mkdir()
        (site / "wp-admin" / "admin.php").write_text("<?php // admin")

        scanner = PlatformConfigScanner()
        threats = scanner.scan(str(site))

        password_threats = [
            t for t in threats
            if "password" in t.title.lower() or "password" in t.evidence.lower()
        ]
        assert len(password_threats) >= 1

    def test_static_site_no_config_threats(self, tmp_path):
        """Static site should have no config threats."""
        site = tmp_path / "site"
        site.mkdir()
        (site / "index.html").write_text("<html></html>")

        scanner = PlatformConfigScanner()
        threats = scanner.scan(str(site))
        assert len(threats) == 0
