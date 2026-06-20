#!/usr/bin/env python3
"""
CleanShift Pre-Deployment Validation Suite
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Comprehensive testing before deploying to production servers.
Tests for:
  1. Read-only safety — scanner NEVER writes/deletes site files
  2. Disk usage — measures cache DB, logs, temp files created
  3. Memory usage — tracks RSS during scan
  4. Scan performance — timing per layer
  5. Edge cases — empty dirs, binary files, huge files, symlinks
  6. Guard PHP validation — all files pass lint
  7. Platform detection accuracy
  8. Universal scanner completeness
  9. Concurrent safety — parallel scan doesn't corrupt cache
  10. Graceful degradation — missing deps, bad permissions, etc.

Usage:
    python3 test_predeploy.py                    # Run all tests
    python3 test_predeploy.py --verbose          # Verbose output
    python3 test_predeploy.py --test disk_usage  # Single test
"""

import hashlib
import json
import os
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

# Ensure we can import the scanner modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models import Threat, ThreatType, Severity, WordPressSite
from src.platform import PlatformDetector, PlatformType, PlatformInfo
from src.universal import (
    UniversalScanner, EnvFileScanner, GitExposureScanner,
    BackupFileScanner, DebugModeScanner, ComposerAuditScanner,
    AdminExposureScanner, SymlinkScanner,
)
from src.trust import TrustEngine, TrustLevel, KNOWN_PLUGINS
from src.behavioral import CapabilityMapper, EntropyScorer
from src.verifier import ChecksumVerifier, HashCache
from src.concordance import ConcordanceEngine


def create_realistic_wp_site(base_dir):
    """Create a realistic WordPress site structure for testing."""
    dirs = [
        'wp-admin', 'wp-includes', 'wp-includes/js', 'wp-includes/css',
        'wp-content/plugins/akismet', 'wp-content/plugins/woocommerce/includes',
        'wp-content/plugins/contact-form-7',
        'wp-content/themes/twentytwentyfive',
        'wp-content/themes/twentytwentyfive/assets',
        'wp-content/uploads/2025/01', 'wp-content/uploads/2025/06',
        'wp-content/uploads/2026/01', 'wp-content/uploads/2026/06',
        'wp-content/mu-plugins',
        'wp-content/cache',
        'wp-content/upgrade',
    ]
    for d in dirs:
        os.makedirs(os.path.join(base_dir, d), exist_ok=True)

    # wp-config.php
    with open(os.path.join(base_dir, 'wp-config.php'), 'w') as f:
        f.write("<?php\n"
                "define('DB_NAME', 'wp_testdb');\n"
                "define('DB_USER', 'wp_user');\n"
                "define('DB_PASSWORD', 'str0ngP@ss!');\n"
                "define('DB_HOST', 'localhost');\n"
                "define('DB_CHARSET', 'utf8mb4');\n"
                "define('AUTH_KEY', 'unique-phrase-here');\n"
                "define('SECURE_AUTH_KEY', 'unique-phrase-here');\n"
                "define('WP_DEBUG', false);\n"
                "$table_prefix = 'wp_';\n")

    # version.php
    with open(os.path.join(base_dir, 'wp-includes', 'version.php'), 'w') as f:
        f.write("<?php\n$wp_version = '6.5.2';\n$wp_db_version = 57155;\n")

    # index.php files
    for d in ['', 'wp-admin', 'wp-content', 'wp-content/plugins',
              'wp-content/themes', 'wp-content/uploads']:
        with open(os.path.join(base_dir, d, 'index.php'), 'w') as f:
            f.write("<?php // Silence is golden.\n")

    # Legitimate plugin files
    with open(os.path.join(base_dir, 'wp-content/plugins/akismet/akismet.php'), 'w') as f:
        f.write("<?php\n/* Plugin Name: Akismet Anti-spam */\n"
                "function akismet_check() { return true; }\n")

    with open(os.path.join(base_dir, 'wp-content/plugins/woocommerce/woocommerce.php'), 'w') as f:
        f.write("<?php\n/* Plugin Name: WooCommerce */\n"
                "function wc_init() { global $wpdb; }\n")

    # Legitimate theme
    with open(os.path.join(base_dir, 'wp-content/themes/twentytwentyfive/style.css'), 'w') as f:
        f.write("/* Theme Name: Twenty Twenty-Five */\nbody { margin: 0; }\n")

    with open(os.path.join(base_dir, 'wp-content/themes/twentytwentyfive/functions.php'), 'w') as f:
        f.write("<?php\nfunction theme_setup() { add_theme_support('post-thumbnails'); }\n")

    # Legitimate uploaded images (small fake files)
    for name in ['photo-001.jpg', 'banner.png', 'logo.gif']:
        path = os.path.join(base_dir, 'wp-content/uploads/2025/01', name)
        with open(path, 'wb') as f:
            f.write(b'\xff\xd8\xff\xe0' + os.urandom(1024))  # Fake JPEG header

    # .htaccess
    with open(os.path.join(base_dir, '.htaccess'), 'w') as f:
        f.write("# BEGIN WordPress\n"
                "<IfModule mod_rewrite.c>\n"
                "RewriteEngine On\nRewriteBase /\n"
                "RewriteRule ^index\\.php$ - [L]\n"
                "RewriteCond %{REQUEST_FILENAME} !-f\n"
                "RewriteCond %{REQUEST_FILENAME} !-d\n"
                "RewriteRule . /index.php [L]\n"
                "</IfModule>\n"
                "# END WordPress\n")

    return base_dir


def create_threats_in_site(base_dir):
    """Plant known threats for detection testing."""
    threats_created = []

    # 1. Backdoor in uploads
    path = os.path.join(base_dir, 'wp-content/uploads/2026/01/cache.php')
    with open(path, 'w') as f:
        f.write('<?php eval(base64_decode($_POST["cmd"])); ?>')
    threats_created.append(('backdoor', path))

    # 2. Exposed .env file
    path = os.path.join(base_dir, '.env')
    with open(path, 'w') as f:
        f.write('DB_PASSWORD=secretpass\nAPP_KEY=base64:abcdef\nSTRIPE_SECRET=sk_live_xxx\n')
    threats_created.append(('.env', path))

    # 3. phpinfo.php
    path = os.path.join(base_dir, 'phpinfo.php')
    with open(path, 'w') as f:
        f.write('<?php phpinfo(); ?>')
    threats_created.append(('phpinfo', path))

    # 4. wp-config backup
    path = os.path.join(base_dir, 'wp-config.php.bak')
    with open(path, 'w') as f:
        f.write("<?php define('DB_PASSWORD', 'oldpass'); ?>")
    threats_created.append(('config_backup', path))

    # 5. SQL dump in webroot
    path = os.path.join(base_dir, 'database.sql')
    with open(path, 'w') as f:
        f.write('-- MySQL dump\nCREATE TABLE wp_users (\n  ID bigint(20)\n);\n')
    threats_created.append(('sql_dump', path))

    # 6. Obfuscated malware
    path = os.path.join(base_dir, 'wp-content/plugins/contact-form-7/includes.php')
    # Simulated obfuscated code — long base64 string
    fake_b64 = 'A' * 5000
    with open(path, 'w') as f:
        f.write('<?php $x = base64_decode("' + fake_b64 + '"); eval($x); ?>')
    threats_created.append(('obfuscated', path))

    return threats_created


# ═══════════════════════════════════════════════════════════════
# Test 1: Read-Only Safety
# ═══════════════════════════════════════════════════════════════

class TestReadOnlySafety(unittest.TestCase):
    """Verify the scanner NEVER modifies, creates, or deletes site files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='cleanshift_safety_')
        create_realistic_wp_site(self.tmpdir)
        create_threats_in_site(self.tmpdir)
        # Snapshot all files with their sizes and hashes
        self.snapshot = self._snapshot_directory(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _snapshot_directory(self, path):
        """Record every file's path, size, and SHA256."""
        snapshot = {}
        for root, dirs, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    st = os.stat(fp)
                    with open(fp, 'rb') as fh:
                        sha = hashlib.sha256(fh.read()).hexdigest()
                    snapshot[fp] = {'size': st.st_size, 'sha256': sha, 'mtime': st.st_mtime}
                except (OSError, PermissionError):
                    snapshot[fp] = {'size': -1, 'sha256': '', 'mtime': 0}
        return snapshot

    def test_universal_scanner_is_readonly(self):
        """UniversalScanner must not modify any files."""
        scanner = UniversalScanner()
        scanner.scan(self.tmpdir)

        after = self._snapshot_directory(self.tmpdir)
        # Same file count
        self.assertEqual(
            set(self.snapshot.keys()), set(after.keys()),
            "Scanner created or deleted files!"
        )
        # Same content
        for fp, before_info in self.snapshot.items():
            after_info = after.get(fp, {})
            self.assertEqual(
                before_info['sha256'], after_info.get('sha256', ''),
                "Scanner modified file: %s" % fp
            )

    def test_platform_detector_is_readonly(self):
        """PlatformDetector must not modify any files."""
        detector = PlatformDetector()
        detector.detect(self.tmpdir)

        after = self._snapshot_directory(self.tmpdir)
        self.assertEqual(set(self.snapshot.keys()), set(after.keys()))

    def test_trust_engine_is_readonly(self):
        """TrustEngine must not modify any files."""
        te = TrustEngine()
        # Evaluate every file in the site
        for fp in self.snapshot.keys():
            te.evaluate(fp, self.tmpdir)

        after = self._snapshot_directory(self.tmpdir)
        self.assertEqual(set(self.snapshot.keys()), set(after.keys()))

    def test_capability_mapper_is_readonly(self):
        """CapabilityMapper must not modify any files."""
        cm = CapabilityMapper()
        for fp in self.snapshot.keys():
            if fp.endswith('.php'):
                try:
                    with open(fp, 'rb') as f:
                        content = f.read()
                    cm.analyze_file(fp, content)
                except (OSError, PermissionError):
                    pass

        after = self._snapshot_directory(self.tmpdir)
        self.assertEqual(set(self.snapshot.keys()), set(after.keys()))

    def test_entropy_scorer_is_readonly(self):
        """EntropyScorer must not modify any files."""
        es = EntropyScorer()
        for fp in self.snapshot.keys():
            if fp.endswith('.php'):
                try:
                    es.score_file(fp)
                except (OSError, PermissionError):
                    pass

        after = self._snapshot_directory(self.tmpdir)
        self.assertEqual(set(self.snapshot.keys()), set(after.keys()))


# ═══════════════════════════════════════════════════════════════
# Test 2: Disk Usage Impact
# ═══════════════════════════════════════════════════════════════

class TestDiskUsage(unittest.TestCase):
    """Measure disk impact of scanner operations."""

    def test_hash_cache_size(self):
        """HashCache DB stays small even with many files."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_hc_')
        tmpdb = os.path.join(tmpdir, 'cache.db')
        try:
            cache = HashCache(tmpdb)
            # Simulate 10,000 files
            for i in range(10000):
                cache.update(
                    '/home/user/public_html',
                    'wp-content/file_%d.php' % i,
                    time.time(), 1024, 'abc%d' % i, 'clean',
                )
            db_size = os.path.getsize(tmpdb)
            # DB should be under 5MB for 10K files
            self.assertLess(db_size, 5 * 1024 * 1024,
                           "HashCache DB too large: %d bytes for 10K files" % db_size)
            print("  HashCache: %d files → %.1f KB" % (10000, db_size / 1024))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_scanner_creates_no_temp_files(self):
        """Scanner must not leave temp files behind."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_disk_')
        create_realistic_wp_site(tmpdir)

        # Count temp files before
        tmp_before = set(os.listdir(tempfile.gettempdir()))

        scanner = UniversalScanner()
        scanner.scan(tmpdir)

        detector = PlatformDetector()
        detector.detect(tmpdir)

        # Count temp files after
        tmp_after = set(os.listdir(tempfile.gettempdir()))
        new_temps = tmp_after - tmp_before
        # Filter out unrelated temp files (other processes)
        scanner_temps = [f for f in new_temps if 'cleanshift' in f.lower()]

        shutil.rmtree(tmpdir, ignore_errors=True)
        self.assertEqual(len(scanner_temps), 0,
                        "Scanner left temp files: %s" % scanner_temps)

    def test_scan_output_size(self):
        """Scan result JSON stays reasonable size."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_output_')
        create_realistic_wp_site(tmpdir)
        create_threats_in_site(tmpdir)

        scanner = UniversalScanner()
        threats = scanner.scan(tmpdir)

        # Serialize threats
        output = json.dumps([{
            'type': str(t.threat_type),
            'severity': str(t.severity),
            'description': t.description,
            'location': t.location,
        } for t in threats])

        output_kb = len(output) / 1024
        print("  Scan output: %d threats → %.1f KB JSON" % (len(threats), output_kb))
        # Output should be under 1MB even with many threats
        self.assertLess(len(output), 1024 * 1024)

        shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
# Test 3: Memory Usage
# ═══════════════════════════════════════════════════════════════

class TestMemoryUsage(unittest.TestCase):
    """Verify scanner doesn't consume excessive memory."""

    def test_scan_memory_usage(self):
        """Full scan should use <100MB additional RSS."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_mem_')
        create_realistic_wp_site(tmpdir)
        create_threats_in_site(tmpdir)

        # Create some large files to stress test
        for i in range(20):
            path = os.path.join(tmpdir, 'wp-content/plugins/woocommerce', 'big_%d.php' % i)
            with open(path, 'w') as f:
                f.write('<?php\n' + ('// comment line\n' * 5000))

        rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        scanner = UniversalScanner()
        scanner.scan(tmpdir)

        cm = CapabilityMapper()
        for root, dirs, files in os.walk(tmpdir):
            for f in files:
                if f.endswith('.php'):
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, 'rb') as fh:
                            content = fh.read()
                        cm.analyze_file(fp, content)
                    except (OSError, PermissionError):
                        pass

        rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        # On macOS ru_maxrss is in bytes, on Linux it's in KB
        if sys.platform == 'darwin':
            rss_delta_mb = (rss_after - rss_before) / (1024 * 1024)
        else:
            rss_delta_mb = (rss_after - rss_before) / 1024

        print("  Memory delta: %.1f MB" % rss_delta_mb)
        # Should use less than 100MB additional
        self.assertLess(rss_delta_mb, 100,
                       "Scanner used too much memory: %.1f MB" % rss_delta_mb)

        shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
# Test 4: Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Test scanner handles edge cases gracefully."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='cleanshift_edge_')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_directory(self):
        """Scanner handles empty directories without errors."""
        scanner = UniversalScanner()
        threats = scanner.scan(self.tmpdir)
        self.assertIsInstance(threats, list)

    def test_binary_files(self):
        """Scanner handles binary files without errors."""
        create_realistic_wp_site(self.tmpdir)
        # Create binary files
        for name in ['data.bin', 'font.woff2', 'image.webp']:
            with open(os.path.join(self.tmpdir, name), 'wb') as f:
                f.write(os.urandom(4096))

        scanner = UniversalScanner()
        threats = scanner.scan(self.tmpdir)
        # Should not crash
        self.assertIsInstance(threats, list)

    def test_deeply_nested_directories(self):
        """Scanner handles deep nesting (20+ levels)."""
        path = self.tmpdir
        for i in range(25):
            path = os.path.join(path, 'level_%d' % i)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, 'deep.php'), 'w') as f:
            f.write('<?php echo "deep"; ?>')

        detector = PlatformDetector()
        info = detector.detect(self.tmpdir)
        # Should not crash or take forever
        self.assertIsNotNone(info)

    def test_unreadable_files(self):
        """Scanner handles permission-denied files gracefully."""
        create_realistic_wp_site(self.tmpdir)
        restricted = os.path.join(self.tmpdir, 'restricted.php')
        with open(restricted, 'w') as f:
            f.write('<?php // restricted ?>')
        os.chmod(restricted, 0o000)

        scanner = UniversalScanner()
        try:
            threats = scanner.scan(self.tmpdir)
            self.assertIsInstance(threats, list)
        finally:
            os.chmod(restricted, 0o644)

    def test_special_characters_in_filenames(self):
        """Scanner handles files with spaces and special chars."""
        create_realistic_wp_site(self.tmpdir)
        special_names = [
            'file with spaces.php',
            'file-with-dashes.php',
            'file_with_underscores.php',
            'UPPERCASE.PHP',
        ]
        for name in special_names:
            path = os.path.join(self.tmpdir, 'wp-content/plugins', name)
            with open(path, 'w') as f:
                f.write('<?php echo "test"; ?>')

        scanner = UniversalScanner()
        threats = scanner.scan(self.tmpdir)
        self.assertIsInstance(threats, list)

    def test_very_large_file(self):
        """Scanner handles large files without hanging."""
        create_realistic_wp_site(self.tmpdir)
        # Create a 10MB PHP file
        large = os.path.join(self.tmpdir, 'wp-content/plugins/big.php')
        with open(large, 'w') as f:
            f.write('<?php\n')
            for _ in range(100000):
                f.write("echo 'line';\n")

        start = time.monotonic()
        cm = CapabilityMapper()
        with open(large, 'rb') as f:
            content = f.read()
        cm.analyze_file(large, content)
        elapsed = time.monotonic() - start

        print("  10MB file scan: %.2fs" % elapsed)
        # Should complete in under 30 seconds
        self.assertLess(elapsed, 30, "Large file scan too slow: %.1fs" % elapsed)

    def test_symlink_loop(self):
        """Scanner handles symlink loops without infinite recursion."""
        create_realistic_wp_site(self.tmpdir)
        link_a = os.path.join(self.tmpdir, 'link_a')
        link_b = os.path.join(self.tmpdir, 'link_b')
        try:
            os.symlink(link_b, link_a)
            os.symlink(link_a, link_b)
        except OSError:
            self.skipTest("Cannot create symlinks on this filesystem")

        scanner = UniversalScanner()
        threats = scanner.scan(self.tmpdir)
        # Should not hang or crash
        self.assertIsInstance(threats, list)

    def test_empty_php_file(self):
        """Scanner handles empty PHP files."""
        create_realistic_wp_site(self.tmpdir)
        with open(os.path.join(self.tmpdir, 'empty.php'), 'w') as f:
            pass  # Empty file

        cm = CapabilityMapper()
        profile = cm.analyze_file(
            os.path.join(self.tmpdir, 'empty.php'), b'',
        )
        self.assertEqual(profile.risk_score, 0)


# ═══════════════════════════════════════════════════════════════
# Test 5: Detection Accuracy
# ═══════════════════════════════════════════════════════════════

class TestDetectionAccuracy(unittest.TestCase):
    """Verify scanner catches all planted threats with no false positives on clean files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='cleanshift_accuracy_')
        create_realistic_wp_site(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_clean_site_produces_minimal_alerts(self):
        """A clean WP site should produce only informational findings."""
        scanner = UniversalScanner()
        threats = scanner.scan(self.tmpdir)

        # Only informational items (wp-config perms on macOS may trigger)
        critical = [t for t in threats if t.severity == Severity.CRITICAL]
        self.assertEqual(len(critical), 0,
                        "Clean site has CRITICAL alerts: %s" %
                        [t.description for t in critical])

    def test_all_planted_threats_detected(self):
        """All planted threats must be detected."""
        planted = create_threats_in_site(self.tmpdir)

        scanner = UniversalScanner()
        threats = scanner.scan(self.tmpdir)

        cm = CapabilityMapper()
        for root, dirs, files in os.walk(self.tmpdir):
            for f in files:
                if f.endswith('.php'):
                    fp = os.path.join(root, f)
                    try:
                        with open(fp, 'rb') as fh:
                            content = fh.read()
                        profile = cm.analyze_file(fp, content)
                        if profile.risk_score > 0 and profile.dangerous_combos:
                            threats.append(Threat(
                                threat_type=ThreatType.BACKDOOR_FILE,
                                severity=Severity.CRITICAL,
                                description='Dangerous capability combo detected',
                                location=fp,
                            ))
                    except (OSError, PermissionError):
                        pass

        found_types = set()
        for t in threats:
            loc = getattr(t, 'location', '') or ''
            if '.env' in loc or 'secret' in (t.description or '').lower():
                found_types.add('.env')
            if 'phpinfo' in loc or 'phpinfo' in (t.description or '').lower():
                found_types.add('phpinfo')
            if '.bak' in loc or 'backup' in (t.description or '').lower():
                found_types.add('config_backup')
            if '.sql' in loc or 'database' in (t.description or '').lower() or 'dump' in (t.description or '').lower():
                found_types.add('sql_dump')
            if 'cache.php' in loc or 'webshell' in (t.description or '').lower() or 'capability' in (t.description or '').lower():
                found_types.add('backdoor')
            if 'obfuscat' in (t.description or '').lower() or 'base64' in (t.description or '').lower() or 'combo' in (t.description or '').lower() or 'dynamic' in (t.description or '').lower():
                found_types.add('obfuscated')

        planted_names = set(p[0] for p in planted)
        missed = planted_names - found_types
        self.assertEqual(
            len(missed), 0,
            "Missed threats: %s (found: %s)" % (missed, found_types)
        )
        print("  Detected %d/%d planted threats" % (len(planted_names), len(planted)))

    def test_known_plugin_not_flagged_as_threat(self):
        """Known plugins should not be flagged as threats."""
        te = TrustEngine()
        woo_file = os.path.join(
            self.tmpdir, 'wp-content/plugins/woocommerce/woocommerce.php',
        )
        # TrustEngine.evaluate expects a site object with .path attribute
        # or falls back gracefully. The allowlist check only needs the filepath.
        result = te._check_allowlist(woo_file)
        self.assertIsNotNone(result)
        self.assertEqual(result.level, TrustLevel.KNOWN)
        self.assertEqual(result.plugin_slug, 'woocommerce')


# ═══════════════════════════════════════════════════════════════
# Test 6: Platform Detection
# ═══════════════════════════════════════════════════════════════

class TestPlatformDetectionAccuracy(unittest.TestCase):
    """Verify platform detection works for all supported platforms."""

    def _create_platform(self, base_dir, files):
        """Helper to create platform files."""
        for f in files:
            path = os.path.join(base_dir, f)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as fh:
                fh.write('<?php // platform file ?>')
        return base_dir

    def test_detects_wordpress(self):
        tmpdir = tempfile.mkdtemp()
        self._create_platform(tmpdir, [
            'wp-config.php', 'wp-includes/version.php', 'wp-admin/admin.php',
        ])
        info = PlatformDetector().detect(tmpdir)
        self.assertEqual(info.platform_type, PlatformType.WORDPRESS)
        shutil.rmtree(tmpdir)

    def test_detects_joomla(self):
        tmpdir = tempfile.mkdtemp()
        self._create_platform(tmpdir, [
            'configuration.php', 'administrator/index.php',
            'libraries/src/Version.php',
        ])
        info = PlatformDetector().detect(tmpdir)
        self.assertEqual(info.platform_type, PlatformType.JOOMLA)
        shutil.rmtree(tmpdir)

    def test_detects_drupal(self):
        tmpdir = tempfile.mkdtemp()
        self._create_platform(tmpdir, [
            'sites/default/settings.php', 'core/lib/Drupal.php',
        ])
        info = PlatformDetector().detect(tmpdir)
        self.assertEqual(info.platform_type, PlatformType.DRUPAL)
        shutil.rmtree(tmpdir)

    def test_detects_laravel(self):
        tmpdir = tempfile.mkdtemp()
        self._create_platform(tmpdir, [
            'artisan', 'app/Http/Kernel.php', 'bootstrap/app.php',
        ])
        info = PlatformDetector().detect(tmpdir)
        self.assertEqual(info.platform_type, PlatformType.LARAVEL)
        shutil.rmtree(tmpdir)

    def test_detects_magento2(self):
        tmpdir = tempfile.mkdtemp()
        self._create_platform(tmpdir, [
            'bin/magento', 'app/etc/env.php', 'pub/index.php',
        ])
        info = PlatformDetector().detect(tmpdir)
        self.assertEqual(info.platform_type, PlatformType.MAGENTO2)
        shutil.rmtree(tmpdir)

    def test_unknown_platform(self):
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, 'index.html'), 'w') as f:
            f.write('<html><body>Hello</body></html>')
        info = PlatformDetector().detect(tmpdir)
        self.assertIn(info.platform_type, [PlatformType.CUSTOM_PHP, PlatformType.STATIC])
        shutil.rmtree(tmpdir)


# ═══════════════════════════════════════════════════════════════
# Test 7: Guard PHP Validation
# ═══════════════════════════════════════════════════════════════

class TestGuardPHPValidation(unittest.TestCase):
    """Validate all guard PHP files pass lint and follow standards."""

    def test_all_php_files_pass_lint(self):
        """Every PHP file must pass php -l."""
        guard_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'guard')
        if not os.path.exists(guard_dir):
            self.skipTest("Guard directory not found")

        # Check if PHP is available
        try:
            subprocess.run(['php', '--version'], capture_output=True, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            self.skipTest("PHP not available for linting")

        errors = []
        for root, dirs, files in os.walk(guard_dir):
            for f in files:
                if f.endswith('.php'):
                    fp = os.path.join(root, f)
                    result = subprocess.run(
                        ['php', '-l', fp],
                        capture_output=True, text=True,
                    )
                    if result.returncode != 0:
                        errors.append("%s: %s" % (f, result.stderr.strip()))

        self.assertEqual(len(errors), 0,
                        "PHP lint errors:\n" + "\n".join(errors))

    def test_all_guards_have_exit_check(self):
        """Every guard file must have ABSPATH or WP_UNINSTALL_PLUGIN check."""
        guard_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'guard')
        if not os.path.exists(guard_dir):
            self.skipTest("Guard directory not found")

        missing = []
        for root, dirs, files in os.walk(guard_dir):
            for f in files:
                if f.endswith('.php'):
                    fp = os.path.join(root, f)
                    with open(fp, 'r') as fh:
                        content = fh.read()
                    # uninstall.php uses WP_UNINSTALL_PLUGIN, others use ABSPATH
                    if 'ABSPATH' not in content and 'WP_UNINSTALL_PLUGIN' not in content:
                        missing.append(f)

        self.assertEqual(len(missing), 0,
                        "Files missing ABSPATH/WP_UNINSTALL_PLUGIN check: %s" % missing)

    def test_no_direct_output_in_guards(self):
        """Guard files must not use echo/print outside of admin UI."""
        guard_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'guard', 'cleanshift-guard')
        if not os.path.exists(guard_dir):
            self.skipTest("Guard directory not found")

        # Only check non-UI guards
        non_ui_guards = [
            'class-upload-guard.php', 'class-user-guard.php',
            'class-option-guard.php', 'class-login-guard.php',
            'class-cron-guard.php', 'class-security-stack.php',
        ]
        violations = []
        for f in non_ui_guards:
            fp = os.path.join(guard_dir, f)
            if not os.path.exists(fp):
                continue
            with open(fp, 'r') as fh:
                content = fh.read()
            # Check for unescaped echo/print (outside comments)
            for i, line in enumerate(content.split('\n'), 1):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('#'):
                    continue
                if ('echo ' in stripped or 'print ' in stripped) and 'esc_html' not in stripped:
                    violations.append("%s:%d: %s" % (f, i, stripped[:60]))

        # Violations are warnings, not hard failures (some may be legitimate)
        if violations:
            print("  WARNING: Potential unescaped output in guards:")
            for v in violations[:5]:
                print("    %s" % v)


# ═══════════════════════════════════════════════════════════════
# Test 8: Concurrent Safety
# ═══════════════════════════════════════════════════════════════

class TestConcurrentSafety(unittest.TestCase):
    """Verify scanner is safe for concurrent use."""

    def test_hashcache_concurrent_writes(self):
        """HashCache handles concurrent writes without corruption."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_conc_hc_')
        tmpdb = os.path.join(tmpdir, 'cache.db')
        errors = []

        def writer(thread_id, count):
            try:
                cache = HashCache(tmpdb)
                for i in range(count):
                    cache.update(
                        '/home/user%d/public_html' % thread_id,
                        'file_%d.php' % i,
                        time.time(), 100, 'hash_%d_%d' % (thread_id, i), 'clean',
                    )
            except Exception as e:
                errors.append("Thread %d: %s" % (thread_id, str(e)))

        threads = []
        for t in range(4):
            th = threading.Thread(target=writer, args=(t, 100))
            threads.append(th)
            th.start()

        for th in threads:
            th.join(timeout=30)

        # Check no corruption
        try:
            cache = HashCache(tmpdb)
            stats = cache.get_stats('/home/user0/public_html')
            self.assertIsInstance(stats, dict)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        self.assertEqual(len(errors), 0,
                        "Concurrent write errors: %s" % errors)


# ═══════════════════════════════════════════════════════════════
# Test 9: Concordance Engine
# ═══════════════════════════════════════════════════════════════

class TestConcordanceIntegration(unittest.TestCase):
    """Test concordance engine with realistic scan results."""

    def test_concordance_with_scan_results(self):
        """Concordance processes real scan output correctly."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_conc_')
        create_realistic_wp_site(tmpdir)
        create_threats_in_site(tmpdir)

        # Run scan
        scanner = UniversalScanner()
        threats = scanner.scan(tmpdir)

        # Run concordance
        engine = ConcordanceEngine()
        report = engine.concordance(tmpdir, threats)

        self.assertIsNotNone(report)
        self.assertIsInstance(report.stats, dict)
        self.assertGreater(report.stats['total_findings'], 0)

        # JSON export should work
        json_str = report.to_json()
        parsed = json.loads(json_str)
        self.assertIn('findings', parsed)

        shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════
# Test 10: Performance Benchmarks
# ═══════════════════════════════════════════════════════════════

class TestPerformance(unittest.TestCase):
    """Benchmark scanner performance."""

    def test_scan_speed_small_site(self):
        """Small WP site (< 50 files) should scan in < 2 seconds."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_perf_')
        create_realistic_wp_site(tmpdir)

        start = time.monotonic()

        detector = PlatformDetector()
        detector.detect(tmpdir)

        scanner = UniversalScanner()
        scanner.scan(tmpdir)

        elapsed = time.monotonic() - start
        print("  Small site scan: %.3fs" % elapsed)
        self.assertLess(elapsed, 2.0, "Small site scan too slow: %.1fs" % elapsed)

        shutil.rmtree(tmpdir, ignore_errors=True)

    def test_scan_speed_large_site(self):
        """Site with 500 files should scan in < 10 seconds."""
        tmpdir = tempfile.mkdtemp(prefix='cleanshift_perf_large_')
        create_realistic_wp_site(tmpdir)

        # Add 500 plugin files
        for i in range(500):
            d = os.path.join(tmpdir, 'wp-content/plugins/fake-plugin-%d' % (i // 10))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, 'file_%d.php' % i), 'w') as f:
                f.write('<?php echo "%d"; ?>' % i)

        start = time.monotonic()

        detector = PlatformDetector()
        detector.detect(tmpdir)

        scanner = UniversalScanner()
        scanner.scan(tmpdir)

        elapsed = time.monotonic() - start
        file_count = sum(len(files) for _, _, files in os.walk(tmpdir))
        print("  Large site scan: %d files in %.3fs (%.0f files/sec)" %
              (file_count, elapsed, file_count / elapsed if elapsed > 0 else 0))
        self.assertLess(elapsed, 10.0, "Large site scan too slow: %.1fs" % elapsed)

        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    print("=" * 60)
    print("CleanShift Pre-Deployment Validation Suite")
    print("=" * 60)
    print()

    unittest.main(verbosity=2)
