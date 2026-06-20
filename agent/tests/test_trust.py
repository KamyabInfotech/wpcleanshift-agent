"""
CleanShift Test Suite — Trust Engine Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the TrustEngine unified trust evaluation pipeline:
  - Verified files (checksum match) are skipped
  - Known-plugin files receive reduced analysis
  - Unknown files receive full analysis
  - Developer-acknowledged files are respected
  - Expired acknowledgments are ignored
  - Modified official files trigger behavioral diff
  - Allowlist contains 30+ plugins
  - .cleanshift-allow file parsing
"""

import datetime
import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.src.models import WordPressSite
from agent.src.trust import (
    KNOWN_PLUGINS,
    TrustEngine,
    TrustLevel,
    TrustResult,
)
from agent.src.verifier import ChecksumVerifier, VerifyResult


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def wp_site(tmp_path):
    """Create a minimal WordPress site structure for trust testing."""
    site_path = tmp_path / "public_html"
    site_path.mkdir()

    # Core directories
    (site_path / "wp-admin").mkdir()
    (site_path / "wp-includes").mkdir()
    (site_path / "wp-content" / "plugins" / "akismet").mkdir(parents=True)
    (site_path / "wp-content" / "plugins" / "custom-plugin").mkdir(parents=True)
    (site_path / "wp-content" / "themes" / "twentytwentyfive").mkdir(parents=True)

    # Version file
    (site_path / "wp-includes" / "version.php").write_text(
        "<?php $wp_version = '6.5.2';"
    )

    # wp-config.php
    (site_path / "wp-config.php").write_text(
        "<?php\n"
        "define('DB_NAME', 'testdb');\n"
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
    )


@pytest.fixture
def mock_verifier():
    """Create a mock ChecksumVerifier."""
    verifier = MagicMock(spec=ChecksumVerifier)
    verifier.verify_file.return_value = VerifyResult.CUSTOM
    return verifier


# ─── TrustLevel Tests ──────────────────────────────────────────────

class TestTrustLevel:
    """Tests for the TrustLevel class."""

    def test_trust_levels_are_strings(self):
        """Trust levels should be string constants."""
        assert TrustLevel.VERIFIED == "verified"
        assert TrustLevel.KNOWN == "known"
        assert TrustLevel.ACKNOWLEDGED == "acknowledged"
        assert TrustLevel.MODIFIED == "modified"
        assert TrustLevel.UNKNOWN == "unknown"


# ─── Verified File Tests ───────────────────────────────────────────

class TestVerifiedFile:
    """Tests for VERIFIED trust level (checksum matches)."""

    def test_verified_file_skipped(self, mock_verifier, wp_site):
        """File matching official checksum should be VERIFIED."""
        mock_verifier.verify_file.return_value = VerifyResult.OFFICIAL

        engine = TrustEngine(checksum_verifier=mock_verifier)

        filepath = os.path.join(wp_site.path, "wp-includes", "load.php")
        # Create the file so it exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text("<?php // official code")

        result = engine.evaluate(filepath, wp_site)

        assert result.level == TrustLevel.VERIFIED
        assert "official" in result.reason.lower()

    def test_modified_official_file_flagged(self, mock_verifier, wp_site):
        """Modified official file should be MODIFIED."""
        mock_verifier.verify_file.return_value = VerifyResult.MODIFIED

        engine = TrustEngine(checksum_verifier=mock_verifier)

        filepath = os.path.join(wp_site.path, "wp-includes", "load.php")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text("<?php // tampered code")

        result = engine.evaluate(filepath, wp_site)

        assert result.level == TrustLevel.MODIFIED
        assert "modified" in result.reason.lower()

    def test_no_verifier_returns_none_for_checksum(self, wp_site):
        """Without verifier, checksum step should be skipped gracefully."""
        engine = TrustEngine(checksum_verifier=None)
        # Force _verifier to None
        engine._verifier = None

        filepath = os.path.join(wp_site.path, "wp-includes", "load.php")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text("<?php // code")

        result = engine.evaluate(filepath, wp_site)

        # Should fall through to UNKNOWN since it's not in allowlist
        assert result.level == TrustLevel.UNKNOWN


# ─── Known Plugin Tests ────────────────────────────────────────────

class TestKnownPluginReducedAnalysis:
    """Tests for KNOWN trust level (in allowlist)."""

    def test_known_plugin_reduced_analysis(self, mock_verifier, wp_site):
        """File from a known plugin should be KNOWN with allowed capabilities."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        filepath = os.path.join(
            wp_site.path, "wp-content", "plugins", "akismet", "akismet.php",
        )
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text("<?php // Akismet")

        result = engine.evaluate(filepath, wp_site)

        assert result.level == TrustLevel.KNOWN
        assert result.plugin_slug == "akismet"
        assert "makes_http_calls" in result.allowed_capabilities
        assert "reads_http_input" in result.allowed_capabilities
        assert "accesses_database" in result.allowed_capabilities

    def test_unknown_plugin_not_matched(self, mock_verifier, wp_site):
        """File from an unknown plugin should NOT be KNOWN."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        filepath = os.path.join(
            wp_site.path, "wp-content", "plugins", "custom-plugin", "main.php",
        )
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        Path(filepath).write_text("<?php // Custom")

        result = engine.evaluate(filepath, wp_site)

        assert result.level == TrustLevel.UNKNOWN

    def test_known_plugin_case_insensitive(self, mock_verifier, wp_site):
        """Plugin slug matching should be case-insensitive."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        # WooCommerce in a dir with mixed case
        plugin_dir = Path(wp_site.path) / "wp-content" / "plugins" / "WooCommerce"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        filepath = str(plugin_dir / "woocommerce.php")
        Path(filepath).write_text("<?php // WooCommerce")

        result = engine.evaluate(filepath, wp_site)

        # lowercase 'woocommerce' is in the allowlist
        assert result.level == TrustLevel.KNOWN
        assert result.plugin_slug == "woocommerce"


# ─── Unknown File Tests ────────────────────────────────────────────

class TestUnknownFileFullAnalysis:
    """Tests for UNKNOWN trust level (no trust established)."""

    def test_unknown_file_full_analysis(self, mock_verifier, wp_site):
        """File not matching any trust mechanism should be UNKNOWN."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        # Root-level PHP file
        filepath = os.path.join(wp_site.path, "suspicious.php")
        Path(filepath).write_text("<?php system($_GET['cmd']); ?>")

        result = engine.evaluate(filepath, wp_site)

        assert result.level == TrustLevel.UNKNOWN
        assert len(result.allowed_capabilities) == 0

    def test_file_outside_site_root(self, mock_verifier, wp_site, tmp_path):
        """File outside the site root should be UNKNOWN."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        # Create file outside site root
        filepath = str(tmp_path / "outside.php")
        Path(filepath).write_text("<?php echo 'outside';")

        result = engine.evaluate(filepath, wp_site)

        assert result.level == TrustLevel.UNKNOWN


# ─── Acknowledged File Tests ───────────────────────────────────────

class TestAcknowledgedFile:
    """Tests for ACKNOWLEDGED trust level (developer .cleanshift-allow)."""

    def test_acknowledged_file_skipped(self, mock_verifier, wp_site):
        """File covered by .cleanshift-allow should be ACKNOWLEDGED."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        plugin_dir = Path(wp_site.path) / "wp-content" / "plugins" / "custom-plugin"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        # Create the target file
        target_file = plugin_dir / "gateway.php"
        target_file.write_text("<?php // Custom payment gateway")
        sha256 = hashlib.sha256(b"<?php // Custom payment gateway").hexdigest()

        # Create .cleanshift-allow
        allow_content = (
            "# Custom plugin acknowledgment\n"
            "acknowledged_by: developer@example.com\n"
            "acknowledged_date: '2026-06-07'\n"
            "reason: Custom payment gateway integration\n"
            "expires: '2027-06-07'\n"
            "file_hashes:\n"
            "  gateway.php: %s\n" % sha256
        )
        (plugin_dir / ".cleanshift-allow").write_text(allow_content)

        result = engine.evaluate(str(target_file), wp_site)

        assert result.level == TrustLevel.ACKNOWLEDGED
        assert "developer@example.com" in result.reason

    def test_acknowledgment_expired(self, mock_verifier, wp_site):
        """Expired .cleanshift-allow should NOT grant ACKNOWLEDGED."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        plugin_dir = Path(wp_site.path) / "wp-content" / "plugins" / "custom-plugin"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        target_file = plugin_dir / "old-file.php"
        target_file.write_text("<?php // Old acknowledged code")
        sha256 = hashlib.sha256(b"<?php // Old acknowledged code").hexdigest()

        # Create .cleanshift-allow with past expiry
        allow_content = (
            "acknowledged_by: developer@example.com\n"
            "acknowledged_date: '2024-01-01'\n"
            "reason: Temporary override\n"
            "expires: '2024-12-31'\n"
            "file_hashes:\n"
            "  old-file.php: %s\n" % sha256
        )
        (plugin_dir / ".cleanshift-allow").write_text(allow_content)

        result = engine.evaluate(str(target_file), wp_site)

        # Should NOT be ACKNOWLEDGED since it expired
        assert result.level != TrustLevel.ACKNOWLEDGED
        assert result.level == TrustLevel.UNKNOWN

    def test_acknowledgment_hash_mismatch(self, mock_verifier, wp_site):
        """File with wrong hash should NOT be ACKNOWLEDGED."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        plugin_dir = Path(wp_site.path) / "wp-content" / "plugins" / "custom-plugin"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        target_file = plugin_dir / "modified.php"
        target_file.write_text("<?php // Modified content (different from hash)")

        # .cleanshift-allow with wrong hash
        allow_content = (
            "acknowledged_by: dev@example.com\n"
            "reason: Original code\n"
            "expires: '2027-06-07'\n"
            "file_hashes:\n"
            "  modified.php: 0000000000000000000000000000000000000000000000000000000000000000\n"
        )
        (plugin_dir / ".cleanshift-allow").write_text(allow_content)

        result = engine.evaluate(str(target_file), wp_site)

        # Hash doesn't match -> should NOT be ACKNOWLEDGED
        assert result.level != TrustLevel.ACKNOWLEDGED

    def test_acknowledgment_no_expiry(self, mock_verifier, wp_site):
        """Allow file without expiry should still work."""
        engine = TrustEngine(checksum_verifier=mock_verifier)

        plugin_dir = Path(wp_site.path) / "wp-content" / "plugins" / "custom-plugin"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        target_file = plugin_dir / "permanent.php"
        target_file.write_text("<?php // Permanent acknowledgment")

        # No expiry, no file_hashes -> covers all files
        allow_content = (
            "acknowledged_by: admin@example.com\n"
            "reason: Permanent custom code\n"
        )
        (plugin_dir / ".cleanshift-allow").write_text(allow_content)

        result = engine.evaluate(str(target_file), wp_site)

        assert result.level == TrustLevel.ACKNOWLEDGED


# ─── Modified Official Behavioral Diff Tests ───────────────────────

class TestBehavioralDiff:
    """Tests for behavioral_diff method on MODIFIED files."""

    def test_modified_official_behavioral_diff(self):
        """behavioral_diff should only return NEW capabilities."""
        engine = TrustEngine(checksum_verifier=None)
        engine._verifier = None

        original_caps = ["makes_http_calls", "reads_http_input"]
        current_caps = [
            "makes_http_calls", "reads_http_input",
            "process_execution",  # NEW
            "creates_users",      # NEW
        ]

        new_caps = engine.behavioral_diff(
            "/fake/path.php", original_caps, current_caps,
        )

        assert "process_execution" in new_caps
        assert "creates_users" in new_caps
        assert "makes_http_calls" not in new_caps
        assert "reads_http_input" not in new_caps
        assert len(new_caps) == 2

    def test_behavioral_diff_no_changes(self):
        """behavioral_diff with same caps should return empty list."""
        engine = TrustEngine(checksum_verifier=None)
        engine._verifier = None

        caps = ["makes_http_calls", "reads_http_input"]

        new_caps = engine.behavioral_diff("/fake/path.php", caps, caps)

        assert new_caps == []

    def test_behavioral_diff_empty_original(self):
        """behavioral_diff with empty original should return all current."""
        engine = TrustEngine(checksum_verifier=None)
        engine._verifier = None

        current_caps = ["makes_http_calls", "process_execution"]

        new_caps = engine.behavioral_diff("/fake/path.php", [], current_caps)

        assert len(new_caps) == 2
        assert "makes_http_calls" in new_caps
        assert "process_execution" in new_caps


# ─── Allowlist Tests ───────────────────────────────────────────────

class TestAllowlist:
    """Tests for the KNOWN_PLUGINS allowlist."""

    def test_allowlist_has_30_plus_plugins(self):
        """KNOWN_PLUGINS should contain at least 30 entries."""
        assert len(KNOWN_PLUGINS) >= 30, (
            "Expected 30+ known plugins, got %d" % len(KNOWN_PLUGINS)
        )

    def test_all_plugins_have_allowed_capabilities(self):
        """Every plugin entry should have an allowed_capabilities list."""
        for slug, info in KNOWN_PLUGINS.items():
            assert "allowed_capabilities" in info, (
                "Plugin %s missing allowed_capabilities" % slug
            )
            assert isinstance(info["allowed_capabilities"], list), (
                "Plugin %s allowed_capabilities should be a list" % slug
            )

    def test_known_security_plugins_have_capabilities(self):
        """Security plugins should have appropriate capabilities."""
        security_plugins = ["wordfence", "sucuri-scanner", "ithemes-security"]
        for slug in security_plugins:
            assert slug in KNOWN_PLUGINS, "%s should be in allowlist" % slug
            caps = KNOWN_PLUGINS[slug]["allowed_capabilities"]
            assert len(caps) >= 3, (
                "%s should have 3+ capabilities, got %d" % (slug, len(caps))
            )


# ─── Allow-file Parsing Tests ──────────────────────────────────────

class TestAllowFileParsing:
    """Tests for .cleanshift-allow file parsing."""

    def test_allowlist_file_parsing_basic(self):
        """Parser should handle basic key: value pairs."""
        content = (
            "acknowledged_by: developer@example.com\n"
            "acknowledged_date: '2026-06-07'\n"
            "reason: Custom integration\n"
        )
        result = TrustEngine._parse_simple_yaml(content)

        assert result["acknowledged_by"] == "developer@example.com"
        assert result["acknowledged_date"] == "2026-06-07"
        assert result["reason"] == "Custom integration"

    def test_allowlist_file_parsing_with_hashes(self):
        """Parser should handle file_hashes section."""
        content = (
            "acknowledged_by: dev@example.com\n"
            "reason: Gateway code\n"
            "file_hashes:\n"
            "  includes/gateway.php: abc123def456\n"
            "  includes/api.php: 789xyz000111\n"
        )
        result = TrustEngine._parse_simple_yaml(content)

        assert result["acknowledged_by"] == "dev@example.com"
        assert "file_hashes" in result
        assert result["file_hashes"]["includes/gateway.php"] == "abc123def456"
        assert result["file_hashes"]["includes/api.php"] == "789xyz000111"

    def test_allowlist_file_parsing_with_comments(self):
        """Parser should ignore comment lines."""
        content = (
            "# This is a comment\n"
            "acknowledged_by: admin@site.com\n"
            "# Another comment\n"
            "reason: Testing\n"
        )
        result = TrustEngine._parse_simple_yaml(content)

        assert result["acknowledged_by"] == "admin@site.com"
        assert result["reason"] == "Testing"

    def test_allowlist_file_parsing_empty_content(self):
        """Parser should handle empty content gracefully."""
        result = TrustEngine._parse_simple_yaml("")
        assert result == {}

    def test_allowlist_file_parsing_with_expiry(self):
        """Parser should extract expires field."""
        content = (
            "acknowledged_by: dev@example.com\n"
            "expires: '2027-06-07'\n"
            "reason: Temporary\n"
        )
        result = TrustEngine._parse_simple_yaml(content)

        assert result["expires"] == "2027-06-07"


# ─── TrustResult Tests ─────────────────────────────────────────────

class TestTrustResult:
    """Tests for the TrustResult data class."""

    def test_default_trust_result(self):
        """Default TrustResult should be UNKNOWN with empty fields."""
        result = TrustResult()
        assert result.level == "unknown"
        assert result.reason == ""
        assert result.allowed_capabilities == []
        assert result.plugin_slug == ""

    def test_trust_result_repr(self):
        """TrustResult repr should be readable."""
        result = TrustResult(
            level=TrustLevel.KNOWN,
            reason="Known plugin",
            plugin_slug="akismet",
        )
        r = repr(result)
        assert "known" in r
        assert "akismet" in r


# ─── Edge Cases ─────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge case tests for TrustEngine."""

    def test_evaluate_handles_exceptions(self, wp_site):
        """evaluate() should never raise, returning UNKNOWN on error."""
        engine = TrustEngine(checksum_verifier=None)
        engine._verifier = None

        # Non-existent file
        result = engine.evaluate("/nonexistent/path.php", wp_site)
        assert result.level == TrustLevel.UNKNOWN

    def test_extract_plugin_slug(self):
        """extract_plugin_slug should correctly parse paths."""
        assert TrustEngine.extract_plugin_slug(
            "/var/www/html/wp-content/plugins/akismet/akismet.php"
        ) == "akismet"

        assert TrustEngine.extract_plugin_slug(
            "/var/www/html/wp-content/themes/twentytwentyfive/style.css"
        ) == "twentytwentyfive"

        assert TrustEngine.extract_plugin_slug(
            "/var/www/html/index.php"
        ) == ""

    def test_trust_engine_with_custom_allowlist(self, mock_verifier, wp_site):
        """TrustEngine should accept custom known_plugins dict."""
        custom = {
            "my-plugin": {
                "allowed_capabilities": ["reads_http_input"],
            },
        }
        engine = TrustEngine(
            checksum_verifier=mock_verifier,
            known_plugins=custom,
        )

        plugin_dir = Path(wp_site.path) / "wp-content" / "plugins" / "my-plugin"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        filepath = str(plugin_dir / "main.php")
        Path(filepath).write_text("<?php // custom plugin")

        result = engine.evaluate(filepath, wp_site)
        assert result.level == TrustLevel.KNOWN
        assert result.plugin_slug == "my-plugin"
        assert result.allowed_capabilities == ["reads_http_input"]

        # akismet should NOT be known with custom allowlist
        akismet_dir = Path(wp_site.path) / "wp-content" / "plugins" / "akismet"
        akismet_dir.mkdir(parents=True, exist_ok=True)
        akismet_file = str(akismet_dir / "akismet.php")
        Path(akismet_file).write_text("<?php // akismet")

        result2 = engine.evaluate(akismet_file, wp_site)
        assert result2.level == TrustLevel.UNKNOWN
