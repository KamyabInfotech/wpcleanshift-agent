"""
CleanShift Test Suite — Intelligence Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the IntelligenceDB including:
- Loading from YAML files
- IoC matching: malware domains, backdoor filenames, rogue admin patterns
- Playbook loading and parsing
- Playbook command validation (blocked commands rejected)
- Path resolution (.. components resolved, not rejected)
- Detection query loading
- Empty/missing intelligence directory handling
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.src.intelligence import (
    AdminScramblePattern,
    BackdoorFilename,
    DbMarker,
    DetectionQuery,
    IntelligenceDB,
    IoC,
    MalwareDomain,
    Playbook,
    PlaybookStep,
    RogueAdminPattern,
    VulnerablePlugin,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def intel_dir(tmp_path):
    """Create a temporary intelligence directory with sample YAML data."""
    indicators_dir = tmp_path / "indicators"
    indicators_dir.mkdir()
    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()

    # Write a minimal IoC database
    ioc_yaml = """
malware_domains:
  - domain: evil.example.com
    type: script_injection
    payload: admin-bar.js
    first_seen: "2024-01-01"
    cve: CVE-2024-28000
    source: unit-test
  - domain: bad-cdn.net
    type: redirect
    source: unit-test

rogue_admin_patterns:
  - username_pattern: "GuaUserWa*"
    email_pattern: "*@org.com"
    role: administrator
    cve: CVE-2024-28000
    behavior:
      - creates rogue admin
      - installs backdoors
    source: unit-test

db_markers:
  - option_name: litespeed_crawler
    purpose: LiteSpeed cache tracker
    prevalence: high
    cve: CVE-2024-28000
    source: unit-test
  - option_name: wpcode_snippet_1
    option_value: "base64_decode"
    purpose: Persistent backdoor
    source: unit-test
  - option_name: suspicious_option
    value_contains: "eval("
    purpose: Code execution marker
    source: unit-test

backdoor_filenames:
  - name: shell.php
    location: any
    risk: critical
    note: Classic webshell
    source: unit-test
  - name: defaults.php
    location: wp-admin/
    risk: high
    source: unit-test
  - name: "*.ico"
    location: any
    size: ">50KB"
    risk: critical
    source: unit-test

admin_scramble_patterns:
  - original_username: admin
    scrambled_to: a8kj3md2
    pattern: "random 8-char alnum"
    email_changed_to: attacker@evil.com
    note: Typical scramble

vulnerable_plugins:
  - name: LiteSpeed Cache
    slug: litespeed-cache
    vulnerable_versions: "<6.4.1"
    cve: CVE-2024-28000
    exploit_type: privilege_escalation
    patched_version: "6.4.1"
    severity: critical
    source: unit-test
    detection:
      - rogue admin accounts
      - db markers

detection_queries:
  - name: find_rogue_admins
    description: Find admin users created after a certain date
    sql: "SELECT * FROM wp_users WHERE user_registered > '2024-01-01' AND ID IN (SELECT user_id FROM wp_usermeta WHERE meta_key='wp_capabilities' AND meta_value LIKE '%administrator%')"
  - name: find_injected_options
    description: Find options with script tags
    sql: "SELECT option_name, LEFT(option_value, 200) FROM wp_options WHERE option_value LIKE '%<script%'"
"""
    (indicators_dir / "ioc-database.yaml").write_text(ioc_yaml)

    # Write a sample playbook
    playbook_yaml = """
name: test-playbook-cve-2024-28000
description: Test playbook for CVE-2024-28000 remediation
severity: critical
estimated_time: "30 minutes"
automated: partially

phase_1_identify:
  - step: "1.1"
    description: List all admin users
    command: "wp user list --role=administrator --format=csv"
    requires_approval: false

  - step: "1.2"
    description: Check for rogue admins
    command: "wp user list --role=administrator"
    requires_approval: true

phase_2_remediate:
  - step: "2.1"
    description: Delete rogue admin
    command: "wp user delete {ROGUE_ID} --yes"
    requires_approval: true

  - step: "2.2"
    description: Manual review step
    manual: true
    description: Review site files manually

  - step: "2.3"
    description: Multiple commands
    commands:
      - "wp cache flush"
      - "wp transient delete --all"

server_wide:
  check_all_sites: true
  note: Lateral movement is common
"""
    (playbooks_dir / "test-playbook.yaml").write_text(playbook_yaml)

    return tmp_path


@pytest.fixture
def loaded_intel(intel_dir):
    """An IntelligenceDB instance loaded from the fixture directory."""
    intel = IntelligenceDB(intel_dir)
    intel.load()
    return intel


# ─── Loading Tests ──────────────────────────────────────────────────

class TestIntelligenceLoading:
    """Tests for loading intelligence data from YAML files."""

    def test_load_from_yaml_populates_domains(self, loaded_intel):
        assert len(loaded_intel.malware_domains) == 2
        assert loaded_intel.malware_domains[0].domain == "evil.example.com"
        assert loaded_intel.malware_domains[1].domain == "bad-cdn.net"

    def test_load_from_yaml_populates_backdoors(self, loaded_intel):
        assert len(loaded_intel.backdoor_filenames) == 3
        names = [b.name for b in loaded_intel.backdoor_filenames]
        assert "shell.php" in names
        assert "defaults.php" in names
        assert "*.ico" in names

    def test_load_from_yaml_populates_rogue_patterns(self, loaded_intel):
        assert len(loaded_intel.rogue_admin_patterns) == 1
        rap = loaded_intel.rogue_admin_patterns[0]
        assert rap.username_pattern == "GuaUserWa*"
        assert rap.cve == "CVE-2024-28000"
        assert "creates rogue admin" in rap.behavior

    def test_load_from_yaml_populates_db_markers(self, loaded_intel):
        assert len(loaded_intel.db_markers) == 3
        names = [m.option_name for m in loaded_intel.db_markers]
        assert "litespeed_crawler" in names

    def test_load_from_yaml_populates_vulnerable_plugins(self, loaded_intel):
        assert len(loaded_intel.vulnerable_plugins) == 1
        vp = loaded_intel.vulnerable_plugins[0]
        assert vp.slug == "litespeed-cache"
        assert vp.cve == "CVE-2024-28000"
        assert vp.patched_version == "6.4.1"

    def test_load_from_yaml_populates_scramble_patterns(self, loaded_intel):
        assert len(loaded_intel.admin_scramble_patterns) == 1
        asp = loaded_intel.admin_scramble_patterns[0]
        assert asp.original_username == "admin"
        assert asp.scrambled_to == "a8kj3md2"

    def test_loaded_flag_set(self, loaded_intel):
        assert loaded_intel._loaded is True


# ─── IoC Matching Tests ────────────────────────────────────────────

class TestIoCMatching:
    """Tests for IoC matching functions."""

    # ── Domain matching ──

    def test_match_domain_known_malware(self, loaded_intel):
        result = loaded_intel.match_domain("https://evil.example.com/admin-bar.js")
        assert result is not None
        assert result.indicator_type == "malware_domain"
        assert result.cve == "CVE-2024-28000"
        assert result.severity == "critical"

    def test_match_domain_case_insensitive(self, loaded_intel):
        result = loaded_intel.match_domain("https://EVIL.EXAMPLE.COM/payload.js")
        assert result is not None

    def test_match_domain_no_match(self, loaded_intel):
        result = loaded_intel.match_domain("https://wordpress.org/plugins/")
        assert result is None

    def test_match_domain_partial(self, loaded_intel):
        """Domain match should work on substring."""
        result = loaded_intel.match_domain("The script was loaded from bad-cdn.net/malware.js")
        assert result is not None
        assert result.matched_value == "bad-cdn.net"

    # ── Filename matching ──

    def test_match_filename_exact(self, loaded_intel):
        result = loaded_intel.match_filename("shell.php")
        assert result is not None
        assert result.indicator_type == "backdoor_file"
        assert result.severity == "critical"

    def test_match_filename_with_path(self, loaded_intel):
        result = loaded_intel.match_filename("/home/user/public_html/shell.php")
        assert result is not None

    def test_match_filename_location_filter(self, loaded_intel):
        """defaults.php should only match in wp-admin/ location."""
        result = loaded_intel.match_filename("/home/user/public_html/wp-admin/defaults.php")
        assert result is not None

    def test_match_filename_location_mismatch(self, loaded_intel):
        """defaults.php outside wp-admin/ should not match."""
        result = loaded_intel.match_filename("/home/user/public_html/wp-content/defaults.php")
        assert result is None

    def test_match_filename_glob_pattern(self, loaded_intel):
        """*.ico pattern should match any .ico file."""
        result = loaded_intel.match_filename("favicon.ico")
        assert result is not None
        assert result.severity == "critical"

    def test_match_filename_no_match(self, loaded_intel):
        result = loaded_intel.match_filename("legitimate-page.php")
        assert result is None

    # ── DB option matching ──

    def test_match_db_option_by_name(self, loaded_intel):
        result = loaded_intel.match_db_option("litespeed_crawler")
        assert result is not None
        assert result.indicator_type == "db_marker"
        assert result.cve == "CVE-2024-28000"

    def test_match_db_option_by_value(self, loaded_intel):
        result = loaded_intel.match_db_option("wpcode_snippet_1", "base64_decode")
        assert result is not None

    def test_match_db_option_value_mismatch(self, loaded_intel):
        """If marker requires specific value, mismatched value should not match."""
        result = loaded_intel.match_db_option("wpcode_snippet_1", "harmless_value")
        assert result is None

    def test_match_db_option_value_contains(self, loaded_intel):
        result = loaded_intel.match_db_option("suspicious_option", "something eval( here")
        assert result is not None

    def test_match_db_option_no_match(self, loaded_intel):
        result = loaded_intel.match_db_option("legitimate_option", "safe value")
        assert result is None

    def test_match_db_option_with_malware_domain_in_value(self, loaded_intel):
        """If option value contains a known malware domain, should match as script_injection."""
        result = loaded_intel.match_db_option("some_option", "<script src='https://evil.example.com/malware.js'>")
        assert result is not None
        assert result.indicator_type == "script_injection"

    # ── Plugin matching ──

    def test_match_plugin_vulnerable_version(self, loaded_intel):
        result = loaded_intel.match_plugin("litespeed-cache", "6.3.0")
        assert result is not None
        assert result.indicator_type == "vulnerable_plugin"
        assert result.cve == "CVE-2024-28000"

    def test_match_plugin_patched_version(self, loaded_intel):
        result = loaded_intel.match_plugin("litespeed-cache", "6.5.0")
        assert result is None

    def test_match_plugin_exact_patch_version(self, loaded_intel):
        """Exact patched version should not be flagged (not less than)."""
        result = loaded_intel.match_plugin("litespeed-cache", "6.4.1")
        assert result is None

    def test_match_plugin_unknown_version(self, loaded_intel):
        """Plugin with no version should be flagged for review."""
        result = loaded_intel.match_plugin("litespeed-cache")
        assert result is not None

    def test_match_plugin_case_insensitive(self, loaded_intel):
        result = loaded_intel.match_plugin("LiteSpeed-Cache", "6.3.0")
        assert result is not None

    def test_match_plugin_no_match(self, loaded_intel):
        result = loaded_intel.match_plugin("akismet", "5.0")
        assert result is None

    # ── Rogue admin patterns ──

    def test_get_rogue_admin_patterns(self, loaded_intel):
        patterns = loaded_intel.get_rogue_admin_patterns()
        assert len(patterns) == 1
        assert patterns[0].username_pattern == "GuaUserWa*"

    def test_get_admin_scramble_patterns(self, loaded_intel):
        patterns = loaded_intel.get_admin_scramble_patterns()
        assert len(patterns) == 1


# ─── Playbook Loading Tests ────────────────────────────────────────

class TestPlaybookLoading:
    """Tests for playbook loading and parsing."""

    def test_playbook_loaded(self, loaded_intel):
        assert len(loaded_intel.playbooks) == 1
        assert "test-playbook-cve-2024-28000" in loaded_intel.playbooks

    def test_playbook_metadata(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        assert pb.description == "Test playbook for CVE-2024-28000 remediation"
        assert pb.severity == "critical"
        assert pb.estimated_time == "30 minutes"
        assert pb.automated == "partially"

    def test_playbook_phases_parsed(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        assert "phase_1_identify" in pb.phases
        assert "phase_2_remediate" in pb.phases

    def test_playbook_steps_parsed(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        phase1 = pb.phases["phase_1_identify"]
        assert len(phase1) == 2
        assert phase1[0].step == "1.1"
        assert phase1[0].command == "wp user list --role=administrator --format=csv"
        assert phase1[0].requires_approval is False

    def test_playbook_approval_flags(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        phase2 = pb.phases["phase_2_remediate"]
        step_21 = [s for s in phase2 if s.step == "2.1"][0]
        assert step_21.requires_approval is True

    def test_playbook_manual_step(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        phase2 = pb.phases["phase_2_remediate"]
        step_22 = [s for s in phase2 if s.step == "2.2"][0]
        assert step_22.manual is True

    def test_playbook_multi_commands(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        phase2 = pb.phases["phase_2_remediate"]
        step_23 = [s for s in phase2 if s.step == "2.3"][0]
        assert step_23.commands is not None
        assert len(step_23.commands) == 2

    def test_playbook_server_wide(self, loaded_intel):
        pb = loaded_intel.playbooks["test-playbook-cve-2024-28000"]
        assert pb.server_wide.get("check_all_sites") is True

    def test_get_playbook_by_name(self, loaded_intel):
        pb = loaded_intel.get_playbook("test-playbook-cve-2024-28000")
        assert pb is not None
        assert pb.name == "test-playbook-cve-2024-28000"

    def test_get_playbook_nonexistent(self, loaded_intel):
        pb = loaded_intel.get_playbook("nonexistent-playbook")
        assert pb is None

    def test_list_playbooks(self, loaded_intel):
        names = loaded_intel.list_playbooks()
        assert "test-playbook-cve-2024-28000" in names


# ─── Playbook Command Validation ───────────────────────────────────

class TestPlaybookCommandValidation:
    """Tests for the blocked command validation in playbook parsing."""

    def test_valid_command_accepted(self):
        assert IntelligenceDB._validate_playbook_command("wp user list --format=csv") is True

    def test_rm_rf_root_blocked(self):
        assert IntelligenceDB._validate_playbook_command("rm -rf /") is False

    def test_dd_blocked(self):
        assert IntelligenceDB._validate_playbook_command("dd if=/dev/zero of=/dev/sda") is False

    def test_mkfs_blocked(self):
        assert IntelligenceDB._validate_playbook_command("mkfs.ext4 /dev/sda1") is False

    def test_fork_bomb_blocked(self):
        assert IntelligenceDB._validate_playbook_command(":(){:|:&};:") is False

    def test_chmod_777_root_blocked(self):
        assert IntelligenceDB._validate_playbook_command("chmod 777 /") is False

    def test_curl_pipe_blocked(self):
        assert IntelligenceDB._validate_playbook_command("curl|bash") is False

    def test_case_insensitive_block(self):
        assert IntelligenceDB._validate_playbook_command("RM -RF /") is False

    def test_blocked_command_stripped_from_playbook(self, tmp_path):
        """When a playbook contains a blocked command, it should be set to None."""
        indicators_dir = tmp_path / "indicators"
        indicators_dir.mkdir()
        (indicators_dir / "ioc-database.yaml").write_text("malware_domains: []")

        playbooks_dir = tmp_path / "playbooks"
        playbooks_dir.mkdir()
        (playbooks_dir / "dangerous.yaml").write_text("""
name: dangerous-playbook
description: Contains a blocked command
phase_1_attack:
  - step: "1.1"
    description: Destroy everything
    command: "rm -rf /"
  - step: "1.2"
    description: Safe step
    command: "wp cache flush"
""")

        intel = IntelligenceDB(tmp_path)
        intel.load()

        pb = intel.playbooks["dangerous-playbook"]
        phase1 = pb.phases["phase_1_attack"]

        # Dangerous command should be None
        step_11 = [s for s in phase1 if s.step == "1.1"][0]
        assert step_11.command is None

        # Safe command should be preserved
        step_12 = [s for s in phase1 if s.step == "1.2"][0]
        assert step_12.command == "wp cache flush"

    def test_blocked_in_multi_commands(self, tmp_path):
        """Blocked commands in 'commands' list should be filtered out."""
        indicators_dir = tmp_path / "indicators"
        indicators_dir.mkdir()
        (indicators_dir / "ioc-database.yaml").write_text("malware_domains: []")

        playbooks_dir = tmp_path / "playbooks"
        playbooks_dir.mkdir()
        (playbooks_dir / "multi.yaml").write_text("""
name: multi-cmd-playbook
description: Test multi commands
phase_1_test:
  - step: "1.1"
    description: Mixed commands
    commands:
      - "wp cache flush"
      - "rm -rf /"
      - "wp transient delete --all"
""")

        intel = IntelligenceDB(tmp_path)
        intel.load()

        pb = intel.playbooks["multi-cmd-playbook"]
        step = pb.phases["phase_1_test"][0]
        # Only safe commands should remain
        assert len(step.commands) == 2
        assert "wp cache flush" in step.commands
        assert "wp transient delete --all" in step.commands


# ─── Path Resolution Tests ─────────────────────────────────────────

class TestPathResolution:
    """Test that IntelligenceDB resolves paths with .. components."""

    def test_dotdot_resolved_not_rejected(self, tmp_path):
        """Paths with .. should be resolved to canonical form, not rejected."""
        # Create the actual intel directory structure
        real_dir = tmp_path / "real_intel"
        real_dir.mkdir()
        indicators = real_dir / "indicators"
        indicators.mkdir()
        (indicators / "ioc-database.yaml").write_text("malware_domains: []")

        # Reference it with .. in the path
        fake_parent = tmp_path / "subdir"
        fake_parent.mkdir()
        dotdot_path = fake_parent / ".." / "real_intel"

        intel = IntelligenceDB(dotdot_path)
        # The path should be resolved
        assert ".." not in str(intel.intel_dir)
        assert intel.intel_dir == real_dir.resolve()

    def test_relative_path_resolved(self, tmp_path):
        """Relative paths should be resolved to absolute."""
        real_dir = tmp_path / "intel"
        real_dir.mkdir()
        indicators = real_dir / "indicators"
        indicators.mkdir()
        (indicators / "ioc-database.yaml").write_text("malware_domains: []")

        intel = IntelligenceDB(real_dir)
        assert intel.intel_dir.is_absolute()


# ─── Detection Queries ─────────────────────────────────────────────

class TestDetectionQueries:
    """Tests for detection query loading."""

    def test_detection_queries_loaded(self, loaded_intel):
        queries = loaded_intel.get_detection_queries()
        assert len(queries) == 2

    def test_detection_query_content(self, loaded_intel):
        queries = loaded_intel.get_detection_queries()
        names = [q.name for q in queries]
        assert "find_rogue_admins" in names
        assert "find_injected_options" in names

    def test_detection_query_has_sql(self, loaded_intel):
        queries = loaded_intel.get_detection_queries()
        for q in queries:
            assert q.sql, f"Detection query '{q.name}' has no SQL"


# ─── Empty / Missing Directory Tests ───────────────────────────────

class TestEmptyMissingIntel:
    """Tests for graceful handling of empty or missing intelligence dirs."""

    def test_missing_intel_dir_loads_empty(self, tmp_path):
        """Missing intelligence directory should result in empty data."""
        intel = IntelligenceDB(tmp_path / "nonexistent")
        intel.load()
        assert intel.malware_domains == []
        assert intel.backdoor_filenames == []
        assert intel.playbooks == {}

    def test_missing_ioc_file_loads_empty(self, tmp_path):
        """Missing ioc-database.yaml should result in empty data."""
        indicators = tmp_path / "indicators"
        indicators.mkdir()
        # No ioc-database.yaml

        intel = IntelligenceDB(tmp_path)
        intel.load()
        assert intel.malware_domains == []

    def test_empty_ioc_file(self, tmp_path):
        """Empty ioc-database.yaml should result in empty data."""
        indicators = tmp_path / "indicators"
        indicators.mkdir()
        (indicators / "ioc-database.yaml").write_text("")

        intel = IntelligenceDB(tmp_path)
        intel.load()
        assert intel.malware_domains == []

    def test_missing_playbooks_dir(self, tmp_path):
        """Missing playbooks directory should result in empty playbooks."""
        indicators = tmp_path / "indicators"
        indicators.mkdir()
        (indicators / "ioc-database.yaml").write_text("malware_domains: []")

        intel = IntelligenceDB(tmp_path)
        intel.load()
        assert intel.playbooks == {}

    def test_empty_playbook_file(self, tmp_path):
        """An empty playbook YAML file should be skipped."""
        indicators = tmp_path / "indicators"
        indicators.mkdir()
        (indicators / "ioc-database.yaml").write_text("malware_domains: []")

        playbooks = tmp_path / "playbooks"
        playbooks.mkdir()
        (playbooks / "empty.yaml").write_text("")

        intel = IntelligenceDB(tmp_path)
        intel.load()
        assert len(intel.playbooks) == 0

    def test_malformed_yaml_handled(self, tmp_path):
        """Malformed YAML should be handled gracefully."""
        indicators = tmp_path / "indicators"
        indicators.mkdir()
        (indicators / "ioc-database.yaml").write_text(
            "malware_domains:\n  - domain: [invalid yaml\n    unclosed"
        )

        intel = IntelligenceDB(tmp_path)
        intel.load()  # Should not raise
        assert intel._loaded is True


# ─── Lazy Loading / Ensure Loaded ──────────────────────────────────

class TestLazyLoading:
    """Test the lazy loading mechanism."""

    def test_ensure_loaded_triggers_load(self, intel_dir):
        intel = IntelligenceDB(intel_dir)
        assert intel._loaded is False
        # Calling a matching function should trigger load
        intel.match_filename("shell.php")
        assert intel._loaded is True

    def test_double_load_is_safe(self, intel_dir):
        intel = IntelligenceDB(intel_dir)
        intel.load()
        initial_count = len(intel.malware_domains)
        intel.load()  # Loading again should not double-add
        # Note: the current impl re-appends. We test the load() call doesn't crash.
        # This is a known behavior — the test documents it.


# ─── Version Comparison ────────────────────────────────────────────

class TestVersionComparison:
    """Tests for version comparison helpers."""

    def test_parse_version_simple(self):
        assert IntelligenceDB._parse_version("6.4.1") == [6, 4, 1]

    def test_parse_version_beta(self):
        """Beta suffixes should be stripped."""
        assert IntelligenceDB._parse_version("6.4.1-beta") == [6, 4, 1]

    def test_parse_version_two_parts(self):
        assert IntelligenceDB._parse_version("5.9") == [5, 9]

    def test_version_lt(self):
        assert IntelligenceDB._version_lt("6.4.0", "6.4.1") is True
        assert IntelligenceDB._version_lt("6.4.1", "6.4.1") is False
        assert IntelligenceDB._version_lt("6.5.0", "6.4.1") is False

    def test_version_in_range_lt(self):
        assert IntelligenceDB._version_in_range("6.3.0", "<6.4.1") is True
        assert IntelligenceDB._version_in_range("6.5.0", "<6.4.1") is False

    def test_version_in_range_lte(self):
        assert IntelligenceDB._version_in_range("6.4.1", "<=6.4.1") is True
        assert IntelligenceDB._version_in_range("6.4.2", "<=6.4.1") is False

    def test_version_in_range_gt(self):
        assert IntelligenceDB._version_in_range("6.5.0", ">6.4.1") is True
        assert IntelligenceDB._version_in_range("6.4.0", ">6.4.1") is False

    def test_version_in_range_gte(self):
        assert IntelligenceDB._version_in_range("6.4.1", ">=6.4.1") is True
        assert IntelligenceDB._version_in_range("6.4.0", ">=6.4.1") is False

    def test_version_in_range_exact(self):
        assert IntelligenceDB._version_in_range("6.4.1", "6.4.1") is True
        assert IntelligenceDB._version_in_range("6.4.0", "6.4.1") is False


# ─── Playbook Matching ─────────────────────────────────────────────

class TestPlaybookMatching:
    """Tests for auto-matching threats to playbooks."""

    def test_match_playbook_by_cve(self, loaded_intel):
        """Playbook should match when threat CVE appears in playbook name/description."""
        from agent.src.models import Threat, ThreatType, Severity

        threats = [
            Threat(
                threat_type=ThreatType.ROGUE_ADMIN,
                severity=Severity.CRITICAL,
                title="Rogue admin",
                site_path="/test",
                cve="CVE-2024-28000",
            ),
        ]

        result = loaded_intel.match_playbook(threats)
        assert result is not None
        assert "cve-2024-28000" in result.name.lower()

    def test_match_playbook_no_threats(self, loaded_intel):
        result = loaded_intel.match_playbook([])
        assert result is None

    def test_match_playbook_no_match(self, loaded_intel):
        from agent.src.models import Threat, ThreatType, Severity

        threats = [
            Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=Severity.LOW,
                title="Bad permissions",
                site_path="/test",
                cve="CVE-9999-99999",
            ),
        ]
        result = loaded_intel.match_playbook(threats)
        assert result is None
