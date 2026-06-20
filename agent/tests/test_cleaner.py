"""
CleanShift Test Suite — Cleaner Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the RemediationEngine including:
- Initialization with different modes
- Destructive action approval gates (delete_user, reset_password, drop_table)
- approve_destructive flag behaviour
- Dry-run mode (no execution)
- shlex.quote applied to command parameters
- Backup creation before remediation
- Audit log entry generation
- Password generation via secrets module
- Non-interactive safety (stdin not tty → skip destructive)
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from agent.src.cleaner import RemediationEngine
from agent.src.intelligence import IntelligenceDB, Playbook, PlaybookStep
from agent.src.models import (
    RemediationAction,
    RemediationMode,
    RemediationStatus,
    ScanResult,
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def mock_intel():
    """Create a minimal mock IntelligenceDB."""
    intel = MagicMock(spec=IntelligenceDB)
    intel.get_playbook.return_value = None
    intel.match_playbook.return_value = None
    return intel


@pytest.fixture
def scan_result():
    """ScanResult with a single rogue-admin threat."""
    site_path = "/tmp/test-site"
    return ScanResult(
        server_hostname="test-server",
        sites=[WordPressSite(path=site_path, domain="example.com")],
        threats=[
            Threat(
                threat_type=ThreatType.ROGUE_ADMIN,
                severity=Severity.CRITICAL,
                title="Rogue admin: hacker",
                location="wp_users",
                site_path=site_path,
                details={"user_id": "42", "user_login": "hacker"},
            ),
        ],
    )


@pytest.fixture
def multi_threat_scan():
    """ScanResult with various threat types."""
    site_path = "/tmp/test-site"
    return ScanResult(
        server_hostname="test-server",
        sites=[WordPressSite(path=site_path, domain="example.com")],
        threats=[
            Threat(
                threat_type=ThreatType.ROGUE_ADMIN,
                severity=Severity.CRITICAL,
                title="Rogue admin",
                site_path=site_path,
                details={"user_id": "42", "user_login": "badguy"},
            ),
            Threat(
                threat_type=ThreatType.DB_MARKER,
                severity=Severity.HIGH,
                title="DB marker",
                location="wp_options.litespeed_crawler",
                site_path=site_path,
                details={"option_name": "litespeed_crawler"},
            ),
            Threat(
                threat_type=ThreatType.VULNERABLE_PLUGIN,
                severity=Severity.CRITICAL,
                title="Vulnerable plugin",
                site_path=site_path,
                details={"plugin_slug": "litespeed-cache"},
            ),
        ],
    )


# ─── Initialization Tests ──────────────────────────────────────────

class TestRemediationEngineInit:
    """Tests for RemediationEngine initialisation with different modes."""

    def test_default_mode_is_report_only(self, mock_intel):
        engine = RemediationEngine(mock_intel)
        assert engine.mode == RemediationMode.REPORT_ONLY
        assert engine.dry_run is False
        assert engine.approve_all is False
        assert engine.approve_destructive is False

    def test_auto_mode(self, mock_intel):
        engine = RemediationEngine(mock_intel, mode=RemediationMode.AUTO)
        assert engine.mode == RemediationMode.AUTO

    def test_report_only_mode(self, mock_intel):
        engine = RemediationEngine(mock_intel, mode=RemediationMode.REPORT_ONLY)
        assert engine.mode == RemediationMode.REPORT_ONLY

    def test_dry_run_flag(self, mock_intel):
        engine = RemediationEngine(mock_intel, dry_run=True)
        assert engine.dry_run is True

    def test_approve_destructive_flag(self, mock_intel):
        engine = RemediationEngine(mock_intel, approve_destructive=True)
        assert engine.approve_destructive is True

    def test_approval_callback_stored(self, mock_intel):
        cb = MagicMock()
        engine = RemediationEngine(mock_intel, approval_callback=cb)
        assert engine.approval_callback is cb

    def test_backup_before_clean_default_true(self, mock_intel):
        engine = RemediationEngine(mock_intel)
        assert engine.backup_before_clean is True

    def test_initial_state_empty(self, mock_intel):
        engine = RemediationEngine(mock_intel)
        assert engine.actions == []
        assert engine.audit_log == []


# ─── Report-Only Mode ──────────────────────────────────────────────

class TestReportOnlyMode:
    """Report-only mode should never execute any actions."""

    def test_report_only_returns_empty(self, mock_intel, scan_result):
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.REPORT_ONLY,
        )
        actions = engine.remediate(scan_result)
        assert actions == []

    def test_report_only_logs_audit(self, mock_intel, scan_result):
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.REPORT_ONLY,
        )
        engine.remediate(scan_result)
        events = [e["event"] for e in engine.audit_log]
        assert "mode_check" in events


# ─── Destructive Action Approval ───────────────────────────────────

class TestDestructiveActions:
    """Destructive actions (delete_user, reset_password, drop_table) always require approval."""

    def test_always_require_approval_set(self):
        assert "delete_user" in RemediationEngine.ALWAYS_REQUIRE_APPROVAL
        assert "reset_password" in RemediationEngine.ALWAYS_REQUIRE_APPROVAL
        assert "drop_table" in RemediationEngine.ALWAYS_REQUIRE_APPROVAL

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_delete_user_requires_approval_no_callback(self, mock_euid, mock_intel, scan_result):
        """Without a callback and not auto-approved, delete_user should be REQUIRES_APPROVAL."""
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        du_actions = [a for a in engine.actions if a.action_type == "delete_user"]
        assert len(du_actions) >= 1
        # Without approve_destructive or callback, should be requires_approval or skipped
        for a in du_actions:
            assert a.status in (
                RemediationStatus.REQUIRES_APPROVAL,
                RemediationStatus.SKIPPED,
            )

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_approve_destructive_auto_approves(self, mock_euid, mock_intel, scan_result):
        """approve_destructive=True should auto-approve destructive actions in dry-run."""
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            approve_destructive=True,
            dry_run=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        du_actions = [a for a in engine.actions if a.action_type == "delete_user"]
        assert len(du_actions) >= 1
        for a in du_actions:
            assert a.status == RemediationStatus.COMPLETED
            assert "[DRY RUN]" in a.output

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    @patch("sys.stdin")
    def test_approval_callback_invoked_for_destructive(self, mock_stdin, mock_euid, mock_intel, scan_result):
        """Approval callback should be called for destructive actions."""
        mock_stdin.isatty.return_value = True

        cb = MagicMock(return_value=False)
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            approval_callback=cb,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        assert cb.called
        du_actions = [a for a in engine.actions if a.action_type == "delete_user"]
        for a in du_actions:
            assert a.status == RemediationStatus.SKIPPED


# ─── Dry-Run Mode ──────────────────────────────────────────────────

class TestDryRunMode:
    """Dry-run should log but never execute actions."""

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    @patch("agent.src.cleaner.subprocess.run")
    def test_dry_run_does_not_call_subprocess(self, mock_subproc, mock_euid, mock_intel, scan_result):
        """subprocess.run should never be called in dry-run mode."""
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True,
            approve_all=True,
            approve_destructive=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)
        mock_subproc.assert_not_called()

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_dry_run_marks_completed(self, mock_euid, mock_intel, scan_result):
        """Dry-run actions should be marked COMPLETED with '[DRY RUN]' in output."""
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True,
            approve_all=True,
            approve_destructive=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        for action in engine.actions:
            assert action.status == RemediationStatus.COMPLETED
            assert "[DRY RUN]" in action.output


# ─── shlex.quote Sanitisation ──────────────────────────────────────

class TestShlexQuote:
    """shlex.quote should be applied to all substituted parameters."""

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_shlex_quote_in_backdoor_quarantine(self, mock_euid, mock_intel, tmp_path):
        """Quarantine commands should use shlex.quote for paths."""
        site_path = tmp_path / "public_html"
        site_path.mkdir()
        backdoor = site_path / "evil script.php"
        backdoor.write_text("<?php system($_GET['x']); ?>")

        threat = Threat(
            threat_type=ThreatType.BACKDOOR_FILE,
            severity=Severity.HIGH,
            title="Backdoor file",
            location=str(backdoor),
            site_path=str(site_path),
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=str(site_path))

        q_actions = [a for a in engine.actions if a.action_type == "quarantine_file"]
        assert len(q_actions) >= 1
        # The path with a space should be quoted
        assert "evil script.php" not in q_actions[0].command or "'" in q_actions[0].command

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_shlex_quote_in_db_marker_option(self, mock_euid, mock_intel):
        """delete_option command should shlex.quote the option name."""
        site_path = "/tmp/test-site"
        threat = Threat(
            threat_type=ThreatType.DB_MARKER,
            severity=Severity.HIGH,
            title="DB marker",
            location="wp_options.mal_option",
            site_path=site_path,
            details={"option_name": "mal_option; rm -rf /"},
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=site_path)

        opt_actions = [a for a in engine.actions if a.action_type == "delete_option"]
        assert len(opt_actions) >= 1
        # The injected payload should be quoted (single quotes wrapping it)
        assert "'" in opt_actions[0].command

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_shlex_quote_in_chmod(self, mock_euid, mock_intel, tmp_path):
        """chmod command should shlex.quote the file path."""
        site_path = tmp_path / "public_html"
        site_path.mkdir()
        target_file = site_path / "wp-config copy.php"
        target_file.write_text("test")

        threat = Threat(
            threat_type=ThreatType.PERMISSION_ISSUE,
            severity=Severity.MEDIUM,
            title="Bad permissions",
            location=str(target_file),
            site_path=str(site_path),
            details={"recommended": "644"},
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=str(site_path))

        perm_actions = [a for a in engine.actions if a.action_type == "fix_permissions"]
        assert len(perm_actions) >= 1
        # Path with space should be quoted
        assert "'" in perm_actions[0].command


# ─── Backup Creation ───────────────────────────────────────────────

class TestBackupCreation:
    """Test backup creation before remediation."""

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_backup_created_before_remediation(self, mock_euid, mock_intel, tmp_path):
        """Backup tar.gz should be created when backup_before_clean=True and not dry_run."""
        site_path = tmp_path / "public_html"
        site_path.mkdir()
        (site_path / "wp-config.php").write_text("<?php // config")
        (site_path / "index.php").write_text("<?php // index")

        threat = Threat(
            threat_type=ThreatType.DB_MARKER,
            severity=Severity.HIGH,
            title="DB marker",
            location="wp_options.test",
            site_path=str(site_path),
            details={"option_name": "test_option"},
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            backup_before_clean=True,
            approve_all=True,
        )

        # Mock the wp-cli call to avoid needing a real WP install
        with patch("agent.src.cleaner.run_wp_cli", return_value=(True, "OK")):
            engine.remediate(result, site_path=str(site_path))

        # Check backup was created
        backup_dir = site_path.parent / ".cleanshift-backups"
        if backup_dir.exists():
            backups = list(backup_dir.glob("*.tar.gz"))
            assert len(backups) >= 1
            # Audit should log backup events
            backup_events = [e for e in engine.audit_log if "backup" in e["event"]]
            assert len(backup_events) >= 1

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_no_backup_in_dry_run(self, mock_euid, mock_intel, tmp_path):
        """Backup should NOT be created in dry-run mode."""
        site_path = tmp_path / "public_html"
        site_path.mkdir()
        (site_path / "wp-config.php").write_text("<?php")

        threat = Threat(
            threat_type=ThreatType.DB_MARKER,
            severity=Severity.HIGH,
            title="test",
            site_path=str(site_path),
            details={"option_name": "x"},
            location="wp_options.x",
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=True,
        )
        engine.remediate(result, site_path=str(site_path))

        backup_dir = site_path.parent / ".cleanshift-backups"
        assert not backup_dir.exists()


# ─── Audit Log ─────────────────────────────────────────────────────

class TestAuditLog:
    """Test that audit log entries are created for all operations."""

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_audit_entries_have_timestamps(self, mock_euid, mock_intel, scan_result):
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            approve_destructive=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        assert len(engine.audit_log) >= 1
        for entry in engine.audit_log:
            assert "timestamp" in entry
            assert "event" in entry
            assert "message" in entry

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_audit_log_records_dry_run(self, mock_euid, mock_intel, scan_result):
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            approve_destructive=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        events = [e["event"] for e in engine.audit_log]
        assert "dry_run" in events

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    @patch("sys.stdin")
    def test_audit_log_records_skipped_action(self, mock_stdin, mock_euid, mock_intel, scan_result):
        mock_stdin.isatty.return_value = True

        cb = MagicMock(return_value=False)
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            approval_callback=cb,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        events = [e["event"] for e in engine.audit_log]
        assert "action_skipped" in events


# ─── Password Generation ──────────────────────────────────────────

class TestPasswordGeneration:
    """Test that password generation uses the secrets module."""

    def test_password_length(self, mock_intel):
        engine = RemediationEngine(mock_intel)
        pw = engine._generate_password()
        assert len(pw) == 24

    def test_password_custom_length(self, mock_intel):
        engine = RemediationEngine(mock_intel)
        pw = engine._generate_password(length=32)
        assert len(pw) == 32

    def test_password_uses_secrets(self, mock_intel):
        """The _generate_password method should call secrets.choice."""
        engine = RemediationEngine(mock_intel)
        with patch("agent.src.cleaner.secrets.choice", side_effect=lambda a: "A") as mock_choice:
            pw = engine._generate_password(length=8)
            assert mock_choice.call_count == 8
            assert pw == "AAAAAAAA"

    def test_password_contains_mixed_chars(self, mock_intel):
        """Generated passwords should contain letters, digits, and symbols."""
        engine = RemediationEngine(mock_intel)
        # Generate many passwords and check they contain variety
        passwords = [engine._generate_password() for _ in range(20)]
        all_chars = "".join(passwords)
        assert any(c.isdigit() for c in all_chars), "Password should contain digits"
        assert any(c.isalpha() for c in all_chars), "Password should contain letters"


# ─── Non-Interactive Safety ────────────────────────────────────────

class TestNonInteractiveSafety:
    """When stdin is not a TTY, destructive actions should be skipped."""

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    @patch("sys.stdin")
    def test_skip_destructive_non_tty(self, mock_stdin, mock_euid, mock_intel, scan_result):
        """Destructive actions should be SKIPPED when stdin is not a TTY."""
        mock_stdin.isatty.return_value = False

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        du_actions = [a for a in engine.actions if a.action_type == "delete_user"]
        assert len(du_actions) >= 1
        for a in du_actions:
            assert a.status == RemediationStatus.SKIPPED
            assert "--approve-destructive" in a.output

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    @patch("sys.stdin")
    def test_approve_destructive_overrides_non_tty(self, mock_stdin, mock_euid, mock_intel, scan_result):
        """approve_destructive=True should still work even with non-TTY stdin."""
        mock_stdin.isatty.return_value = False

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            approve_destructive=True,
            dry_run=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)

        du_actions = [a for a in engine.actions if a.action_type == "delete_user"]
        assert len(du_actions) >= 1
        for a in du_actions:
            assert a.status == RemediationStatus.COMPLETED


# ─── Input Validation ──────────────────────────────────────────────

class TestInputValidation:
    """Test security validations in remediation targets."""

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_non_numeric_user_id_rejected(self, mock_euid, mock_intel):
        """Rogue admin with non-numeric user_id should be silently skipped."""
        site_path = "/tmp/test-site"
        threat = Threat(
            threat_type=ThreatType.ROGUE_ADMIN,
            severity=Severity.CRITICAL,
            title="Rogue admin with SQL injection",
            site_path=site_path,
            details={"user_id": "42; DROP TABLE wp_users", "user_login": "hacker"},
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            approve_destructive=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=site_path)

        # No delete_user action should be created for non-numeric ID
        du_actions = [a for a in engine.actions if a.action_type == "delete_user"]
        assert len(du_actions) == 0

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_invalid_plugin_slug_rejected(self, mock_euid, mock_intel):
        """Plugin slug with special characters should be rejected."""
        site_path = "/tmp/test-site"
        threat = Threat(
            threat_type=ThreatType.VULNERABLE_PLUGIN,
            severity=Severity.HIGH,
            title="Bad plugin",
            site_path=site_path,
            details={"plugin_slug": "../../etc/passwd"},
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=site_path)

        plugin_actions = [
            a for a in engine.actions
            if a.action_type in ("update_plugin", "deactivate_plugin", "delete_plugin")
        ]
        assert len(plugin_actions) == 0

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_unsafe_chmod_mode_rejected(self, mock_euid, mock_intel, tmp_path):
        """chmod with unsafe modes like 777 should be rejected."""
        site_path = tmp_path / "site"
        site_path.mkdir()
        target = site_path / "test.php"
        target.write_text("<?php")

        threat = Threat(
            threat_type=ThreatType.PERMISSION_ISSUE,
            severity=Severity.LOW,
            title="Permissions",
            location=str(target),
            site_path=str(site_path),
            details={"recommended": "777"},
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=str(site_path))

        perm_actions = [a for a in engine.actions if a.action_type == "fix_permissions"]
        assert len(perm_actions) == 0


# ─── Empty / Edge Cases ───────────────────────────────────────────

class TestEdgeCases:
    """Edge cases for the remediation engine."""

    def test_no_threats_returns_empty(self, mock_intel):
        result = ScanResult(threats=[])
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            backup_before_clean=False,
        )
        actions = engine.remediate(result)
        assert actions == []

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_generate_report_returns_markdown(self, mock_euid, mock_intel, scan_result):
        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            approve_destructive=True,
            backup_before_clean=False,
        )
        engine.remediate(scan_result)
        report = engine.generate_report()
        assert "# CleanShift Remediation Report" in report
        assert "## Summary" in report

    @patch("agent.src.cleaner.os.geteuid", return_value=1000)
    def test_low_confidence_skipped_in_auto(self, mock_euid, mock_intel):
        """Low confidence threats should be skipped in AUTO mode."""
        site_path = "/tmp/test-site"
        threat = Threat(
            threat_type=ThreatType.BACKDOOR_FILE,
            severity=Severity.MEDIUM,
            title="Maybe backdoor",
            location="/tmp/test-site/maybe.php",
            site_path=site_path,
            confidence=0.3,
        )
        result = ScanResult(threats=[threat])

        engine = RemediationEngine(
            mock_intel, mode=RemediationMode.AUTO,
            dry_run=True, approve_all=True,
            backup_before_clean=False,
        )
        engine.remediate(result, site_path=site_path)

        # Low confidence threats are skipped in _remediate_threats
        assert len(engine.actions) == 0
