"""
CleanShift Test Suite — Alerter Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for the Telegram alerter module including:
- Message formatting
- Rate limiting
- Retry logic
- Configuration loading (YAML + env file fallback)
- Graceful failure handling
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from agent.src.alerter import TelegramAlerter
from agent.src.models import (
    ScanResult,
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def alerter():
    """Create a TelegramAlerter with test credentials."""
    return TelegramAlerter(
        bot_token="test_token_123",
        chat_id="-1002531048951",
        topic_id="25",
        max_messages_per_run=3,
        max_retries=1,
        base_backoff=0.01,  # Fast backoff for tests
    )


@pytest.fixture
def disabled_alerter():
    """Create a disabled TelegramAlerter (no credentials)."""
    return TelegramAlerter(bot_token="", chat_id="")


@pytest.fixture
def scan_result():
    """Create a mock ScanResult for testing."""
    result = ScanResult(
        id="test-scan-001",
        agent_id="agent-001",
        server_hostname="test-server.example.com",
    )
    result.sites = [
        WordPressSite(
            path="/home/testuser/public_html",
            domain="example.com",
            wp_version="6.5.2",
        )
    ]
    result.threats = [
        Threat(
            threat_type=ThreatType.ROGUE_ADMIN,
            severity=Severity.CRITICAL,
            title="Rogue admin: GuaUserWa5",
            description="Admin account matches known attacker pattern",
            location="wp_users (ID: 42)",
            site_path="/home/testuser/public_html",
            cve="CVE-2024-28000",
        ),
        Threat(
            threat_type=ThreatType.BACKDOOR_FILE,
            severity=Severity.HIGH,
            title="Known backdoor file: shell.php",
            description="File matches known backdoor pattern",
            location="/home/testuser/public_html/shell.php",
            site_path="/home/testuser/public_html",
            details={"sha256": "abc123def456"},
        ),
    ]
    result.summary = {
        "total_threats": 2,
        "threats_by_severity": {"critical": 1, "high": 1},
        "total_sites_scanned": 1,
        "sites_with_threats": 1,
        "scan_duration_seconds": 12.5,
    }
    return result


# ─── Initialization Tests ──────────────────────────────────────────

class TestAlerterInit:
    """Tests for TelegramAlerter initialization."""

    def test_enabled_with_credentials(self, alerter):
        """Alerter should be enabled when credentials are provided."""
        assert alerter.is_enabled is True

    def test_disabled_without_credentials(self, disabled_alerter):
        """Alerter should be disabled without credentials."""
        assert disabled_alerter.is_enabled is False

    def test_from_config_with_yaml_values(self):
        """from_config should use values from config dict."""
        config = {
            "telegram": {
                "bot_token": "yaml_token",
                "chat_id": "-12345",
                "topic_id": "10",
            }
        }
        alerter = TelegramAlerter.from_config(config)
        assert alerter.bot_token == "yaml_token"
        assert alerter.chat_id == "-12345"
        assert alerter.topic_id == "10"

    def test_from_config_empty_falls_back_to_env(self, tmp_path):
        """from_config should fall back to env file when config is empty."""
        env_file = tmp_path / "telegram.env"
        env_file.write_text(
            "TELEGRAM_BOT_TOKEN=env_token_123\n"
            "TELEGRAM_CHAT_ID=-99999\n"
            "TELEGRAM_TOPIC_ID=42\n"
        )

        config = {"telegram": {"bot_token": "", "chat_id": ""}}

        with patch.object(TelegramAlerter, "_load_from_env_file") as mock_load:
            mock_load.return_value = ("env_token_123", "-99999", "42")
            alerter = TelegramAlerter.from_config(config)

        assert alerter.bot_token == "env_token_123"
        assert alerter.chat_id == "-99999"


# ─── Env File Loading Tests ────────────────────────────────────────

class TestEnvFileLoading:
    """Tests for loading credentials from env files."""

    def test_load_valid_env_file(self, tmp_path):
        """Should parse valid env file correctly."""
        env_file = tmp_path / "telegram.env"
        env_file.write_text(
            "# Telegram secrets\n"
            "TELEGRAM_BOT_TOKEN=8773332873:AAHcToXcZxZvYgFaJmPlhTjWTLL71YvatXY\n"
            "TELEGRAM_CHAT_ID=-1002531048951\n"
            "TELEGRAM_TOPIC_ID=25\n"
        )

        token, chat_id, topic_id = TelegramAlerter._load_from_env_file(env_file)
        assert token == "8773332873:AAHcToXcZxZvYgFaJmPlhTjWTLL71YvatXY"
        assert chat_id == "-1002531048951"
        assert topic_id == "25"

    def test_load_env_file_with_quotes(self, tmp_path):
        """Should handle quoted values in env files."""
        env_file = tmp_path / "telegram.env"
        env_file.write_text(
            "TELEGRAM_BOT_TOKEN='quoted_token'\n"
            'TELEGRAM_CHAT_ID="-12345"\n'
        )

        token, chat_id, _ = TelegramAlerter._load_from_env_file(env_file)
        assert token == "quoted_token"
        assert chat_id == "-12345"

    def test_load_nonexistent_env_file(self, tmp_path):
        """Should return empty strings for missing env file."""
        token, chat_id, topic_id = TelegramAlerter._load_from_env_file(
            tmp_path / "nonexistent.env"
        )
        assert token == ""
        assert chat_id == ""


# ─── Rate Limiting Tests ───────────────────────────────────────────

class TestRateLimiting:
    """Tests for message rate limiting."""

    def test_rate_limit_blocks_excess_messages(self, alerter):
        """Should block messages after exceeding rate limit."""
        # Max is 3 for test alerter
        with patch.object(alerter, "_send_message", return_value=True) as mock_send:
            alerter._messages_sent = 3

            # This should be blocked
            result = alerter.send_scan_summary(MagicMock())
            assert result is False

    def test_rate_limit_reset(self, alerter):
        """reset_rate_limit should clear the message counter."""
        alerter._messages_sent = 5
        alerter.reset_rate_limit()
        assert alerter._messages_sent == 0
        assert alerter.messages_remaining == 3

    def test_messages_remaining_decreases(self, alerter):
        """messages_remaining should decrease with each send."""
        assert alerter.messages_remaining == 3
        alerter._messages_sent = 1
        assert alerter.messages_remaining == 2


# ─── Message Formatting Tests ──────────────────────────────────────

class TestMessageFormatting:
    """Tests for Telegram message formatting."""

    def test_escape_markdown_special_chars(self):
        """Should escape all Telegram MarkdownV2 special characters."""
        text = "Hello [world] (test) *bold* _italic_ `code`"
        escaped = TelegramAlerter._escape_md(text)
        assert "\\[" in escaped
        assert "\\]" in escaped
        assert "\\(" in escaped
        assert "\\*" in escaped
        assert "\\_" in escaped
        assert "\\`" in escaped

    def test_escape_preserves_normal_text(self):
        """Should not modify normal alphanumeric text."""
        text = "simple text 123"
        escaped = TelegramAlerter._escape_md(text)
        assert escaped == text

    @patch("agent.src.alerter.urlopen")
    def test_send_scan_summary_clean(self, mock_urlopen, alerter, scan_result):
        """Should send properly formatted clean scan summary."""
        scan_result.threats = []
        scan_result.summary["total_threats"] = 0

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"ok": True}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = alerter.send_scan_summary(scan_result)
        assert result is True
        assert alerter._messages_sent == 1

    @patch("agent.src.alerter.urlopen")
    def test_send_scan_summary_with_threats(self, mock_urlopen, alerter, scan_result):
        """Should include threat details in summary message."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"ok": True}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = alerter.send_scan_summary(scan_result)
        assert result is True

        # Verify the API was called with correct chat_id
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data.decode())
        assert body["chat_id"] == "-1002531048951"
        assert body["message_thread_id"] == "25"

    def test_disabled_alerter_returns_false(self, disabled_alerter, scan_result):
        """Disabled alerter should return False without sending."""
        result = disabled_alerter.send_scan_summary(scan_result)
        assert result is False


# ─── Threat Alert Tests ────────────────────────────────────────────

class TestThreatAlerts:
    """Tests for individual threat alerts."""

    @patch("agent.src.alerter.urlopen")
    def test_sends_critical_threat(self, mock_urlopen, alerter):
        """Should send alerts for CRITICAL threats."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"ok": True}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        threat = Threat(
            threat_type=ThreatType.ROGUE_ADMIN,
            severity=Severity.CRITICAL,
            title="Rogue admin: evil_user",
            description="Malicious admin account",
            location="wp_users",
            site_path="/home/test/public_html",
        )

        result = alerter.send_threat_alert(threat)
        assert result is True

    def test_skips_low_severity_threats(self, alerter):
        """Should not send alerts for LOW/MEDIUM/INFO threats."""
        for severity in [Severity.LOW, Severity.MEDIUM, Severity.INFO]:
            threat = Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=severity,
                title="Minor issue",
                description="test",
                location="test",
            )
            result = alerter.send_threat_alert(threat)
            assert result is False


# ─── Retry Logic Tests ─────────────────────────────────────────────

class TestRetryLogic:
    """Tests for API retry behavior."""

    @patch("agent.src.alerter.urlopen")
    def test_retries_on_http_error(self, mock_urlopen, alerter):
        """Should retry on HTTP errors up to max_retries."""
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="", code=500, msg="Server Error",
            hdrs=None, fp=None,
        )

        result = alerter._send_message("test")
        assert result is False
        assert mock_urlopen.call_count == alerter.max_retries

    @patch("agent.src.alerter.urlopen")
    def test_succeeds_on_second_try(self, mock_urlopen, alerter):
        """Should succeed if retry after initial failure works."""
        from urllib.error import URLError

        alerter.max_retries = 2

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"ok": True}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [
            URLError("Connection refused"),
            mock_response,
        ]

        result = alerter._send_message("test")
        assert result is True
        assert mock_urlopen.call_count == 2
