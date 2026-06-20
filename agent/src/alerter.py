"""
CleanShift Telegram Alerter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sends scan summaries and individual threat alerts to a Telegram
chat/topic via the Telegram Bot API.

Features:
    - Formatted Markdown messages for Telegram
    - Rate limiting: max 10 messages per scan run
    - Retry logic: 3 retries with exponential backoff
    - Graceful failure: never crashes the scanner
    - Config from YAML, fallback to /root/.secrets/telegram.env

Usage:
    alerter = TelegramAlerter.from_config(config)
    alerter.send_scan_summary(scan_result)
    alerter.send_threat_alert(threat)
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import json as json_module

from .models import ScanResult, Severity, Threat, ThreatType

logger = logging.getLogger("cleanshift.alerter")

# Telegram Bot API base URL
_TELEGRAM_API_BASE = "https://api.telegram.org/bot{token}/{method}"

# Default env file for credentials fallback
_DEFAULT_SECRETS_PATH = Path("/root/.secrets/telegram.env")

# Severity emoji mapping for Telegram messages
_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

# Threat type labels for messages
_THREAT_LABELS = {
    ThreatType.ROGUE_ADMIN: "Rogue Admin",
    ThreatType.BACKDOOR_FILE: "Backdoor File",
    ThreatType.DB_MARKER: "DB Marker",
    ThreatType.SCRIPT_INJECTION: "Script Injection",
    ThreatType.VULNERABLE_PLUGIN: "Vuln Plugin",
    ThreatType.CORE_MODIFIED: "Core Modified",
    ThreatType.PERMISSION_ISSUE: "Permission Issue",
    ThreatType.SUSPICIOUS_FILE: "Suspicious File",
    ThreatType.PHP_CONFIG_RISK: "PHP Config Risk",
    ThreatType.PHP_OUTDATED: "PHP Outdated",
    ThreatType.MYSQL_CONFIG_RISK: "MySQL Config Risk",
    ThreatType.MYSQL_ROGUE_USER: "MySQL Rogue User",
    ThreatType.DB_INJECTION: "DB Injection",
    ThreatType.WP_CRON_ABUSE: "WP Cron Abuse",
}


class TelegramAlerter:
    """
    Sends formatted scan results and threat alerts to Telegram.

    Rate-limited to a configurable max messages per scan run (default 10).
    All API errors are caught and logged — alerter failures never crash
    the scanner or remediation engine.
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        topic_id: Optional[str] = None,
        max_messages_per_run: int = 10,
        max_retries: int = 3,
        base_backoff: float = 1.0,
    ) -> None:
        """
        Initialize the Telegram alerter.

        Args:
            bot_token: Telegram Bot API token.
            chat_id: Chat ID to send messages to (group/channel).
            topic_id: Optional topic/thread ID for forum-style groups.
            max_messages_per_run: Rate limit per scan run.
            max_retries: Number of retries on API failure.
            base_backoff: Base delay for exponential backoff (seconds).
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.topic_id = topic_id
        self.max_messages_per_run = max_messages_per_run
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        self._messages_sent = 0
        self._enabled = bool(bot_token and chat_id)

        if not self._enabled:
            logger.warning(
                "Telegram alerter disabled — bot_token or chat_id not configured"
            )

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "TelegramAlerter":
        """
        Create a TelegramAlerter from the agent configuration dict.

        Loads credentials from config.yaml first, then falls back to
        the secrets env file at /root/.secrets/telegram.env.

        Args:
            config: Agent configuration dictionary.

        Returns:
            Configured TelegramAlerter instance.
        """
        telegram_config = config.get("telegram", {})

        bot_token = telegram_config.get("bot_token", "")
        chat_id = str(telegram_config.get("chat_id", ""))
        topic_id = str(telegram_config.get("topic_id", "")) or None

        # Fallback to env file if config values are empty
        if not bot_token or not chat_id:
            env_token, env_chat_id, env_topic_id = cls._load_from_env_file()
            if not bot_token:
                bot_token = env_token
            if not chat_id:
                chat_id = env_chat_id
            if not topic_id:
                topic_id = env_topic_id

        return cls(
            bot_token=bot_token,
            chat_id=chat_id,
            topic_id=topic_id,
            max_messages_per_run=telegram_config.get("max_messages_per_run", 10),
        )

    @staticmethod
    def _load_from_env_file(
        path: Path = _DEFAULT_SECRETS_PATH,
    ) -> tuple:
        """
        Load Telegram credentials from a shell env file.

        Expected format:
            TELEGRAM_BOT_TOKEN=xxx
            TELEGRAM_CHAT_ID=xxx
            TELEGRAM_TOPIC_ID=xxx

        Returns (bot_token, chat_id, topic_id) tuple.
        """
        bot_token = ""
        chat_id = ""
        topic_id = ""

        try:
            if path.exists():
                content = path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("'\"")

                    if key == "TELEGRAM_BOT_TOKEN":
                        bot_token = value
                    elif key == "TELEGRAM_CHAT_ID":
                        chat_id = value
                    elif key == "TELEGRAM_TOPIC_ID":
                        topic_id = value
        except (OSError, PermissionError) as e:
            logger.debug("Could not read secrets file %s: %s", path, e)

        return bot_token, chat_id, topic_id or None

    def send_scan_summary(self, result: ScanResult) -> bool:
        """
        Send a formatted summary of scan results to Telegram.

        Includes severity breakdown, site count, duration, and
        top threats (up to 5).

        Args:
            result: Completed ScanResult.

        Returns:
            True if message was sent successfully.
        """
        if not self._enabled:
            return False

        try:
            summary = result.summary or {}
            total_threats = summary.get("total_threats", len(result.threats))
            by_sev = summary.get("threats_by_severity", {})
            duration = summary.get("scan_duration_seconds", 0)
            sites_count = summary.get("total_sites_scanned", len(result.sites))
            sites_with_threats = summary.get("sites_with_threats", 0)

            # Determine overall status
            if total_threats == 0:
                status_emoji = "✅"
                status_text = "CLEAN"
            elif by_sev.get("critical", 0) > 0:
                status_emoji = "🚨"
                status_text = "CRITICAL THREATS"
            elif by_sev.get("high", 0) > 0:
                status_emoji = "⚠️"
                status_text = "HIGH THREATS"
            else:
                status_emoji = "⚡"
                status_text = "THREATS FOUND"

            # Build message
            lines = [
                f"{status_emoji} *CleanShift Scan Report*",
                f"",
                f"🖥 *Server:* `{result.server_hostname}`",
                f"📅 *Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                f"⏱ *Duration:* {duration:.1f}s",
                f"🌐 *Sites scanned:* {sites_count}",
                f"",
                f"*Status: {status_text}*",
            ]

            if total_threats > 0:
                lines.append(f"")
                lines.append(f"*Threats: {total_threats}*")

                # Severity breakdown
                sev_parts = []
                for sev_name, emoji in [
                    ("critical", "🔴"),
                    ("high", "🟠"),
                    ("medium", "🟡"),
                    ("low", "🔵"),
                    ("info", "⚪"),
                ]:
                    count = by_sev.get(sev_name, 0)
                    if count > 0:
                        sev_parts.append(f"{emoji} {count} {sev_name.upper()}")

                if sev_parts:
                    lines.append(" \\| ".join(sev_parts))

                lines.append(f"")
                lines.append(f"📍 *Affected sites:* {sites_with_threats}/{sites_count}")

                # Top threats (up to 5)
                if result.threats:
                    lines.append(f"")
                    lines.append(f"*Top Threats:*")
                    sorted_threats = sorted(
                        result.threats,
                        key=lambda t: list(Severity).index(t.severity),
                    )
                    for i, threat in enumerate(sorted_threats[:5], 1):
                        emoji = _SEVERITY_EMOJI.get(threat.severity, "❓")
                        label = _THREAT_LABELS.get(threat.threat_type, threat.threat_type.value)
                        cve = f" ({threat.cve})" if threat.cve else ""
                        lines.append(
                            f"{i}\\. {emoji} *{label}* — {self._escape_md(threat.title[:60])}{cve}"
                        )

                    if len(result.threats) > 5:
                        lines.append(f"_\\.\\.\\. and {len(result.threats) - 5} more_")
            else:
                lines.append(f"")
                lines.append(f"🎉 No threats detected across {sites_count} site\\(s\\)")

            message = "\n".join(lines)
            return self._send_message(message, parse_mode="MarkdownV2")

        except Exception as e:
            logger.error("Failed to build scan summary message: %s", e, exc_info=True)
            return False

    def send_threat_alert(self, threat: Threat) -> bool:
        """
        Send an individual critical threat notification.

        Only sends for CRITICAL and HIGH severity threats.

        Args:
            threat: The threat to alert about.

        Returns:
            True if message was sent successfully.
        """
        if not self._enabled:
            return False

        if threat.severity not in (Severity.CRITICAL, Severity.HIGH):
            return False

        try:
            emoji = _SEVERITY_EMOJI.get(threat.severity, "❓")
            label = _THREAT_LABELS.get(threat.threat_type, threat.threat_type.value)

            lines = [
                f"{emoji} *THREAT ALERT: {self._escape_md(label)}*",
                f"",
                f"*Title:* {self._escape_md(threat.title)}",
                f"*Severity:* {threat.severity.value.upper()}",
                f"*Location:* `{self._escape_md(threat.location[:100])}`",
            ]

            if threat.site_path:
                lines.append(f"*Site:* `{self._escape_md(threat.site_path)}`")
            if threat.cve:
                lines.append(f"*CVE:* {self._escape_md(threat.cve)}")
            if threat.description:
                desc = threat.description[:200]
                lines.append(f"")
                lines.append(f"_{self._escape_md(desc)}_")

            # SHA256 if available
            sha256 = threat.details.get("sha256", "")
            if sha256:
                lines.append(f"")
                lines.append(f"*SHA256:* `{sha256[:16]}...`")

            message = "\n".join(lines)
            return self._send_message(message, parse_mode="MarkdownV2")

        except Exception as e:
            logger.error("Failed to build threat alert message: %s", e, exc_info=True)
            return False

    def _send_message(
        self,
        text: str,
        parse_mode: str = "MarkdownV2",
    ) -> bool:
        """
        Send a message via the Telegram Bot API with rate limiting and retries.

        Args:
            text: Message text.
            parse_mode: Telegram parse mode (MarkdownV2, HTML, etc.).

        Returns:
            True if the message was sent successfully.
        """
        # Rate limit check
        if self._messages_sent >= self.max_messages_per_run:
            logger.warning(
                "Rate limit reached (%d/%d messages) — skipping",
                self._messages_sent, self.max_messages_per_run,
            )
            return False

        # Build API request
        url = _TELEGRAM_API_BASE.format(token=self.bot_token, method="sendMessage")

        payload: Dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        if self.topic_id:
            payload["message_thread_id"] = self.topic_id

        # Retry loop with exponential backoff
        for attempt in range(self.max_retries):
            try:
                data = json_module.dumps(payload).encode("utf-8")
                req = Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                with urlopen(req, timeout=15) as resp:
                    response_data = json_module.loads(resp.read().decode("utf-8"))

                if response_data.get("ok"):
                    self._messages_sent += 1
                    logger.info(
                        "Telegram message sent (%d/%d)",
                        self._messages_sent, self.max_messages_per_run,
                    )
                    return True
                else:
                    logger.warning(
                        "Telegram API returned error: %s",
                        response_data.get("description", "Unknown error"),
                    )

            except HTTPError as e:
                logger.warning(
                    "Telegram API HTTP error (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, e,
                )
            except URLError as e:
                logger.warning(
                    "Telegram API connection error (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, e,
                )
            except Exception as e:
                logger.warning(
                    "Telegram send failed (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, e,
                )

            # Exponential backoff before retry
            if attempt < self.max_retries - 1:
                delay = self.base_backoff * (2 ** attempt)
                logger.debug("Retrying in %.1fs...", delay)
                time.sleep(delay)

        logger.error(
            "Failed to send Telegram message after %d attempts",
            self.max_retries,
        )
        return False

    @staticmethod
    def _escape_md(text: str) -> str:
        """
        Escape special characters for Telegram MarkdownV2.

        Telegram MarkdownV2 requires escaping: _ * [ ] ( ) ~ ` > # + - = | { } . !
        """
        special_chars = r"_*[]()~`>#+-=|{}.!"
        escaped = ""
        for ch in text:
            if ch in special_chars:
                escaped += "\\" + ch
            else:
                escaped += ch
        return escaped

    def reset_rate_limit(self) -> None:
        """Reset the message counter (call at the start of each scan run)."""
        self._messages_sent = 0

    @property
    def is_enabled(self) -> bool:
        """Check if the alerter is configured and enabled."""
        return self._enabled

    @property
    def messages_remaining(self) -> int:
        """Return the number of messages remaining in this run."""
        return max(0, self.max_messages_per_run - self._messages_sent)
