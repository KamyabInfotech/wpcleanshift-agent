"""
CleanShift Universal Scanners
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Platform-agnostic security scanners that apply to ANY PHP application
regardless of the CMS or framework in use.  These complement the
platform-specific scanners by checking for common server-level
misconfigurations and exposed files.

Scanners:
    EnvFileScanner          — exposed ``.env`` files with secrets
    GitExposureScanner      — exposed ``.git/`` and ``.svn/`` directories
    BackupFileScanner       — database dumps, archives, config backups
    DebugModeScanner        — debug / development mode left on
    PHPConfigScanner        — dangerous php.ini / .user.ini settings
    ComposerAuditScanner    — composer.lock vulnerable dependencies
    AdminExposureScanner    — exposed DB admin tools (adminer, phpMyAdmin)
    SymlinkScanner          — malicious symlinks crossing user boundaries
    PlatformConfigScanner   — config secrets & permission audit

All scanners follow the project convention of returning
``List[Threat]`` and using ``ThreatType`` / ``Severity`` from
``models.py``.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Severity,
    Threat,
    ThreatType,
)
from .platform import (
    PlatformDetector,
    PlatformInfo,
    PlatformType,
    _path_exists,
    _safe_read_text,
)

logger = logging.getLogger("cleanshift.universal")


# ─── Helpers ────────────────────────────────────────────────────────

def _file_size_safe(filepath):
    # type: (str) -> int
    """Return file size in bytes, or 0 on error."""
    try:
        return os.path.getsize(filepath)
    except (OSError, PermissionError):
        return 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EnvFileScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class EnvFileScanner:
    """
    Scans for exposed ``.env`` files that contain application secrets.

    These files commonly contain database passwords, API keys, and
    encryption keys.  If accessible via the web server they allow
    full application compromise.
    """

    ENV_FILENAMES = [
        ".env",
        ".env.backup",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.old",
        ".env.save",
        ".env.bak",
        ".env.example",
        ".env.dist",
    ]  # type: List[str]

    # Keys whose values should be treated as secrets
    SECRET_KEYS = {
        "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD",
        "APP_KEY", "APP_SECRET", "SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY", "AWS_SECRET",
        "STRIPE_SECRET", "STRIPE_SECRET_KEY",
        "MAIL_PASSWORD", "SMTP_PASSWORD",
        "REDIS_PASSWORD",
        "JWT_SECRET",
        "PUSHER_APP_SECRET",
        "MIX_PUSHER_APP_KEY",
        "PAYPAL_SECRET",
        "TWILIO_AUTH_TOKEN",
        "GITHUB_TOKEN",
        "API_SECRET",
    }  # type: set

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan *site_path* for exposed .env files.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        for env_name in self.ENV_FILENAMES:
            env_path = os.path.join(site_path, env_name)
            try:
                if not os.path.isfile(env_path):
                    continue
            except (OSError, PermissionError):
                continue

            content = _safe_read_text(env_path, max_bytes=65536)
            has_real_secrets = False
            found_secrets = []  # type: List[str]

            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip().upper()
                    val = val.strip().strip("'\"")

                    if key in self.SECRET_KEYS and val and val not in (
                        "null", "secret", "password", "your-secret-here",
                        "SomeRandomString", "base64:...",
                    ):
                        has_real_secrets = True
                        found_secrets.append(key)

            # Determine severity
            if env_name in (".env.example", ".env.dist"):
                # Template files — lower severity unless they contain real secrets
                severity = Severity.HIGH if has_real_secrets else Severity.LOW
            elif has_real_secrets:
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH

            threats.append(Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=severity,
                title="Exposed env file: %s" % env_name,
                description=(
                    "Environment file found at site root. "
                    "Contains %d secret keys. "
                    "If accessible via the web, credentials are fully exposed."
                    % len(found_secrets)
                ),
                location=env_path,
                evidence="Secret keys found: %s" % ", ".join(found_secrets[:5]) if found_secrets else "No secrets detected",
                site_path=site_path,
                details={
                    "env_file": env_name,
                    "has_real_secrets": has_real_secrets,
                    "secret_count": len(found_secrets),
                    "secret_keys": found_secrets[:10],
                },
            ))

        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GitExposureScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class GitExposureScanner:
    """
    Scans for exposed version control directories (``.git/``,
    ``.svn/``) in the webroot.  These allow attackers to clone the
    entire source code, including credentials in config files.
    """

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Check for exposed .git and .svn directories.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        # ── .git exposure ────────────────────────────────────────────
        git_head = os.path.join(site_path, ".git", "HEAD")
        try:
            if os.path.isfile(git_head):
                # Check .git/config for remote URLs that may contain tokens
                git_config = os.path.join(site_path, ".git", "config")
                has_token = False
                remote_url = ""
                if os.path.isfile(git_config):
                    config_content = _safe_read_text(git_config, max_bytes=8192)
                    # Look for URLs with embedded tokens
                    token_patterns = [
                        r"https?://[^@]+@",  # user@host
                        r"ghp_[A-Za-z0-9]+",  # GitHub PAT
                        r"glpat-[A-Za-z0-9]+",  # GitLab PAT
                    ]
                    for pat in token_patterns:
                        if re.search(pat, config_content):
                            has_token = True
                            break
                    # Extract remote URL
                    url_m = re.search(r"url\s*=\s*(.+)", config_content)
                    if url_m:
                        remote_url = url_m.group(1).strip()

                severity = Severity.CRITICAL if has_token else Severity.HIGH

                # Redact embedded credentials from remote URL
                redacted_url = re.sub(r'(https?://)[^@]+@', r'\1***REDACTED***@', remote_url)

                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=severity,
                    title="Exposed .git directory in webroot",
                    description=(
                        ".git directory is accessible. Attackers can reconstruct "
                        "the full source code, commit history, and any credentials "
                        "committed to the repository."
                    ),
                    location=os.path.join(site_path, ".git"),
                    evidence="Remote URL: %s" % redacted_url if redacted_url else ".git/HEAD exists",
                    site_path=site_path,
                    details={
                        "has_token_in_config": has_token,
                        "remote_url": redacted_url,
                    },
                ))
        except (OSError, PermissionError) as exc:
            logger.debug("Error checking .git: %s", exc)

        # ── .svn exposure ────────────────────────────────────────────
        svn_checks = [
            os.path.join(site_path, ".svn", "entries"),
            os.path.join(site_path, ".svn", "wc.db"),
        ]
        for svn_path in svn_checks:
            try:
                if os.path.exists(svn_path):
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=Severity.HIGH,
                        title="Exposed .svn directory in webroot",
                        description=(
                            ".svn directory is accessible. Source code and "
                            "repository metadata can be reconstructed."
                        ),
                        location=os.path.join(site_path, ".svn"),
                        evidence="Found: %s" % os.path.basename(svn_path),
                        site_path=site_path,
                        details={"svn_file": svn_path},
                    ))
                    break  # One finding per .svn is enough
            except (OSError, PermissionError):
                continue

        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BackupFileScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BackupFileScanner:
    """
    Scans for exposed backup files: database dumps, archives, and
    configuration backups that should not be accessible via the web.
    """

    # Database dump extensions
    DB_DUMP_EXTENSIONS = {
        ".sql", ".sql.gz", ".sql.bz2", ".sql.zip",
        ".dump", ".dump.gz",
    }  # type: set

    # Archive extensions
    ARCHIVE_EXTENSIONS = {
        ".tar.gz", ".tgz", ".zip", ".rar", ".7z",
        ".tar.bz2", ".tar.xz", ".gz",
    }  # type: set

    # Minimum archive size to flag (1MB)
    ARCHIVE_MIN_SIZE = 1024 * 1024  # type: int

    # Config backup extensions
    CONFIG_BACKUP_EXTENSIONS = [
        ".bak", ".old", ".save", ".orig", ".copy",
    ]  # type: List[str]

    # PHP source backup patterns
    PHP_BACKUP_PATTERNS = [
        ".php.bak", ".php.old", ".php.save", ".php.orig",
        ".php.copy", ".php~", ".php.swp",
    ]  # type: List[str]

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan for exposed backup files.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        try:
            entries = os.listdir(site_path)
        except (OSError, PermissionError):
            return threats

        for entry in entries:
            full_path = os.path.join(site_path, entry)

            try:
                if not os.path.isfile(full_path):
                    continue
            except (OSError, PermissionError):
                continue

            entry_lower = entry.lower()

            # ── Database dumps ───────────────────────────────────────
            is_db_dump = False
            for ext in self.DB_DUMP_EXTENSIONS:
                if entry_lower.endswith(ext):
                    is_db_dump = True
                    break

            if is_db_dump:
                file_size = _file_size_safe(full_path)
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.CRITICAL,
                    title="Database dump in webroot: %s" % entry,
                    description=(
                        "Database dump file found in the site root. "
                        "Contains full database contents including user "
                        "credentials and potentially sensitive data."
                    ),
                    location=full_path,
                    evidence="Size: %d bytes" % file_size,
                    site_path=site_path,
                    details={"file": entry, "size_bytes": file_size, "type": "db_dump"},
                ))
                continue

            # ── Archives ─────────────────────────────────────────────
            is_archive = False
            for ext in self.ARCHIVE_EXTENSIONS:
                if entry_lower.endswith(ext):
                    is_archive = True
                    break

            if is_archive:
                file_size = _file_size_safe(full_path)
                if file_size >= self.ARCHIVE_MIN_SIZE:
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=Severity.HIGH,
                        title="Large archive in webroot: %s" % entry,
                        description=(
                            "Archive file larger than 1MB found in the site root. "
                            "May contain source code, database exports, or "
                            "other sensitive data."
                        ),
                        location=full_path,
                        evidence="Size: %d bytes (%.1f MB)" % (file_size, file_size / (1024.0 * 1024.0)),
                        site_path=site_path,
                        details={"file": entry, "size_bytes": file_size, "type": "archive"},
                    ))
                continue

            # ── PHP source backups ───────────────────────────────────
            for pattern in self.PHP_BACKUP_PATTERNS:
                if entry_lower.endswith(pattern):
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=Severity.HIGH,
                        title="PHP backup file: %s" % entry,
                        description=(
                            "PHP source backup file found. If served as "
                            "plain text, source code and credentials are exposed."
                        ),
                        location=full_path,
                        evidence="Backup pattern: %s" % pattern,
                        site_path=site_path,
                        details={"file": entry, "type": "php_backup"},
                    ))
                    break

        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DebugModeScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DebugModeScanner:
    """
    Detects debug / development mode left on in production across
    multiple platforms.  Debug mode leaks stack traces, database
    queries, and environment details to visitors.
    """

    # Known debug/info PHP files
    DEBUG_FILES = [
        "phpinfo.php",
        "info.php",
        "test.php",
        "php_info.php",
        "i.php",
        "pi.php",
    ]  # type: List[str]

    # phpinfo() pattern
    _PHPINFO_RE = re.compile(r"phpinfo\s*\(\s*\)", re.IGNORECASE)

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan for debug mode indicators.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        # ── Platform-specific debug checks ───────────────────────────
        if platform_info:
            pt = platform_info.platform_type
            try:
                if pt == PlatformType.WORDPRESS:
                    threats.extend(self._check_wordpress_debug(site_path))
                elif pt == PlatformType.LARAVEL:
                    threats.extend(self._check_laravel_debug(site_path))
                elif pt == PlatformType.SYMFONY:
                    threats.extend(self._check_symfony_debug(site_path))
                elif pt == PlatformType.DRUPAL:
                    threats.extend(self._check_drupal_debug(site_path))
                elif pt == PlatformType.CODEIGNITER:
                    threats.extend(self._check_codeigniter_debug(site_path))
                elif pt == PlatformType.YII:
                    threats.extend(self._check_yii_debug(site_path))
                elif pt == PlatformType.CAKEPHP:
                    threats.extend(self._check_cakephp_debug(site_path))
            except Exception as exc:
                logger.debug("Debug mode check error for %s: %s", pt, exc)

        # ── Generic debug/info files ─────────────────────────────────
        for debug_file in self.DEBUG_FILES:
            debug_path = os.path.join(site_path, debug_file)
            try:
                if os.path.isfile(debug_path):
                    content = _safe_read_text(debug_path, max_bytes=4096)
                    if content and self._PHPINFO_RE.search(content):
                        threats.append(Threat(
                            threat_type=ThreatType.PERMISSION_ISSUE,
                            severity=Severity.HIGH,
                            title="phpinfo() file exposed: %s" % debug_file,
                            description=(
                                "File containing phpinfo() found in webroot. "
                                "Exposes PHP version, extensions, configuration, "
                                "environment variables, and server paths."
                            ),
                            location=debug_path,
                            evidence="phpinfo() call detected",
                            site_path=site_path,
                            details={"file": debug_file, "check": "phpinfo"},
                        ))
                    elif os.path.isfile(debug_path):
                        # File exists but may not contain phpinfo
                        threats.append(Threat(
                            threat_type=ThreatType.SUSPICIOUS_FILE,
                            severity=Severity.MEDIUM,
                            title="Debug/test file in webroot: %s" % debug_file,
                            description=(
                                "File with a debug/test name found in the webroot. "
                                "May expose sensitive information or provide attack surface."
                            ),
                            location=debug_path,
                            evidence="File exists: %s" % debug_file,
                            site_path=site_path,
                            details={"file": debug_file, "check": "debug_file"},
                        ))
            except (OSError, PermissionError):
                continue

        # ── Symfony app_dev.php ───────────────────────────────────────
        app_dev = os.path.join(site_path, "app_dev.php")
        try:
            if os.path.isfile(app_dev):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.HIGH,
                    title="Symfony app_dev.php exposed",
                    description=(
                        "Symfony development front controller is accessible. "
                        "Provides full debug toolbar and profiler."
                    ),
                    location=app_dev,
                    evidence="app_dev.php exists in webroot",
                    site_path=site_path,
                    details={"check": "symfony_app_dev"},
                ))
        except (OSError, PermissionError):
            pass

        return threats

    def _check_wordpress_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check WP_DEBUG in wp-config.php."""
        threats = []  # type: List[Threat]
        content = _safe_read_text(os.path.join(site_path, "wp-config.php"))
        if not content:
            return threats

        # WP_DEBUG true
        if re.search(r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)", content, re.IGNORECASE):
            threats.append(Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=Severity.MEDIUM,
                title="WordPress WP_DEBUG is enabled",
                description=(
                    "WP_DEBUG is set to true in wp-config.php. "
                    "This exposes PHP notices and warnings to visitors."
                ),
                location=os.path.join(site_path, "wp-config.php"),
                evidence="WP_DEBUG = true",
                site_path=site_path,
                details={"check": "wp_debug", "platform": "wordpress"},
            ))

        # WP_DEBUG_DISPLAY true
        if re.search(r"define\s*\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*true\s*\)", content, re.IGNORECASE):
            threats.append(Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=Severity.HIGH,
                title="WordPress WP_DEBUG_DISPLAY is enabled",
                description=(
                    "WP_DEBUG_DISPLAY is set to true. Debug output is "
                    "displayed directly in the browser to all visitors."
                ),
                location=os.path.join(site_path, "wp-config.php"),
                evidence="WP_DEBUG_DISPLAY = true",
                site_path=site_path,
                details={"check": "wp_debug_display", "platform": "wordpress"},
            ))

        return threats

    def _check_laravel_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check APP_DEBUG in .env."""
        threats = []  # type: List[Threat]
        content = _safe_read_text(os.path.join(site_path, ".env"))
        if not content:
            return threats

        for line in content.splitlines():
            line = line.strip()
            if line.upper().startswith("APP_DEBUG") and "=" in line:
                _, _, val = line.partition("=")
                val = val.strip().strip("'\"").lower()
                if val == "true":
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=Severity.MEDIUM,
                        title="Laravel APP_DEBUG is enabled",
                        description=(
                            "APP_DEBUG=true in .env file. Laravel will display "
                            "detailed error pages with stack traces, config values, "
                            "and environment variables to all visitors."
                        ),
                        location=os.path.join(site_path, ".env"),
                        evidence="APP_DEBUG=true",
                        site_path=site_path,
                        details={"check": "laravel_debug", "platform": "laravel"},
                    ))
                break
        return threats

    def _check_symfony_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check APP_DEBUG in .env and _profiler route."""
        threats = []  # type: List[Threat]
        content = _safe_read_text(os.path.join(site_path, ".env"))
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.upper().startswith("APP_DEBUG") and "=" in line:
                    _, _, val = line.partition("=")
                    val = val.strip().strip("'\"").lower()
                    if val in ("1", "true"):
                        threats.append(Threat(
                            threat_type=ThreatType.PERMISSION_ISSUE,
                            severity=Severity.MEDIUM,
                            title="Symfony APP_DEBUG is enabled",
                            description=(
                                "APP_DEBUG is enabled. Symfony web profiler "
                                "and debug toolbar are accessible."
                            ),
                            location=os.path.join(site_path, ".env"),
                            evidence="APP_DEBUG=%s" % val,
                            site_path=site_path,
                            details={"check": "symfony_debug", "platform": "symfony"},
                        ))
                    break
        return threats

    def _check_drupal_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check error_level setting in Drupal."""
        threats = []  # type: List[Threat]
        settings_path = os.path.join(site_path, "sites", "default", "settings.php")
        content = _safe_read_text(settings_path)
        if content and re.search(r"error_level.*verbose", content, re.IGNORECASE):
            threats.append(Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=Severity.MEDIUM,
                title="Drupal verbose error reporting enabled",
                description=(
                    "Drupal error_level is set to verbose. Detailed error "
                    "messages are displayed to all visitors."
                ),
                location=settings_path,
                evidence="error_level = verbose",
                site_path=site_path,
                details={"check": "drupal_debug", "platform": "drupal"},
            ))
        return threats

    def _check_codeigniter_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check ENVIRONMENT constant in CodeIgniter."""
        threats = []  # type: List[Threat]

        # CI3: index.php
        for candidate in ["index.php", ".env"]:
            content = _safe_read_text(os.path.join(site_path, candidate))
            if content:
                if re.search(r"ENVIRONMENT.*['\"]development['\"]", content, re.IGNORECASE):
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=Severity.MEDIUM,
                        title="CodeIgniter ENVIRONMENT is 'development'",
                        description=(
                            "CodeIgniter is running in development mode. "
                            "Detailed errors are displayed."
                        ),
                        location=os.path.join(site_path, candidate),
                        evidence="ENVIRONMENT = development",
                        site_path=site_path,
                        details={"check": "ci_debug", "platform": "codeigniter"},
                    ))
                    break
        return threats

    def _check_yii_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check YII_DEBUG constant."""
        threats = []  # type: List[Threat]
        for candidate in ["index.php", "web/index.php", "config/web.php"]:
            content = _safe_read_text(os.path.join(site_path, candidate))
            if content and re.search(r"YII_DEBUG.*true", content, re.IGNORECASE):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.MEDIUM,
                    title="Yii YII_DEBUG is enabled",
                    description="YII_DEBUG is set to true. Debug mode is active.",
                    location=os.path.join(site_path, candidate),
                    evidence="YII_DEBUG = true",
                    site_path=site_path,
                    details={"check": "yii_debug", "platform": "yii"},
                ))
                break
        return threats

    def _check_cakephp_debug(self, site_path):
        # type: (str) -> List[Threat]
        """Check 'debug' => true in config/app.php."""
        threats = []  # type: List[Threat]
        content = _safe_read_text(os.path.join(site_path, "config", "app.php"))
        if content and re.search(r"['\"]debug['\"]\s*=>\s*true", content, re.IGNORECASE):
            threats.append(Threat(
                threat_type=ThreatType.PERMISSION_ISSUE,
                severity=Severity.MEDIUM,
                title="CakePHP debug mode is enabled",
                description="CakePHP 'debug' is set to true in config/app.php.",
                location=os.path.join(site_path, "config", "app.php"),
                evidence="'debug' => true",
                site_path=site_path,
                details={"check": "cakephp_debug", "platform": "cakephp"},
            ))
        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHPConfigScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PHPConfigScanner:
    """
    Checks PHP runtime configuration for dangerous settings via
    ``.user.ini`` and ``php.ini`` files.
    """

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan PHP configuration files for dangerous settings.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        # Check .user.ini and php.ini at site root
        for ini_name in [".user.ini", "php.ini"]:
            ini_path = os.path.join(site_path, ini_name)
            try:
                if not os.path.isfile(ini_path):
                    continue
            except (OSError, PermissionError):
                continue

            content = _safe_read_text(ini_path, max_bytes=32768)
            if not content:
                continue

            settings = self._parse_ini_content(content)

            # allow_url_include
            if settings.get("allow_url_include", "").lower() in ("on", "1", "true"):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.CRITICAL,
                    title="PHP allow_url_include is ON",
                    description=(
                        "allow_url_include is enabled in %s. "
                        "This allows include() and require() to fetch "
                        "remote PHP code via URL, enabling remote code execution."
                        % ini_name
                    ),
                    location=ini_path,
                    evidence="allow_url_include = On",
                    site_path=site_path,
                    details={"setting": "allow_url_include", "file": ini_name},
                ))

            # allow_url_fopen
            if settings.get("allow_url_fopen", "").lower() in ("on", "1", "true"):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.MEDIUM,
                    title="PHP allow_url_fopen is ON",
                    description=(
                        "allow_url_fopen is enabled in %s. "
                        "Allows file functions to access URLs." % ini_name
                    ),
                    location=ini_path,
                    evidence="allow_url_fopen = On",
                    site_path=site_path,
                    details={"setting": "allow_url_fopen", "file": ini_name},
                ))

            # display_errors
            if settings.get("display_errors", "").lower() in ("on", "1", "true"):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.MEDIUM,
                    title="PHP display_errors is ON",
                    description=(
                        "display_errors is enabled in %s. Error messages "
                        "with paths and queries are shown to visitors."
                        % ini_name
                    ),
                    location=ini_path,
                    evidence="display_errors = On",
                    site_path=site_path,
                    details={"setting": "display_errors", "file": ini_name},
                ))

            # expose_php
            if settings.get("expose_php", "").lower() in ("on", "1", "true"):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.LOW,
                    title="PHP expose_php is ON",
                    description=(
                        "expose_php is enabled in %s. The X-Powered-By "
                        "header reveals the PHP version." % ini_name
                    ),
                    location=ini_path,
                    evidence="expose_php = On",
                    site_path=site_path,
                    details={"setting": "expose_php", "file": ini_name},
                ))

            # disable_functions empty
            if "disable_functions" in settings and not settings["disable_functions"].strip():
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.HIGH,
                    title="PHP disable_functions is empty",
                    description=(
                        "disable_functions is empty in %s. All dangerous "
                        "functions (exec, system, passthru, etc.) are available."
                        % ini_name
                    ),
                    location=ini_path,
                    evidence="disable_functions = (empty)",
                    site_path=site_path,
                    details={"setting": "disable_functions", "file": ini_name},
                ))

        return threats

    @staticmethod
    def _parse_ini_content(content):
        # type: (str) -> Dict[str, str]
        """Parse INI file content into a key-value dict."""
        settings = {}  # type: Dict[str, str]
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            if line.startswith("["):
                continue  # Section header
            if "=" in line:
                key, _, val = line.partition("=")
                settings[key.strip()] = val.strip()
        return settings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ComposerAuditScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ComposerAuditScanner:
    """
    Scans ``composer.lock`` for known vulnerable or abandoned packages.

    Maintains a built-in list of high-impact vulnerabilities.  Also
    checks for the dangerous ``phpunit/phpunit`` eval-stdin.php file
    on disk.
    """

    # (package_name, vulnerable_version_spec, severity, description, cve)
    # version_spec: "<X.Y.Z" means any version below X.Y.Z is vulnerable
    KNOWN_VULNERABILITIES = [
        (
            "phpunit/phpunit", "<9.0.0", "critical",
            "PHPUnit < 9.0 with eval-stdin.php allows remote code execution",
            "CVE-2017-9841",
        ),
        (
            "phpmailer/phpmailer", "<6.5.0", "high",
            "PHPMailer < 6.5.0 has multiple security vulnerabilities",
            None,
        ),
        (
            "dompdf/dompdf", "<2.0.0", "critical",
            "dompdf < 2.0.0 allows remote code execution via crafted PDF",
            "CVE-2021-3838",
        ),
        (
            "guzzlehttp/guzzle", "<7.4.5", "medium",
            "Guzzle < 7.4.5 has SSRF and header injection vulnerabilities",
            "CVE-2022-31090",
        ),
        (
            "twig/twig", "<3.4.3", "high",
            "Twig < 3.4.3 has sandbox bypass vulnerability",
            None,
        ),
        (
            "symfony/http-kernel", "<5.4.20", "high",
            "Symfony HttpKernel < 5.4.20 has security vulnerabilities",
            None,
        ),
        (
            "laravel/framework", "<9.35.0", "high",
            "Laravel framework < 9.35.0 has security vulnerabilities",
            None,
        ),
        (
            "phpoffice/phpspreadsheet", "<1.29.0", "high",
            "PHPSpreadsheet < 1.29.0 has XXE and code execution vulnerabilities",
            None,
        ),
        (
            "firebase/php-jwt", "<6.4.0", "medium",
            "php-jwt < 6.4.0 has algorithm confusion vulnerability",
            None,
        ),
        (
            "league/flysystem", "<3.0.0", "medium",
            "Flysystem < 3.0.0 has path traversal vulnerability",
            None,
        ),
        (
            "pear/archive_tar", "<1.4.14", "high",
            "Archive_Tar < 1.4.14 allows arbitrary file overwrite",
            "CVE-2021-32610",
        ),
        (
            "phpseclib/phpseclib", "<3.0.19", "medium",
            "phpseclib < 3.0.19 has timing side-channel vulnerability",
            None,
        ),
    ]  # type: List[Tuple[str, str, str, str, Optional[str]]]

    # Abandoned packages that should be replaced
    ABANDONED_PACKAGES = [
        (
            "fzaninotto/faker", "medium",
            "fzaninotto/faker is abandoned, use fakerphp/faker instead",
        ),
        (
            "swiftmailer/swiftmailer", "medium",
            "swiftmailer/swiftmailer is abandoned, use symfony/mailer instead",
        ),
    ]  # type: List[Tuple[str, str, str]]

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan composer.lock for vulnerable dependencies.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        lock_path = os.path.join(site_path, "composer.lock")
        try:
            if not os.path.isfile(lock_path):
                return threats
        except (OSError, PermissionError):
            return threats

        content = _safe_read_text(lock_path)
        if not content:
            return threats

        try:
            data = json.loads(content)
        except (ValueError, TypeError) as exc:
            logger.warning("Failed to parse composer.lock: %s", exc)
            return threats

        packages = data.get("packages", [])
        packages_dev = data.get("packages-dev", [])
        all_packages = packages + packages_dev

        # Build name -> version map
        pkg_map = {}  # type: Dict[str, str]
        for pkg in all_packages:
            try:
                name = pkg.get("name", "").lower()
                version = pkg.get("version", "")
                if version.startswith("v"):
                    version = version[1:]
                if name and version:
                    pkg_map[name] = version
            except (AttributeError, TypeError):
                continue

        # Check known vulnerabilities
        for vuln_pkg, vuln_spec, sev_str, desc, cve in self.KNOWN_VULNERABILITIES:
            installed_ver = pkg_map.get(vuln_pkg.lower(), "")
            if not installed_ver:
                continue

            if self._version_matches_spec(installed_ver, vuln_spec):
                severity = self._str_to_severity(sev_str)
                threats.append(Threat(
                    threat_type=ThreatType.VULNERABLE_PLUGIN,
                    severity=severity,
                    title="Vulnerable dependency: %s %s" % (vuln_pkg, installed_ver),
                    description=desc,
                    location=lock_path,
                    evidence="Installed: %s, vulnerable: %s" % (installed_ver, vuln_spec),
                    site_path=site_path,
                    cve=cve,
                    details={
                        "package": vuln_pkg,
                        "installed_version": installed_ver,
                        "vulnerable_spec": vuln_spec,
                    },
                ))

        # Check abandoned packages
        for abn_pkg, abn_sev, abn_desc in self.ABANDONED_PACKAGES:
            if abn_pkg.lower() in pkg_map:
                severity = self._str_to_severity(abn_sev)
                threats.append(Threat(
                    threat_type=ThreatType.VULNERABLE_PLUGIN,
                    severity=severity,
                    title="Abandoned package: %s" % abn_pkg,
                    description=abn_desc,
                    location=lock_path,
                    evidence="Installed version: %s" % pkg_map[abn_pkg.lower()],
                    site_path=site_path,
                    details={
                        "package": abn_pkg,
                        "installed_version": pkg_map[abn_pkg.lower()],
                        "status": "abandoned",
                    },
                ))

        # Check for phpunit eval-stdin.php on disk
        eval_stdin = os.path.join(
            site_path, "vendor", "phpunit", "phpunit", "src", "Util", "PHP", "eval-stdin.php"
        )
        try:
            if os.path.isfile(eval_stdin):
                threats.append(Threat(
                    threat_type=ThreatType.BACKDOOR_FILE,
                    severity=Severity.CRITICAL,
                    title="PHPUnit eval-stdin.php is accessible",
                    description=(
                        "The PHPUnit eval-stdin.php file exists on disk. "
                        "This allows unauthenticated remote code execution "
                        "via a POST request."
                    ),
                    location=eval_stdin,
                    evidence="eval-stdin.php found in vendor/phpunit/",
                    site_path=site_path,
                    cve="CVE-2017-9841",
                    details={"check": "phpunit_eval_stdin"},
                ))
        except (OSError, PermissionError):
            pass

        return threats

    @staticmethod
    def _version_matches_spec(installed, spec):
        # type: (str, str) -> bool
        """
        Check if installed version matches a vulnerability spec.

        Currently supports ``<X.Y.Z`` format only.

        Args:
            installed: Installed version string (e.g. ``"5.7.3"``).
            spec:      Vulnerability specification (e.g. ``"<6.5.0"``).

        Returns:
            True if the installed version is vulnerable.
        """
        if not spec.startswith("<"):
            return False

        threshold = spec[1:]
        try:
            installed_parts = [int(x) for x in installed.split(".")[:3]]
            threshold_parts = [int(x) for x in threshold.split(".")[:3]]

            # Pad to 3 parts
            while len(installed_parts) < 3:
                installed_parts.append(0)
            while len(threshold_parts) < 3:
                threshold_parts.append(0)

            return installed_parts < threshold_parts
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _str_to_severity(sev_str):
        # type: (str) -> Severity
        """Convert a severity string to a Severity enum member."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(sev_str.lower(), Severity.MEDIUM)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AdminExposureScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AdminExposureScanner:
    """
    Scans for exposed database administration tools that provide
    unauthenticated or weakly-authenticated database access.
    """

    # Files to check in webroot
    ADMIN_FILES = [
        ("adminer.php", Severity.CRITICAL, "Adminer database manager"),
        ("editor.php", Severity.CRITICAL, "Adminer editor"),
    ]  # type: List[Tuple[str, Severity, str]]

    # Adminer with version suffix patterns
    _ADMINER_RE = re.compile(r"adminer[\-_]?\d*\.?\d*\.php$", re.IGNORECASE)

    # Directories
    ADMIN_DIRS = [
        ("phpmyadmin", Severity.HIGH, "phpMyAdmin"),
        ("pma", Severity.HIGH, "phpMyAdmin (alias)"),
        ("myadmin", Severity.HIGH, "phpMyAdmin (alias)"),
        ("phppgadmin", Severity.HIGH, "phpPgAdmin"),
    ]  # type: List[Tuple[str, Severity, str]]

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan for exposed admin tools.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        # Check specific admin files
        for filename, severity, tool_name in self.ADMIN_FILES:
            filepath = os.path.join(site_path, filename)
            try:
                if os.path.isfile(filepath):
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=severity,
                        title="Exposed admin tool: %s" % tool_name,
                        description=(
                            "%s found in webroot. Provides direct database "
                            "access with minimal authentication." % tool_name
                        ),
                        location=filepath,
                        evidence="File: %s" % filename,
                        site_path=site_path,
                        details={"tool": tool_name, "file": filename},
                    ))
            except (OSError, PermissionError):
                continue

        # Check for adminer-*.php variants
        try:
            for entry in os.listdir(site_path):
                if self._ADMINER_RE.match(entry) and entry not in ("adminer.php",):
                    filepath = os.path.join(site_path, entry)
                    if os.path.isfile(filepath):
                        threats.append(Threat(
                            threat_type=ThreatType.PERMISSION_ISSUE,
                            severity=Severity.CRITICAL,
                            title="Exposed Adminer variant: %s" % entry,
                            description=(
                                "Adminer database manager variant found in webroot. "
                                "Provides direct database access."
                            ),
                            location=filepath,
                            evidence="File: %s" % entry,
                            site_path=site_path,
                            details={"tool": "adminer", "file": entry},
                        ))
        except (OSError, PermissionError):
            pass

        # Check admin directories
        for dirname, severity, tool_name in self.ADMIN_DIRS:
            dirpath = os.path.join(site_path, dirname)
            try:
                if os.path.isdir(dirpath):
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=severity,
                        title="Exposed admin tool: %s" % tool_name,
                        description=(
                            "%s directory found in webroot. Should be "
                            "restricted or removed." % tool_name
                        ),
                        location=dirpath,
                        evidence="Directory: %s/" % dirname,
                        site_path=site_path,
                        details={"tool": tool_name, "directory": dirname},
                    ))
            except (OSError, PermissionError):
                continue

        # Platform-specific checks
        if platform_info:
            try:
                if platform_info.platform_type == PlatformType.MOODLE:
                    threats.extend(self._check_moodle_data(site_path))
            except Exception as exc:
                logger.debug("Platform-specific admin check error: %s", exc)

        return threats

    def _check_moodle_data(self, site_path):
        # type: (str) -> List[Threat]
        """Check if moodledata is inside the webroot."""
        threats = []  # type: List[Threat]
        moodledata = os.path.join(site_path, "moodledata")
        try:
            if os.path.isdir(moodledata):
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.HIGH,
                    title="Moodle data directory inside webroot",
                    description=(
                        "moodledata/ is inside the webroot. This directory "
                        "contains user uploads and session data that should "
                        "not be web-accessible. Move it outside the webroot."
                    ),
                    location=moodledata,
                    evidence="moodledata/ found in site root",
                    site_path=site_path,
                    details={"check": "moodledata_webroot", "platform": "moodle"},
                ))
        except (OSError, PermissionError):
            pass
        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SymlinkScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SymlinkScanner:
    """
    Scans for malicious symlinks that point outside the site or
    user directory, which can be used for cross-account data access
    on shared hosting.
    """

    # Sensitive files that symlinks commonly target
    SENSITIVE_TARGETS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/my.cnf",
        "/etc/mysql/my.cnf",
        "/root/.bash_history",
        "/root/.ssh/",
        # macOS equivalents (where /etc -> /private/etc)
        "/private/etc/passwd",
        "/private/etc/shadow",
        "/private/etc/my.cnf",
    ]  # type: List[str]

    # CageFS path fragments that indicate CloudLinux-managed symlinks
    _CAGEFS_INDICATORS = (
        "/.cagefs/opt/alt/",
        "/.cagefs/opt/lve/",
    )  # type: tuple

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan for malicious symlinks.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional platform detection result.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        # Determine the user's home directory boundary
        home_dir = self._get_home_dir(site_path)

        try:
            site_p = Path(site_path)
            for item in itertools.islice(site_p.rglob("*"), 50000):
                try:
                    if not item.is_symlink():
                        continue

                    target = str(item.resolve())
                    link_path = str(item)
                    rel_path = str(item.relative_to(site_p))

                    # Check if target is outside home directory
                    outside_home = False
                    if home_dir and not target.startswith(home_dir):
                        outside_home = True

                    # Check if target points to a sensitive system file
                    points_to_sensitive = any(
                        target.startswith(s) for s in self.SENSITIVE_TARGETS
                    )

                    if outside_home or points_to_sensitive:
                        # CageFS symlinks are legitimate CloudLinux infrastructure
                        if self._is_cagefs_path(target) or self._is_cagefs_path(link_path):
                            severity = Severity.INFO
                            description = (
                                "Symlink is managed by CageFS (CloudLinux). "
                                "This is expected infrastructure and not a security threat."
                            )
                            logger.debug(
                                "CageFS symlink downgraded to INFO: %s -> %s",
                                rel_path, target,
                            )
                        elif points_to_sensitive:
                            severity = Severity.CRITICAL
                            description = (
                                "Symlink points to a sensitive system file. "
                                "This is a clear indicator of a symlink attack."
                            )
                        else:
                            severity = Severity.CRITICAL
                            description = (
                                "Symlink points outside user's home directory. "
                                "This may be used for cross-user data access "
                                "on shared hosting."
                            )

                        threats.append(Threat(
                            threat_type=ThreatType.BACKDOOR_FILE,
                            severity=severity,
                            title="Malicious symlink: %s" % rel_path,
                            description=description,
                            location=link_path,
                            evidence="Target: %s" % target,
                            site_path=site_path,
                            details={
                                "symlink": rel_path,
                                "target": target,
                                "outside_home": outside_home,
                                "points_to_sensitive": points_to_sensitive,
                                "cagefs_managed": self._is_cagefs_path(target) or self._is_cagefs_path(link_path),
                            },
                        ))

                except (OSError, PermissionError, ValueError):
                    continue

        except (OSError, PermissionError) as exc:
            logger.debug("Symlink scan error: %s", exc)

        return threats

    def _is_cagefs_path(self, path):
        # type: (str) -> bool
        """Return True if the path belongs to CageFS (CloudLinux) infrastructure.

        CageFS creates virtualised filesystem views for each user on
        CloudLinux-powered shared hosting.  Symlinks inside these
        paths (e.g. ``/.cagefs/opt/alt/`` for alternate PHP versions
        or ``/.cagefs/opt/lve/`` for LVE resources) are legitimate
        and should not be treated as malicious.
        """
        for indicator in self._CAGEFS_INDICATORS:
            if indicator in path:
                return True
        return False

    @staticmethod
    def _get_home_dir(site_path):
        # type: (str) -> str
        """
        Determine the user's home directory from the site path.

        Assumes standard ``/home/user/`` or ``/Users/user/`` layout.
        """
        parts = site_path.split(os.sep)
        # Plesk: /var/www/vhosts/{domain}/httpdocs → /var/www/vhosts/{domain}
        if "vhosts" in parts:
            idx = parts.index("vhosts")
            if idx + 1 < len(parts):
                return str(Path(*parts[:idx + 2]))
        # /home/user/... or /Users/user/...
        if len(parts) >= 3:
            if parts[1] in ("home", "Users"):
                return os.sep + os.path.join(parts[1], parts[2])
        return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PlatformConfigScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PlatformConfigScanner:
    """
    Audits platform configuration files for:
      - Insecure file permissions (world-readable/writable)
      - Backup copies of config files
      - Empty or default database passwords
      - Default / unset secret keys
      - Debug / development mode enabled

    Works with any platform detected by ``PlatformDetector``.
    """

    def __init__(self, detector=None):
        # type: (Optional[PlatformDetector]) -> None
        self.detector = detector or PlatformDetector()

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Scan platform config for security issues.

        If *platform_info* is not provided, auto-detection is
        performed first.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional pre-computed ``PlatformInfo``.

        Returns:
            List of Threat objects.
        """
        threats = []  # type: List[Threat]

        if platform_info is None:
            try:
                platform_info = self.detector.detect(site_path)
            except Exception as exc:
                logger.debug("Platform detection failed: %s", exc)
                return threats

        if not platform_info.platform_type or platform_info.platform_type in (
            PlatformType.STATIC, PlatformType.CUSTOM_PHP
        ):
            return threats

        # 1. Config file permissions
        try:
            perm_issues = self.detector.check_config_permissions(site_path, platform_info)
            for issue in perm_issues:
                sev_str = issue.get("severity", "medium")
                severity = ComposerAuditScanner._str_to_severity(sev_str)
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=severity,
                    title=issue.get("title", "Config permission issue"),
                    description=issue.get("detail", ""),
                    location=platform_info.config_file,
                    evidence=issue.get("detail", ""),
                    site_path=site_path,
                    details={"check": "config_permissions", "platform": platform_info.platform_type},
                ))
        except Exception as exc:
            logger.debug("Config permission check error: %s", exc)

        # 2. Config secrets audit
        try:
            secrets = self.detector.get_config_secrets(site_path, platform_info)
            issues = secrets.get("issues", [])

            for issue_text in issues:
                # Determine severity from issue text
                if "empty" in issue_text.lower() and "password" in issue_text.lower():
                    severity = Severity.HIGH
                elif "default" in issue_text.lower() or "empty" in issue_text.lower():
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.MEDIUM

                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=severity,
                    title="Config issue: %s" % issue_text,
                    description=(
                        "Platform configuration audit found: %s. "
                        "This weakens the security of the application."
                        % issue_text
                    ),
                    location=platform_info.config_file,
                    evidence=issue_text,
                    site_path=site_path,
                    details={
                        "check": "config_secrets",
                        "platform": platform_info.platform_type,
                        "issue": issue_text,
                    },
                ))
        except Exception as exc:
            logger.debug("Config secrets audit error: %s", exc)

        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# UniversalScanner (Facade)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UniversalScanner:
    """
    Façade that runs all universal scanners on a site path.

    Usage::

        scanner = UniversalScanner()
        threats = scanner.scan("/home/user/public_html")
    """

    def __init__(self, detector=None):
        # type: (Optional[PlatformDetector]) -> None
        self.detector = detector or PlatformDetector()
        self.env_scanner = EnvFileScanner()
        self.git_scanner = GitExposureScanner()
        self.backup_scanner = BackupFileScanner()
        self.debug_scanner = DebugModeScanner()
        self.php_config_scanner = PHPConfigScanner()
        self.composer_scanner = ComposerAuditScanner()
        self.admin_scanner = AdminExposureScanner()
        self.symlink_scanner = SymlinkScanner()
        self.config_scanner = PlatformConfigScanner(detector=self.detector)

    def scan(self, site_path, platform_info=None):
        # type: (str, Optional[PlatformInfo]) -> List[Threat]
        """
        Run all universal scanners.

        Args:
            site_path:     Root directory of the site.
            platform_info: Optional pre-computed ``PlatformInfo``.
                           If not provided, auto-detection is performed.

        Returns:
            Aggregated list of Threat objects from all scanners.
        """
        threats = []  # type: List[Threat]

        # Auto-detect platform if not provided
        if platform_info is None:
            try:
                platform_info = self.detector.detect(site_path)
                logger.info(
                    "UniversalScanner auto-detected platform: %s (%.0f%% confidence)",
                    platform_info.platform_type,
                    platform_info.detection_confidence * 100,
                )
            except Exception as exc:
                logger.warning("Platform detection failed: %s", exc)
                platform_info = PlatformInfo()

        scanners = [
            ("env_files", self.env_scanner),
            ("git_exposure", self.git_scanner),
            ("backup_files", self.backup_scanner),
            ("debug_mode", self.debug_scanner),
            ("php_config", self.php_config_scanner),
            ("composer_audit", self.composer_scanner),
            ("admin_exposure", self.admin_scanner),
            ("symlinks", self.symlink_scanner),
            ("config_audit", self.config_scanner),
        ]  # type: List[Tuple[str, Any]]

        for name, scanner in scanners:
            try:
                logger.debug("Running universal scanner: %s", name)
                results = scanner.scan(site_path, platform_info)
                threats.extend(results)
                logger.debug("Scanner %s found %d threats", name, len(results))
            except Exception as exc:
                logger.warning("Universal scanner %s failed: %s", name, exc)

        logger.info(
            "UniversalScanner complete: %d total threats at %s",
            len(threats), site_path,
        )
        return threats
