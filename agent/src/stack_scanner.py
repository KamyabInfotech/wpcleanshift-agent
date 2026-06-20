"""
CleanShift Stack Scanner — PHP & MySQL Level Checks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Detects server-level security issues in PHP configuration,
MySQL databases, and WordPress database tables that go beyond
simple file scanning.

Architecture:
    PHPConfigScanner   — dangerous php.ini settings, EOL versions
    MySQLSecurityScanner — rogue users, open access, malicious data
    WPDatabaseScanner  — wp_options injection, rogue crons, transient malware
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger("cleanshift.stack_scanner")


# ─── PHP EOL versions (update annually) ────────────────────────────

PHP_EOL_VERSIONS = {
    "5.6": "2018-12-31",
    "7.0": "2019-01-10",
    "7.1": "2019-12-01",
    "7.2": "2020-11-30",
    "7.3": "2021-12-06",
    "7.4": "2022-11-28",
    "8.0": "2023-11-26",
    "8.1": "2025-12-31",
    "8.2": "2026-12-08",
}

# Dangerous PHP settings that indicate security risk
DANGEROUS_PHP_SETTINGS = {
    "allow_url_include": {
        "dangerous_value": "1",
        "severity": "critical",
        "description": "Allows remote file inclusion (RFI) attacks — PHP can include files from remote URLs",
        "fix": "allow_url_include = Off",
    },
    "display_errors": {
        "dangerous_value": "1",
        "severity": "medium",
        "description": "Exposes PHP errors to visitors — leaks file paths, DB credentials, and internal structure",
        "fix": "display_errors = Off",
    },
    "expose_php": {
        "dangerous_value": "1",
        "severity": "low",
        "description": "Reveals PHP version in HTTP headers via X-Powered-By — aids attacker reconnaissance",
        "fix": "expose_php = Off",
    },
    "allow_url_fopen": {
        "dangerous_value": "1",
        "severity": "medium",
        "description": "Allows PHP to open remote URLs as files — can be abused for SSRF attacks",
        "fix": "allow_url_fopen = Off (may break some plugins)",
    },
    "register_globals": {
        "dangerous_value": "1",
        "severity": "critical",
        "description": "Injects request variables into global scope — removed in PHP 5.4 but may exist in custom builds",
        "fix": "register_globals = Off",
    },
    "session.cookie_httponly": {
        "dangerous_value": "",  # empty or 0 is dangerous
        "severity": "medium",
        "description": "Session cookies accessible via JavaScript — enables XSS session hijacking",
        "fix": "session.cookie_httponly = 1",
    },
    "session.cookie_secure": {
        "dangerous_value": "",  # empty or 0 is dangerous
        "severity": "medium",
        "description": "Session cookies sent over plain HTTP — enables session sniffing on shared networks",
        "fix": "session.cookie_secure = 1",
    },
    "open_basedir": {
        "dangerous_value": "",  # empty means unrestricted
        "severity": "high",
        "description": "PHP can read/write any file on the server — no filesystem isolation between sites",
        "fix": "open_basedir = /home/$USER/public_html:/tmp",
    },
    "disable_functions": {
        "dangerous_value": "",  # empty means all dangerous functions available
        "severity": "high",
        "description": "Dangerous shell functions (exec, system, passthru, shell_exec) are not disabled",
        "fix": "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source",
    },
}

# Dangerous PHP functions that should be disabled in production
DANGEROUS_PHP_FUNCTIONS = [
    "exec", "passthru", "shell_exec", "system", "proc_open",
    "popen", "curl_exec", "curl_multi_exec", "parse_ini_file",
    "show_source", "pcntl_exec",
]

# Suspicious patterns in wp_options that indicate injection
WP_OPTIONS_MALWARE_PATTERNS = [
    (r"<script[^>]*src=['\"]https?://[^'\"]*(?:\.ru|\.cn|\.tk|\.xyz|\.top|\.pw|\.bid|\.win|\.click)", "script_injection"),
    (r"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|strrev)", "obfuscated_code"),
    (r"document\.write\s*\(\s*unescape", "unescape_injection"),
    (r"window\.location\s*=\s*['\"]https?://(?!(?:www\.)?(?:google|facebook|twitter))", "redirect_malware"),
    (r"<iframe[^>]*style=['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)", "hidden_iframe"),
    (r"(?:viagra|cialis|casino|poker|xxx|porn|sex\s+toy)", "seo_spam"),
    (r"data:text/javascript;base64,", "base64_js_injection"),
    (r"String\.fromCharCode\s*\(.*(?:104|116|116|112)", "charcode_obfuscation"),
]

# Suspicious wp_cron entries
SUSPICIOUS_CRON_PATTERNS = [
    r"wp_update_plugins_\w{8,}",  # Random hash cron names
    r"wp_system_update_\w+",       # Fake "system update" crons
    r"file_get_contents\s*\(",     # Cron hooks that fetch remote files
    r"curl_exec\s*\(",             # Cron hooks that make HTTP requests
    r"eval\s*\(",                  # Cron hooks with eval
]


def _run_cmd(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a shell command and return result."""
    return subprocess.run(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, timeout=timeout,
    )


# ═══════════════════════════════════════════════════════════════════
# PHP Config Scanner
# ═══════════════════════════════════════════════════════════════════

class PHPConfigScanner:
    """Scans PHP configuration for dangerous settings and EOL versions."""

    def scan(self) -> List[dict]:
        """Run all PHP-level checks. Returns list of threat dicts."""
        threats = []
        threats.extend(self._check_php_version())
        threats.extend(self._check_php_settings())
        threats.extend(self._check_rogue_php_ini())
        threats.extend(self._check_disabled_functions())
        return threats

    def _check_php_version(self) -> List[dict]:
        """Check if PHP version is EOL."""
        threats = []
        try:
            result = _run_cmd("php -v 2>/dev/null | head -1")
            if result.returncode != 0:
                return threats

            match = re.search(r"PHP (\d+\.\d+)\.(\d+)", result.stdout)
            if not match:
                return threats

            major_minor = match.group(1)
            full_version = f"{major_minor}.{match.group(2)}"

            if major_minor in PHP_EOL_VERSIONS:
                eol_date = PHP_EOL_VERSIONS[major_minor]
                today = datetime.now().strftime("%Y-%m-%d")
                if today > eol_date:
                    threats.append({
                        "threat_type": "php_outdated",
                        "severity": "critical" if major_minor.startswith("5") else "high",
                        "title": f"PHP {full_version} is End-of-Life (EOL since {eol_date})",
                        "description": (
                            f"PHP {full_version} no longer receives security patches. "
                            f"Known vulnerabilities remain unpatched, exposing all sites to exploitation. "
                            f"Upgrade to PHP 8.2+ immediately."
                        ),
                        "location": _run_cmd("which php").stdout.strip(),
                        "evidence": {
                            "php_version": full_version,
                            "eol_date": eol_date,
                            "recommended": "8.2+",
                        },
                    })

            # Also check all PHP-FPM versions
            for php_bin in Path("/usr/bin").glob("php*"):
                if php_bin.name != "php" and re.match(r"php\d+\.\d+$", php_bin.name):
                    r = _run_cmd(f"{php_bin} -v 2>/dev/null | head -1")
                    m = re.search(r"PHP (\d+\.\d+)", r.stdout)
                    if m and m.group(1) in PHP_EOL_VERSIONS:
                        eol = PHP_EOL_VERSIONS[m.group(1)]
                        if datetime.now().strftime("%Y-%m-%d") > eol:
                            threats.append({
                                "threat_type": "php_outdated",
                                "severity": "medium",
                                "title": f"PHP {m.group(1)} binary still present (EOL since {eol})",
                                "description": f"Old PHP {m.group(1)} binary at {php_bin} should be removed.",
                                "location": str(php_bin),
                                "evidence": {"eol_date": eol},
                            })

        except Exception as exc:
            logger.warning("PHP version check failed: %s", exc)

        return threats

    def _check_php_settings(self) -> List[dict]:
        """Check php.ini for dangerous settings."""
        threats = []
        try:
            result = _run_cmd("php -i 2>/dev/null")
            if result.returncode != 0:
                return threats

            phpinfo = result.stdout

            for setting, config in DANGEROUS_PHP_SETTINGS.items():
                # Parse "setting => value => value" or "setting => value"
                pattern = re.compile(
                    rf"^{re.escape(setting)}\s*=>\s*(.+?)(?:\s*=>\s*(.+?))?$",
                    re.MULTILINE,
                )
                match = pattern.search(phpinfo)
                if not match:
                    # Setting not found — for some this IS the dangerous state
                    if setting in ("disable_functions", "open_basedir"):
                        current = "not set"
                        is_dangerous = True
                    else:
                        continue
                else:
                    current = (match.group(2) or match.group(1)).strip()
                    dangerous_val = config["dangerous_value"]

                    if dangerous_val == "":
                        # Empty means dangerous — check if current is empty/none
                        is_dangerous = current.lower() in ("", "no value", "off", "0", "none")
                        if setting == "disable_functions":
                            # Check if dangerous functions are NOT disabled
                            disabled = set(current.lower().replace(" ", "").split(",")) if current else set()
                            missing = [f for f in DANGEROUS_PHP_FUNCTIONS if f not in disabled]
                            is_dangerous = len(missing) > 3  # Allow a few
                            if is_dangerous:
                                config = dict(config)  # copy
                                config["description"] = (
                                    f"Dangerous functions not disabled: {', '.join(missing[:5])}{'...' if len(missing) > 5 else ''}"
                                )
                    else:
                        is_dangerous = current.strip().lower() in (dangerous_val, "on", "1", "yes")

                if is_dangerous:
                    threats.append({
                        "threat_type": "php_config_risk",
                        "severity": config["severity"],
                        "title": f"Dangerous PHP setting: {setting} = {current}",
                        "description": config["description"],
                        "location": _run_cmd("php -i 2>/dev/null | grep 'Loaded Configuration'").stdout.strip(),
                        "evidence": {
                            "setting": setting,
                            "current_value": current,
                            "recommended_fix": config["fix"],
                        },
                    })

        except Exception as exc:
            logger.warning("PHP settings check failed: %s", exc)

        return threats

    def _check_rogue_php_ini(self) -> List[dict]:
        """Find rogue php.ini / .user.ini files in web directories."""
        threats = []
        try:
            # Look for .user.ini or php.ini in public_html directories
            result = _run_cmd(
                "find /home/*/public_html -maxdepth 3 -name '.user.ini' -o -name 'php.ini' "
                "2>/dev/null | head -20",
                timeout=15,
            )
            for ini_path in result.stdout.strip().split("\n"):
                if not ini_path:
                    continue
                try:
                    content = Path(ini_path).read_text(errors="ignore")
                    # Check for dangerous overrides
                    if re.search(r"auto_prepend_file\s*=", content):
                        threats.append({
                            "threat_type": "php_config_risk",
                            "severity": "critical",
                            "title": f"Rogue PHP config with auto_prepend_file: {ini_path}",
                            "description": (
                                "A .user.ini or php.ini file is injecting PHP code via auto_prepend_file. "
                                "This is a common backdoor technique that executes malicious code on every request."
                            ),
                            "location": ini_path,
                            "evidence": {"content_snippet": content[:500]},
                        })
                    elif re.search(r"auto_append_file\s*=", content):
                        threats.append({
                            "threat_type": "php_config_risk",
                            "severity": "critical",
                            "title": f"Rogue PHP config with auto_append_file: {ini_path}",
                            "description": "auto_append_file injects code at the end of every PHP response.",
                            "location": ini_path,
                            "evidence": {"content_snippet": content[:500]},
                        })
                    elif re.search(r"allow_url_include\s*=\s*(?:1|On|on)", content):
                        threats.append({
                            "threat_type": "php_config_risk",
                            "severity": "critical",
                            "title": f"Rogue PHP config enabling allow_url_include: {ini_path}",
                            "description": "A web-accessible config file enables remote file inclusion.",
                            "location": ini_path,
                            "evidence": {"content_snippet": content[:500]},
                        })
                except (PermissionError, OSError):
                    continue

        except Exception as exc:
            logger.warning("Rogue PHP ini check failed: %s", exc)

        return threats

    def _check_disabled_functions(self) -> List[dict]:
        """Check if per-domain PHP configs override disable_functions."""
        threats = []
        try:
            # cPanel/WHM stores per-domain PHP configs
            for conf in Path("/usr/local/apache/conf/userdata/").rglob("*.conf"):
                try:
                    content = conf.read_text(errors="ignore")
                    if "disable_functions" in content and "none" in content.lower():
                        threats.append({
                            "threat_type": "php_config_risk",
                            "severity": "high",
                            "title": f"Per-domain PHP config disables function restrictions: {conf}",
                            "description": (
                                "This Apache user config overrides disable_functions, "
                                "giving this domain access to shell_exec, system, etc."
                            ),
                            "location": str(conf),
                            "evidence": {"content_snippet": content[:500]},
                        })
                except (PermissionError, OSError):
                    continue
        except FileNotFoundError:
            pass  # Not a cPanel server
        except Exception as exc:
            logger.warning("Per-domain PHP config check failed: %s", exc)

        return threats


# ═══════════════════════════════════════════════════════════════════
# MySQL Security Scanner
# ═══════════════════════════════════════════════════════════════════

class MySQLSecurityScanner:
    """Scans MySQL for rogue users, open access, and misconfigurations."""

    def scan(self) -> List[dict]:
        """Run all MySQL-level checks."""
        threats = []
        threats.extend(self._check_mysql_version())
        threats.extend(self._check_anonymous_users())
        threats.extend(self._check_remote_root())
        threats.extend(self._check_test_database())
        threats.extend(self._check_mysql_running_as_root())
        return threats

    def _check_mysql_version(self) -> List[dict]:
        """Check MySQL/MariaDB version for EOL."""
        threats = []
        try:
            result = _run_cmd("mysql --version 2>/dev/null")
            if result.returncode != 0:
                return threats

            version_str = result.stdout.strip()
            # MySQL EOL: 5.7 EOL Oct 2023, 8.0 EOL Apr 2026
            if re.search(r"mysql\s+Ver\s+.*5\.[0-6]\.", version_str, re.IGNORECASE):
                threats.append({
                    "threat_type": "mysql_config_risk",
                    "severity": "critical",
                    "title": f"MySQL 5.x is End-of-Life",
                    "description": f"Running: {version_str}. Upgrade to MySQL 8.0+ or MariaDB 10.6+.",
                    "location": "mysql",
                    "evidence": {"version": version_str},
                })
            # MariaDB EOL: 10.3 May 2023, 10.4 Jun 2024, 10.5 Jun 2025
            if re.search(r"MariaDB.*10\.[0-4]\.", version_str, re.IGNORECASE):
                threats.append({
                    "threat_type": "mysql_config_risk",
                    "severity": "high",
                    "title": f"MariaDB version is near or past End-of-Life",
                    "description": f"Running: {version_str}. Upgrade to MariaDB 10.6+ or 11.x.",
                    "location": "mysql",
                    "evidence": {"version": version_str},
                })

        except Exception as exc:
            logger.warning("MySQL version check failed: %s", exc)
        return threats

    def _check_anonymous_users(self) -> List[dict]:
        """Check for anonymous MySQL users (blank username)."""
        threats = []
        try:
            result = _run_cmd(
                "mysql -N -e \"SELECT User, Host FROM mysql.user WHERE User='' OR User IS NULL\" 2>/dev/null"
            )
            if result.returncode == 0 and result.stdout.strip():
                threats.append({
                    "threat_type": "mysql_rogue_user",
                    "severity": "high",
                    "title": "Anonymous MySQL users detected",
                    "description": (
                        "Anonymous (blank username) MySQL accounts allow anyone to connect without credentials. "
                        "Remove with: DROP USER ''@'localhost'; DROP USER ''@'%';"
                    ),
                    "location": "mysql.user",
                    "evidence": {"users": result.stdout.strip()},
                })
        except Exception as exc:
            logger.warning("Anonymous user check failed: %s", exc)
        return threats

    def _check_remote_root(self) -> List[dict]:
        """Check if MySQL root can connect from any host."""
        threats = []
        try:
            result = _run_cmd(
                "mysql -N -e \"SELECT Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')\" 2>/dev/null"
            )
            if result.returncode == 0 and result.stdout.strip():
                threats.append({
                    "threat_type": "mysql_config_risk",
                    "severity": "critical",
                    "title": "MySQL root has remote access enabled",
                    "description": (
                        f"Root can connect from: {result.stdout.strip()}. "
                        "This exposes the database to brute-force and credential stuffing attacks. "
                        "Restrict root to localhost only."
                    ),
                    "location": "mysql.user",
                    "evidence": {"remote_hosts": result.stdout.strip()},
                })
        except Exception as exc:
            logger.warning("Remote root check failed: %s", exc)
        return threats

    def _check_test_database(self) -> List[dict]:
        """Check for test databases that should be removed."""
        threats = []
        try:
            result = _run_cmd(
                "mysql -N -e \"SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name IN ('test', 'test_db')\" 2>/dev/null"
            )
            if result.returncode == 0 and result.stdout.strip():
                threats.append({
                    "threat_type": "mysql_config_risk",
                    "severity": "low",
                    "title": "Test database exists on production server",
                    "description": (
                        "The 'test' database is accessible by anonymous users by default. "
                        "Remove with: DROP DATABASE test;"
                    ),
                    "location": "mysql",
                    "evidence": {"databases": result.stdout.strip()},
                })
        except Exception as exc:
            logger.warning("Test database check failed: %s", exc)
        return threats

    def _check_mysql_running_as_root(self) -> List[dict]:
        """Check if MySQL daemon runs as root (should run as mysql user)."""
        threats = []
        try:
            result = _run_cmd("ps aux | grep -E 'mysql[d]' | awk '{print $1}' | head -1")
            if result.returncode == 0 and result.stdout.strip():
                user = result.stdout.strip()
                if user == "root":
                    threats.append({
                        "threat_type": "mysql_config_risk",
                        "severity": "critical",
                        "title": "MySQL/MariaDB running as root",
                        "description": (
                            "The database server is running as root. If MySQL is compromised, "
                            "the attacker has full root access to the entire server. "
                            "Configure MySQL to run as the 'mysql' user."
                        ),
                        "location": "mysqld process",
                        "evidence": {"running_as": user},
                    })
        except Exception as exc:
            logger.warning("MySQL process check failed: %s", exc)
        return threats


# ═══════════════════════════════════════════════════════════════════
# WordPress Database Scanner (per-site)
# ═══════════════════════════════════════════════════════════════════

class WPDatabaseDeepScanner:
    """Deep-scans WordPress database tables for injected content and abuse."""

    def scan_site(self, site_path: str, domain: str = "") -> List[dict]:
        """Run all WP database checks for a single site."""
        threats = []
        threats.extend(self._check_wp_options_injection(site_path, domain))
        threats.extend(self._check_wp_cron_abuse(site_path, domain))
        threats.extend(self._check_wp_users_suspicious(site_path, domain))
        threats.extend(self._check_wp_transient_malware(site_path, domain))
        return threats

    def _check_wp_options_injection(self, site_path: str, domain: str) -> List[dict]:
        """Scan wp_options for known malware patterns."""
        threats = []
        try:
            # Get siteurl and suspicious options in one shot
            result = _run_cmd(
                f"wp option list --fields=option_name,option_value --format=csv "
                f"--path={site_path} --allow-root 2>/dev/null | head -500"
            )
            if result.returncode != 0:
                return threats

            for line in result.stdout.split("\n"):
                for pattern, inject_type in WP_OPTIONS_MALWARE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        option_name = line.split(",")[0] if "," in line else "unknown"
                        threats.append({
                            "threat_type": "db_injection",
                            "severity": "critical",
                            "title": f"Malicious content in wp_options: {option_name} ({inject_type})",
                            "description": (
                                f"The wp_options table contains {inject_type} in option '{option_name}'. "
                                f"This affects all pages served by {domain or site_path}."
                            ),
                            "location": site_path,
                            "evidence": {
                                "option_name": option_name,
                                "injection_type": inject_type,
                                "snippet": line[:200],
                            },
                        })
                        break  # One match per line

        except Exception as exc:
            logger.warning("wp_options injection check failed for %s: %s", site_path, exc)
        return threats

    def _check_wp_cron_abuse(self, site_path: str, domain: str) -> List[dict]:
        """Check for suspicious wp-cron entries."""
        threats = []
        try:
            result = _run_cmd(
                f"wp cron event list --fields=hook,next_run --format=csv "
                f"--path={site_path} --allow-root 2>/dev/null"
            )
            if result.returncode != 0:
                return threats

            for line in result.stdout.split("\n"):
                for pattern in SUSPICIOUS_CRON_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        hook_name = line.split(",")[0] if "," in line else line.strip()
                        threats.append({
                            "threat_type": "wp_cron_abuse",
                            "severity": "high",
                            "title": f"Suspicious wp-cron job: {hook_name}",
                            "description": (
                                f"A WordPress cron job '{hook_name}' matches known malware patterns. "
                                "Attackers use wp-cron to maintain persistence and re-infect cleaned sites."
                            ),
                            "location": site_path,
                            "evidence": {"cron_hook": hook_name, "cron_line": line.strip()},
                        })
                        break

        except Exception as exc:
            logger.warning("wp-cron check failed for %s: %s", site_path, exc)
        return threats

    def _check_wp_users_suspicious(self, site_path: str, domain: str) -> List[dict]:
        """Check for recently created admin accounts that look suspicious."""
        threats = []
        try:
            result = _run_cmd(
                f"wp user list --role=administrator "
                f"--fields=ID,user_login,user_email,user_registered "
                f"--format=csv --path={site_path} --allow-root 2>/dev/null"
            )
            if result.returncode != 0:
                return threats

            suspicious_patterns = [
                r"^wp_?\d+$",           # wp_12345 (auto-generated names)
                r"^admin\d{3,}$",       # admin12345
                r"^[a-z]{2,4}\d{5,}$",  # ab12345
                r"@(?:mailinator|guerrillamail|tempmail|yopmail|throwaway)\.",  # Disposable emails
            ]

            for line in result.stdout.split("\n")[1:]:  # Skip header
                if not line.strip():
                    continue
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                user_id, username, email, registered = parts[0], parts[1], parts[2], parts[3]
                for pat in suspicious_patterns:
                    if re.search(pat, username, re.IGNORECASE) or re.search(pat, email, re.IGNORECASE):
                        threats.append({
                            "threat_type": "rogue_admin",
                            "severity": "critical",
                            "title": f"Suspicious admin account: {username} ({email})",
                            "description": (
                                f"Admin user '{username}' with email '{email}' matches known "
                                f"rogue admin patterns. Created: {registered}. Verify this is legitimate."
                            ),
                            "location": site_path,
                            "evidence": {
                                "user_id": user_id,
                                "username": username,
                                "email": email,
                                "registered": registered,
                            },
                        })
                        break

        except Exception as exc:
            logger.warning("WP user check failed for %s: %s", site_path, exc)
        return threats

    def _check_wp_transient_malware(self, site_path: str, domain: str) -> List[dict]:
        """Check for malware hidden in WordPress transients (DB-only, no file changes)."""
        threats = []
        try:
            # Transients with suspicious names or large values
            result = _run_cmd(
                f"wp db query \"SELECT option_name, LENGTH(option_value) as val_len "
                f"FROM $(wp db prefix --path={site_path} --allow-root 2>/dev/null)options "
                f"WHERE option_name LIKE '_transient_%' AND LENGTH(option_value) > 10000 "
                f"ORDER BY val_len DESC LIMIT 10\" "
                f"--path={site_path} --allow-root 2>/dev/null"
            )
            if result.returncode != 0:
                return threats

            for line in result.stdout.split("\n"):
                if "_transient_" in line and any(
                    suspicious in line.lower()
                    for suspicious in ["update_", "feed_", "rss_", "dash_"]
                ):
                    # Check if the transient content is suspicious
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        try:
                            size = int(parts[1])
                        except ValueError:
                            continue
                        if size > 50000:  # > 50KB transient is suspicious
                            threats.append({
                                "threat_type": "db_injection",
                                "severity": "medium",
                                "title": f"Unusually large transient: {name} ({size // 1024}KB)",
                                "description": (
                                    f"WordPress transient '{name}' is {size // 1024}KB. "
                                    "Attackers hide malware in transients to survive file-level cleanups."
                                ),
                                "location": site_path,
                                "evidence": {"transient_name": name, "size_bytes": size},
                            })

        except Exception as exc:
            logger.warning("Transient malware check failed for %s: %s", site_path, exc)
        return threats


# ═══════════════════════════════════════════════════════════════════
# Unified Stack Scanner
# ═══════════════════════════════════════════════════════════════════

class StackScanner:
    """Orchestrates all PHP, MySQL, and WP database-level scans."""

    def __init__(self):
        self.php_scanner = PHPConfigScanner()
        self.mysql_scanner = MySQLSecurityScanner()
        self.wp_db_scanner = WPDatabaseDeepScanner()

    def scan_server(self) -> List[dict]:
        """Run server-level PHP and MySQL checks."""
        threats = []
        logger.info("Starting PHP configuration scan...")
        threats.extend(self.php_scanner.scan())
        logger.info("PHP scan found %d issue(s). Starting MySQL scan...", len(threats))
        mysql_threats = self.mysql_scanner.scan()
        threats.extend(mysql_threats)
        logger.info("MySQL scan found %d issue(s).", len(mysql_threats))
        return threats

    def scan_site(self, site_path: str, domain: str = "") -> List[dict]:
        """Run per-site WordPress database deep scan."""
        logger.info("Deep scanning WP database for %s...", domain or site_path)
        threats = self.wp_db_scanner.scan_site(site_path, domain)
        logger.info("WP database scan found %d issue(s) for %s.", len(threats), domain or site_path)
        return threats
