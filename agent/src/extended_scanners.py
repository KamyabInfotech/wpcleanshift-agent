"""
CleanShift Extended Scanning Layers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Additional scanner layers for deeper WordPress security analysis.
Each scanner auto-detects the server's existing security stack
(Imunify360, CPGuard, CSF, ModSecurity, Fail2ban, CageFS, Cloudflare)
and adjusts severity/recommendations accordingly.

Layers:
    A: HtaccessScanner      — .htaccess malware & hijacking
    B: MuPluginScanner       — mu-plugins enumeration & analysis
    C: ImageScanner          — polyglot image / PHP-in-image detection
    D: ConfigScanner         — config exposure & hidden dotfiles
    F: SystemScanner         — cron, /tmp, SSH persistence
    G: NetworkScanner        — HTTP-level attack surface checks
    I: HardeningEngine       — security configuration recommendations

Design principle:
    Every scanner checks SecurityStack.detect() and notes when another
    system already covers a finding. Standalone servers get elevated
    severity and explicit hardening steps.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import shutil
import socket
import stat
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .models import (
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)

logger = logging.getLogger("cleanshift.extended")

# Re-use the progress callback type from the main scanner module
ProgressCallback = Optional[Callable[[str, str, int, int], None]]


# ─── Security Stack Detection ──────────────────────────────────────

@dataclass
class SecurityStack:
    """
    Auto-detected security systems present on the server.

    Each boolean flag indicates whether the corresponding system was
    found installed and (where detectable) running.  Scanners query
    this to annotate findings with 'also covered by: X' information
    and to adjust severity when standalone.
    """
    imunify360: bool = False
    cpguard: bool = False
    csf: bool = False
    modsecurity: bool = False
    fail2ban: bool = False
    cagefs: bool = False
    cloudflare: bool = False

    # Cache so we only detect once per process (thread-safe)
    _instance = None  # type: Optional[SecurityStack]
    _lock = threading.Lock()

    @classmethod
    def detect(cls):
        # type: () -> SecurityStack
        """Auto-detect which security systems are installed."""
        if cls._instance is not None:
            return cls._instance
        with cls._lock:
            # Double-check after acquiring lock
            if cls._instance is not None:
                return cls._instance

            # NOTE: Detection is filesystem-based (heuristic). An attacker with
            # code execution could plant decoy files to spoof security tools.
            # Future: verify tools are running via process list / service status.
            stack = cls()

            # Imunify360
            try:
                stack.imunify360 = (
                    os.path.exists("/etc/sysconfig/imunify360")
                    or os.path.exists("/usr/bin/imunify360-agent")
                    or shutil.which("imunify360-agent") is not None
                )
            except Exception:
                pass

            # CPGuard
            try:
                stack.cpguard = shutil.which("cpgcli") is not None
            except Exception:
                pass

            # CSF (ConfigServer Firewall)
            try:
                stack.csf = os.path.exists("/etc/csf/csf.conf")
            except Exception:
                pass

            # ModSecurity — check common module/config paths
            try:
                modsec_paths = [
                    "/etc/apache2/mods-enabled/security2.load",
                    "/etc/httpd/conf.d/mod_security.conf",
                    "/usr/local/apache/conf/modsec2.conf",
                    "/etc/modsecurity/modsecurity.conf",
                ]
                stack.modsecurity = any(os.path.exists(p) for p in modsec_paths)
            except Exception:
                pass

            # Fail2ban
            try:
                stack.fail2ban = shutil.which("fail2ban-client") is not None
            except Exception:
                pass

            # CageFS (CloudLinux)
            try:
                stack.cagefs = os.path.exists("/usr/sbin/cagefsctl")
            except Exception:
                pass

            # Cloudflare — difficult to detect without a domain; set later per-site
            stack.cloudflare = False

            cls._instance = stack
            logger.info(
                "Security stack detected: imunify360=%s cpguard=%s csf=%s "
                "modsec=%s fail2ban=%s cagefs=%s cloudflare=%s",
                stack.imunify360, stack.cpguard, stack.csf,
                stack.modsecurity, stack.fail2ban, stack.cagefs,
                stack.cloudflare,
            )
            return stack

    @classmethod
    def reset_cache(cls):
        # type: () -> None
        """Reset the cached instance (useful for testing)."""
        cls._instance = None

    def covers_malware_scanning(self):
        # type: () -> List[str]
        """Return names of systems that provide real-time malware scanning."""
        covers = []
        if self.imunify360:
            covers.append("Imunify360")
        if self.cpguard:
            covers.append("CPGuard")
        return covers

    def covers_firewall(self):
        # type: () -> List[str]
        """Return names of systems that provide firewall/WAF functionality."""
        covers = []
        if self.csf:
            covers.append("CSF")
        if self.modsecurity:
            covers.append("ModSecurity")
        if self.cloudflare:
            covers.append("Cloudflare WAF")
        return covers

    def covers_brute_force(self):
        # type: () -> List[str]
        """Return names of systems that provide brute-force protection."""
        covers = []
        if self.fail2ban:
            covers.append("Fail2ban")
        if self.csf:
            covers.append("CSF/LFD")
        if self.imunify360:
            covers.append("Imunify360")
        if self.cloudflare:
            covers.append("Cloudflare")
        return covers

    def is_standalone(self):
        # type: () -> bool
        """True if no external security system is detected."""
        return not any([
            self.imunify360, self.cpguard, self.csf,
            self.modsecurity, self.fail2ban, self.cagefs,
            self.cloudflare,
        ])

    def summary_text(self):
        # type: () -> str
        """Human-readable summary of detected security systems."""
        if self.is_standalone():
            return "No external security systems detected (standalone)"
        parts = []
        if self.imunify360:
            parts.append("Imunify360")
        if self.cpguard:
            parts.append("CPGuard")
        if self.csf:
            parts.append("CSF")
        if self.modsecurity:
            parts.append("ModSecurity")
        if self.fail2ban:
            parts.append("Fail2ban")
        if self.cagefs:
            parts.append("CageFS")
        if self.cloudflare:
            parts.append("Cloudflare")
        return "Active security: " + ", ".join(parts)


def _detect_cloudflare_for_domain(domain):
    # type: (str) -> bool
    """Check if a domain is proxied through Cloudflare by NS/header heuristic."""
    if not domain:
        return False
    # Strip protocol and path
    host = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        answers = socket.getaddrinfo(host, 80, socket.AF_INET)
        for _family, _type, _proto, _canonname, sockaddr in answers:
            ip = sockaddr[0]
            # Cloudflare IPv4 ranges (simplified check of common prefixes)
            cf_prefixes = [
                "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                "172.67.", "141.101.", "108.162.", "190.93.",
                "188.114.", "197.234.", "198.41.",
            ]
            for prefix in cf_prefixes:
                if ip.startswith(prefix):
                    return True
    except Exception:
        pass
    return False


def _safe_read_bytes(filepath, max_bytes=65536):
    # type: (Path, int) -> bytes
    """Read up to max_bytes from a file, returning empty bytes on error."""
    try:
        # Security: only follow symlinks to safe targets
        if os.path.islink(str(filepath)):
            target = os.path.realpath(str(filepath))
            # Always allow CageFS managed symlinks
            if '/.cagefs/' not in target:
                # Block symlinks to system directories
                _UNSAFE_TARGETS = ('/etc/', '/proc/', '/sys/', '/dev/', '/run/', '/boot/', '/root/')
                if any(target.startswith(p) for p in _UNSAFE_TARGETS):
                    return b''
        with open(str(filepath), "rb") as fh:
            return fh.read(max_bytes)
    except (OSError, IOError, PermissionError):
        return b""


def _covered_by_text(systems):
    # type: (List[str]) -> str
    """Format a 'covered by' annotation string."""
    if not systems:
        return ""
    return "Also covered by: " + ", ".join(systems)


def _adjust_severity(base, stack):
    # type: (Severity, SecurityStack) -> Severity
    """Lower severity by one level if another security system covers it."""
    if stack.is_standalone():
        return base
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    idx = order.index(base) if base in order else 0
    if idx < len(order) - 1:
        return order[idx + 1]
    return base


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer A: HtaccessScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class HtaccessScanner:
    """
    Scans all .htaccess files within a WordPress site for malicious
    directives: handler hijacks, SEO spam redirects, PHP engine
    enablement in uploads, and external-domain redirects.
    """

    # Patterns that indicate malicious .htaccess content
    _HANDLER_HIJACK = re.compile(
        rb"(?:SetHandler|AddType|AddHandler)\s+.{0,200}(?:php|application/x-httpd)",
        re.IGNORECASE,
    )
    _HANDLER_WHITELIST = re.compile(
        rb"AddHandler\s+application/x-httpd-(?:ea-)?php\d*(?:___[a-z0-9_-]+)?\s+(?:\.php\d*|\.phtml|\s+)+",
        re.IGNORECASE,
    )
    _AUTO_PREPEND = re.compile(
        rb"(?:auto_prepend_file|auto_append_file)\s*=",
        re.IGNORECASE,
    )
    _REFERER_REDIRECT = re.compile(
        rb"HTTP_REFERER.{0,500}RewriteRule.{0,200}\[R=30[12]\]",
        re.IGNORECASE,
    )
    _EXTERNAL_REDIRECT = re.compile(
        rb"RewriteRule\s+.{0,200}https?://(?!%\{HTTP_HOST\})",
        re.IGNORECASE,
    )
    _ERROR_DOC_EXTERNAL = re.compile(
        rb"ErrorDocument\s+\d+\s+https?://",
        re.IGNORECASE,
    )
    _PHP_ENGINE_ON = re.compile(
        rb"php_flag\s+engine\s+on",
        re.IGNORECASE,
    )

    def __init__(
        self,
        intel,         # type: Any
        progress_callback=None,  # type: ProgressCallback
    ):
        # type: (...) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Scan all .htaccess files in the site directory tree."""
        threats = []  # type: List[Threat]
        site_path = Path(site.path)
        if not site_path.exists():
            return threats

        self._emit_progress("htaccess_scan", "Searching for .htaccess files", 0, 1)

        htaccess_files = list(site_path.rglob(".htaccess"))
        total = len(htaccess_files)
        self._emit_progress("htaccess_scan", "Found %d .htaccess files" % total, 0, total)

        for idx, htfile in enumerate(htaccess_files):
            try:
                self._emit_progress("htaccess_scan", str(htfile.name), idx, total)
                threats.extend(self._analyze_htaccess(htfile, site_path, site))
            except Exception as exc:
                logger.warning("Error scanning %s: %s", htfile, exc)

        self._emit_progress("htaccess_scan", "Complete", total, total)
        logger.info("HtaccessScanner: %s — %d threats", site.path, len(threats))
        return threats

    def _analyze_htaccess(self, htfile, site_path, site):
        # type: (Path, Path, WordPressSite) -> List[Threat]
        threats = []  # type: List[Threat]
        content = _safe_read_bytes(htfile, max_bytes=32768)
        if not content:
            return threats

        rel = str(htfile.relative_to(site_path))
        in_uploads = "uploads" in rel.lower()

        # 1. SetHandler / AddType mapping images to PHP
        if self._HANDLER_HIJACK.search(content) and not self._is_legitimate_handler(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="Handler hijack in %s" % rel,
                description=(
                    ".htaccess maps non-PHP extensions to the PHP handler, "
                    "allowing attackers to execute uploaded files as PHP."
                ),
                location=str(htfile),
                evidence=self._extract_match(content, self._HANDLER_HIJACK),
                site_path=site.path,
                details={"check": "handler_hijack", "covered_by": _covered_by_text(self.stack.covers_malware_scanning())},
            ))

        # 2. auto_prepend_file / auto_append_file
        if self._AUTO_PREPEND.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="PHP auto_prepend/append in %s" % rel,
                description=(
                    ".htaccess sets auto_prepend_file or auto_append_file, "
                    "which silently includes a PHP file on every request."
                ),
                location=str(htfile),
                evidence=self._extract_match(content, self._AUTO_PREPEND),
                site_path=site.path,
                details={"check": "auto_prepend"},
            ))

        # 3. SEO spam redirects (HTTP_REFERER based)
        if self._REFERER_REDIRECT.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.HIGH,
                title="SEO spam redirect in %s" % rel,
                description=(
                    ".htaccess redirects visitors from search engines to a "
                    "spam or phishing site based on HTTP_REFERER."
                ),
                location=str(htfile),
                evidence=self._extract_match(content, self._REFERER_REDIRECT),
                site_path=site.path,
                details={"check": "seo_spam_redirect"},
            ))

        # 4. External domain redirects
        if self._EXTERNAL_REDIRECT.search(content):
            sev = _adjust_severity(Severity.HIGH, self.stack) if not in_uploads else Severity.HIGH
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=sev,
                title="External redirect in %s" % rel,
                description=".htaccess redirects traffic to an external domain.",
                location=str(htfile),
                evidence=self._extract_match(content, self._EXTERNAL_REDIRECT),
                site_path=site.path,
                details={"check": "external_redirect"},
            ))

        # 5. ErrorDocument to external URL
        if self._ERROR_DOC_EXTERNAL.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.MEDIUM,
                title="ErrorDocument external URL in %s" % rel,
                description="ErrorDocument directive points to an external URL.",
                location=str(htfile),
                evidence=self._extract_match(content, self._ERROR_DOC_EXTERNAL),
                site_path=site.path,
                details={"check": "error_doc_external"},
            ))

        # 6. php_flag engine on in uploads
        if in_uploads and self._PHP_ENGINE_ON.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="PHP engine enabled in uploads via %s" % rel,
                description=(
                    ".htaccess in the uploads directory enables PHP execution, "
                    "allowing any uploaded PHP file to run as code."
                ),
                location=str(htfile),
                evidence=self._extract_match(content, self._PHP_ENGINE_ON),
                site_path=site.path,
                details={"check": "php_engine_uploads"},
            ))

        # 7. Unusually large .htaccess (> 5KB)
        try:
            size = htfile.stat().st_size
        except OSError:
            size = len(content)
        if size > 5120:
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=Severity.MEDIUM,
                title="Oversized .htaccess: %s (%d bytes)" % (rel, size),
                description=(
                    ".htaccess file is larger than 5KB which is unusual "
                    "and may contain injected rules."
                ),
                location=str(htfile),
                evidence="File size: %d bytes" % size,
                site_path=site.path,
                details={"check": "oversized", "size_bytes": size},
            ))

        return threats

    @staticmethod
    def _extract_match(content, pattern, max_len=200):
        # type: (bytes, re.Pattern, int) -> str
        """Extract the first match of pattern from content as a string snippet."""
        m = pattern.search(content)
        if m:
            return m.group(0)[:max_len].decode("utf-8", errors="replace")
        return ""

    def _is_legitimate_handler(self, content):
        # type: (bytes) -> bool
        """Check if all handler directives in content are legitimate PHP handlers."""
        # Find all handler-related lines
        for line in content.split(b"\n"):
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            if self._HANDLER_HIJACK.search(line):
                # This line matches the hijack pattern — check if it's whitelisted
                if not self._HANDLER_WHITELIST.search(line):
                    return False  # Found a non-whitelisted handler directive
        return True  # All handler directives are legitimate


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer B: MuPluginScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class MuPluginScanner:
    """
    Scans wp-content/mu-plugins/ for suspicious or unexpected files.

    Must-use plugins auto-load on every request, making them a prime
    persistence mechanism for attackers. This scanner enumerates all
    files and applies obfuscation / dropper heuristics.
    """

    # Known hosting-provider mu-plugins that are legitimate and should
    # be skipped from deep analysis (glob-style matching on filename
    # or first directory component).
    _HOSTING_WHITELIST = [
        "wp-toolkit.php",
        "wp-toolkit/",
        "wpcleanshift-guard.php",
        "cleanshift-guard/",
        "cloudflare.php",
    ]  # type: List[str]

    # Prefix-based whitelist entries (matched with str.startswith)
    _HOSTING_WHITELIST_PREFIXES = (
        "imunify-security",
        "imunify360",
        "plesk-",
    )  # type: tuple

    # Dropper / loader patterns
    _DROPPER_PATTERNS = [
        re.compile(rb"file_get_contents\s*\(\s*['\"]https?://", re.IGNORECASE),
        re.compile(rb"wp_remote_get\s*\(", re.IGNORECASE),
        re.compile(rb"wp_remote_post\s*\(", re.IGNORECASE),
        re.compile(rb"curl_exec\s*\(", re.IGNORECASE),
        re.compile(rb"curl_init\s*\(", re.IGNORECASE),
        re.compile(rb"fsockopen\s*\(", re.IGNORECASE),
    ]

    # Suspicious DB option references (common malware persistence keys)
    _SUSPICIOUS_OPTIONS = [
        re.compile(rb"get_option\s*\(\s*['\"]_site_transient_", re.IGNORECASE),
        re.compile(rb"get_option\s*\(\s*['\"]wp_cd_[a-z]+", re.IGNORECASE),
        re.compile(rb"update_option\s*\(\s*['\"]_transient_feed_", re.IGNORECASE),
    ]

    # Obfuscation patterns reused from FileScanner
    _OBFUSCATION_PATTERNS = [
        re.compile(rb"base64_decode\s*\(", re.IGNORECASE),
        re.compile(rb"eval\s*\(", re.IGNORECASE),
        re.compile(rb"gzinflate\s*\(", re.IGNORECASE),
        re.compile(rb"str_rot13\s*\(", re.IGNORECASE),
        re.compile(rb"assert\s*\(", re.IGNORECASE),
        re.compile(rb"create_function\s*\(", re.IGNORECASE),
        re.compile(rb"chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)", re.IGNORECASE),
        re.compile(rb"preg_replace\s*\(\s*['\"]/.*/e", re.IGNORECASE),
    ]

    def __init__(self, intel, progress_callback=None):
        # type: (Any, ProgressCallback) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Scan the mu-plugins directory for suspicious files."""
        threats = []  # type: List[Threat]
        site_path = Path(site.path)
        mu_dir = site_path / "wp-content" / "mu-plugins"

        if not mu_dir.exists():
            self._emit_progress("mu_plugin_scan", "No mu-plugins directory", 0, 0)
            return threats

        self._emit_progress("mu_plugin_scan", "Enumerating mu-plugins", 0, 1)

        php_files = list(mu_dir.rglob("*.php"))
        total = len(php_files)

        for idx, php_file in enumerate(php_files):
            try:
                self._emit_progress("mu_plugin_scan", php_file.name, idx, total)
                rel = str(php_file.relative_to(site_path))

                # Skip our own guard files — they contain detection patterns
                # (eval, base64_decode, etc.) as signatures, not malware
                if "cleanshift-guard" in php_file.parts or php_file.name in ("wpcleanshift-guard.php", "wpcleanshift-security.php"):
                    logger.debug("Skipping own guard file: %s", php_file.name)
                    continue

                # Skip known hosting-provider mu-plugins entirely
                if self._is_hosting_whitelisted(php_file, mu_dir):
                    logger.debug("Skipping whitelisted hosting mu-plugin: %s", php_file.name)
                    threats.append(Threat(
                        threat_type=ThreatType.SUSPICIOUS_FILE,
                        severity=Severity.INFO,
                        title="Whitelisted hosting mu-plugin: %s" % php_file.name,
                        description=(
                            "Known hosting-provider mu-plugin detected. "
                            "This file is expected on managed hosting and "
                            "has been excluded from deep analysis."
                        ),
                        location=str(php_file),
                        evidence="Path: %s" % rel,
                        site_path=site.path,
                        details={"check": "mu_plugin_hosting_whitelist"},
                    ))
                    continue

                # 1. Report every PHP file present (mu-plugins should be known)
                threats.append(Threat(
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    severity=Severity.INFO,
                    title="mu-plugin found: %s" % php_file.name,
                    description=(
                        "Must-use plugin file auto-loads on every request. "
                        "Verify this is a legitimate, expected plugin."
                    ),
                    location=str(php_file),
                    evidence="Path: %s" % rel,
                    site_path=site.path,
                    details={"check": "mu_plugin_enumeration"},
                ))

                content = _safe_read_bytes(php_file, max_bytes=65536)
                if not content:
                    continue

                # 2. Obfuscated code check
                obf_matches = []
                for pat in self._OBFUSCATION_PATTERNS:
                    if pat.search(content):
                        obf_matches.append(pat.pattern.decode("utf-8", errors="replace"))
                if len(obf_matches) >= 2:
                    threats.append(Threat(
                        threat_type=ThreatType.BACKDOOR_FILE,
                        severity=Severity.CRITICAL,
                        title="Obfuscated mu-plugin: %s" % php_file.name,
                        description=(
                            "Must-use plugin contains %d obfuscation patterns. "
                            "This is a strong indicator of a backdoor." % len(obf_matches)
                        ),
                        location=str(php_file),
                        evidence="Patterns: %s" % ", ".join(obf_matches[:5]),
                        site_path=site.path,
                        details={
                            "check": "obfuscation",
                            "pattern_count": len(obf_matches),
                            "patterns": obf_matches,
                            "covered_by": _covered_by_text(self.stack.covers_malware_scanning()),
                        },
                    ))

                # 3. Dropper / loader patterns
                for pat in self._DROPPER_PATTERNS:
                    if pat.search(content):
                        threats.append(Threat(
                            threat_type=ThreatType.BACKDOOR_FILE,
                            severity=Severity.HIGH,
                            title="Dropper pattern in mu-plugin: %s" % php_file.name,
                            description=(
                                "Must-use plugin fetches remote content, which "
                                "may be used to download additional malware."
                            ),
                            location=str(php_file),
                            evidence=pat.pattern.decode("utf-8", errors="replace"),
                            site_path=site.path,
                            details={"check": "dropper_pattern"},
                        ))
                        break  # One dropper finding per file is enough

                # 4. Suspicious DB option key references
                for pat in self._SUSPICIOUS_OPTIONS:
                    if pat.search(content):
                        threats.append(Threat(
                            threat_type=ThreatType.BACKDOOR_FILE,
                            severity=Severity.HIGH,
                            title="Suspicious option key in mu-plugin: %s" % php_file.name,
                            description=(
                                "Must-use plugin references DB option keys commonly "
                                "used by malware for persistence."
                            ),
                            location=str(php_file),
                            evidence=pat.pattern.decode("utf-8", errors="replace"),
                            site_path=site.path,
                            details={"check": "suspicious_option_key"},
                        ))
                        break

            except Exception as exc:
                logger.warning("Error scanning mu-plugin %s: %s", php_file, exc)

        self._emit_progress("mu_plugin_scan", "Complete", total, total)
        logger.info("MuPluginScanner: %s — %d threats", site.path, len(threats))
        return threats

    def _is_hosting_whitelisted(self, php_file, mu_dir):
        # type: (Path, Path) -> bool
        """Check if a mu-plugin file matches the hosting-provider whitelist.

        Matches against:
        - Exact filenames (e.g. ``wp-toolkit.php``, ``cloudflare.php``)
        - Directory prefixes (e.g. files inside ``wp-toolkit/``)
        - Name prefixes (e.g. ``imunify-security*``, ``imunify360*``, ``plesk-*``)

        Returns:
            True if the file should be skipped from deep analysis.
        """
        name = php_file.name

        # Exact filename match
        if name in self._HOSTING_WHITELIST:
            return True

        # Check if file is inside a whitelisted directory
        try:
            rel_to_mu = php_file.relative_to(mu_dir)
            first_part = rel_to_mu.parts[0] if rel_to_mu.parts else ""
            # Directory entries end with '/' in the whitelist
            if (first_part + "/") in self._HOSTING_WHITELIST:
                return True
        except (ValueError, IndexError):
            pass

        # Prefix-based matching (imunify-security*, imunify360*, plesk-*)
        name_lower = name.lower()
        for prefix in self._HOSTING_WHITELIST_PREFIXES:
            if name_lower.startswith(prefix):
                return True

        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer C: ImageScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ImageScanner:
    """
    Detects PHP code embedded in image files (polyglot attacks).

    Checks JPEG, PNG, GIF, ICO, and SVG files for embedded PHP tags,
    script injections, and oversized .ico files that are likely webshells.
    """

    _PHP_OPEN_TAG = re.compile(rb"<\?php\b", re.IGNORECASE)
    _PHP_SHORT_TAG = re.compile(rb"<\?=", re.IGNORECASE)
    _SVG_SCRIPT = re.compile(rb"<script\b", re.IGNORECASE)
    _SVG_EVENT_HANDLER = re.compile(
        rb"\b(?:onload|onerror|onmouseover|onfocus|onclick)\s*=",
        re.IGNORECASE,
    )
    _IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".ico", ".bmp", ".webp"}
    _SVG_EXTENSIONS = {".svg"}
    _ICO_BACKDOOR_SIZE = 500 * 1024  # 500KB

    def __init__(self, intel, progress_callback=None):
        # type: (Any, ProgressCallback) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Scan image files in wp-content for embedded PHP."""
        threats = []  # type: List[Threat]
        site_path = Path(site.path)
        content_dir = site_path / "wp-content"

        if not content_dir.exists():
            return threats

        self._emit_progress("image_scan", "Collecting image files", 0, 1)

        image_files = []  # type: List[Path]
        svg_files = []    # type: List[Path]
        _MAX_FILES = 50000  # H1: prevent OOM on huge uploads dirs
        file_count = 0
        try:
            for fpath in content_dir.rglob("*"):
                file_count += 1
                if file_count > _MAX_FILES:
                    logger.warning(
                        "Image scan: hit %d file limit in %s — stopping enumeration",
                        _MAX_FILES, content_dir,
                    )
                    break
                if not fpath.is_file():
                    continue
                ext = fpath.suffix.lower()
                if ext in self._IMAGE_EXTENSIONS:
                    image_files.append(fpath)
                elif ext in self._SVG_EXTENSIONS:
                    svg_files.append(fpath)
        except (OSError, PermissionError):
            pass

        total = len(image_files) + len(svg_files)
        self._emit_progress("image_scan", "Scanning %d image files" % total, 0, total)

        # Scan raster images
        for idx, img in enumerate(image_files):
            try:
                if idx % 100 == 0:
                    self._emit_progress("image_scan", img.name, idx, total)
                threats.extend(self._scan_raster_image(img, site_path, site))
            except Exception as exc:
                logger.debug("Error scanning image %s: %s", img, exc)

        # Scan SVGs
        for idx, svg in enumerate(svg_files):
            try:
                self._emit_progress("image_scan", svg.name, len(image_files) + idx, total)
                threats.extend(self._scan_svg(svg, site_path, site))
            except Exception as exc:
                logger.debug("Error scanning SVG %s: %s", svg, exc)

        self._emit_progress("image_scan", "Complete", total, total)
        logger.info("ImageScanner: %s — %d threats", site.path, len(threats))
        return threats

    def _scan_raster_image(self, img, site_path, site):
        # type: (Path, Path, WordPressSite) -> List[Threat]
        threats = []  # type: List[Threat]
        rel = str(img.relative_to(site_path))

        try:
            file_size = img.stat().st_size
        except OSError:
            return threats

        # Check 1: Oversized .ico files (likely backdoor)
        if img.suffix.lower() == ".ico" and file_size > self._ICO_BACKDOOR_SIZE:
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="Oversized .ico file: %s" % rel,
                description=(
                    ".ico file is %d bytes (>500KB) which strongly suggests "
                    "it is a disguised PHP webshell." % file_size
                ),
                location=str(img),
                evidence="Size: %d bytes" % file_size,
                site_path=site.path,
                details={"check": "ico_oversized", "size_bytes": file_size},
            ))

        # Check 2: PHP tags in first 8KB of image
        # For `<?php`, any match is suspicious. For `<?=` (short tag),
        # require that it's followed by printable ASCII — random binary
        # data in JPEG/PNG streams frequently contains the bytes 0x3c3f3d
        # by coincidence and is NOT actual PHP injection.
        head = _safe_read_bytes(img, max_bytes=8192)
        _has_php_tag = head and self._PHP_OPEN_TAG.search(head)
        _has_real_short_tag = False
        if head and not _has_php_tag:
            for m in self._PHP_SHORT_TAG.finditer(head):
                after = head[m.end():m.end() + 8]
                # Real PHP: <?= followed by printable ASCII (space, letters, quotes, $)
                if after and sum(1 for b in after if 0x20 <= b <= 0x7e) >= 4:
                    _has_real_short_tag = True
                    break
        if _has_php_tag or _has_real_short_tag:
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="PHP code in image header: %s" % rel,
                description=(
                    "PHP tags found in the first 8KB of an image file. "
                    "This is a polyglot file that can execute as PHP."
                ),
                location=str(img),
                evidence="PHP tag detected in image header",
                site_path=site.path,
                details={
                    "check": "php_in_image_header",
                    "covered_by": _covered_by_text(self.stack.covers_malware_scanning()),
                },
            ))

        # Check 3: PHP code appended after image data (last 2KB)
        if file_size > 2048:
            try:
                with open(str(img), "rb") as fh:
                    fh.seek(max(0, file_size - 2048))
                    tail = fh.read(2048)
            except (OSError, IOError):
                tail = b""

            # Apply same short-tag validation as Check 2
            _tail_php = tail and self._PHP_OPEN_TAG.search(tail)
            _tail_short = False
            if tail and not _tail_php:
                for m in self._PHP_SHORT_TAG.finditer(tail):
                    after = tail[m.end():m.end() + 8]
                    if after and sum(1 for b in after if 0x20 <= b <= 0x7e) >= 4:
                        _tail_short = True
                        break
            if _tail_php or _tail_short:
                threats.append(Threat(
                    threat_type=ThreatType.BACKDOOR_FILE,
                    severity=Severity.CRITICAL,
                    title="PHP code appended to image: %s" % rel,
                    description=(
                        "PHP tags found in the last 2KB of an image file. "
                        "Code was appended after the image data."
                    ),
                    location=str(img),
                    evidence="PHP tag detected in image tail",
                    site_path=site.path,
                    details={"check": "php_in_image_tail"},
                ))

        # Check 4: EXIF comment containing PHP (JPEG only)
        if img.suffix.lower() in (".jpg", ".jpeg") and head:
            threats.extend(self._check_exif_php(img, head, rel, site))

        return threats

    def _check_exif_php(self, img, head, rel, site):
        # type: (Path, bytes, str, WordPressSite) -> List[Threat]
        """Check JPEG EXIF comment markers for embedded PHP."""
        threats = []  # type: List[Threat]
        # JPEG comment marker is FF FE followed by 2-byte length
        idx = 0
        while idx < len(head) - 4:
            if head[idx] == 0xFF and head[idx + 1] == 0xFE:
                # Comment segment found
                try:
                    comment_len = struct.unpack(">H", head[idx + 2:idx + 4])[0]
                    comment = head[idx + 4:idx + 4 + comment_len]
                    if self._PHP_OPEN_TAG.search(comment):
                        threats.append(Threat(
                            threat_type=ThreatType.BACKDOOR_FILE,
                            severity=Severity.HIGH,
                            title="PHP in EXIF comment: %s" % rel,
                            description="JPEG EXIF comment contains PHP code.",
                            location=str(img),
                            evidence="PHP tag in EXIF comment segment",
                            site_path=site.path,
                            details={"check": "exif_php_comment"},
                        ))
                        break
                except (struct.error, IndexError):
                    break
            idx += 1
        return threats

    def _scan_svg(self, svg, site_path, site):
        # type: (Path, Path, WordPressSite) -> List[Threat]
        """Scan SVG for script tags and event handlers."""
        threats = []  # type: List[Threat]
        rel = str(svg.relative_to(site_path))
        content = _safe_read_bytes(svg, max_bytes=65536)
        if not content:
            return threats

        if self._SVG_SCRIPT.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.HIGH,
                title="Script tag in SVG: %s" % rel,
                description="SVG file contains a <script> tag which can execute JavaScript.",
                location=str(svg),
                evidence="<script> tag found in SVG",
                site_path=site.path,
                details={"check": "svg_script"},
            ))

        if self._SVG_EVENT_HANDLER.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.HIGH,
                title="Event handler in SVG: %s" % rel,
                description="SVG file contains JavaScript event handlers (e.g. onload, onerror).",
                location=str(svg),
                evidence="Event handler attribute found in SVG",
                site_path=site.path,
                details={"check": "svg_event_handler"},
            ))

        # Also check for PHP in SVG
        if self._PHP_OPEN_TAG.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="PHP code in SVG: %s" % rel,
                description="SVG file contains PHP tags, making it a polyglot backdoor.",
                location=str(svg),
                evidence="PHP tag found in SVG file",
                site_path=site.path,
                details={"check": "svg_php"},
            ))

        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer D: ConfigScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ConfigScanner:
    """
    Scans for configuration exposures: dotfiles with PHP, .user.ini
    abuse, wp-config backup files, debug.log presence, dangerous
    permissions, and PHP in uploads.
    """

    _WP_CONFIG_BACKUP_EXTS = (
        ".bak", ".old", ".save", ".swp", ".orig", ".tmp",
        ".backup", ".copy", "~",
    )

    _PHP_TAG = re.compile(rb"<\?php\b", re.IGNORECASE)

    _AUTO_PREPEND_INI = re.compile(
        rb"(?:auto_prepend_file|auto_append_file)\s*=\s*\S+",
        re.IGNORECASE,
    )
    _ALLOW_URL_INCLUDE = re.compile(
        rb"allow_url_include\s*=\s*(?:on|1|true)",
        re.IGNORECASE,
    )

    def __init__(self, intel, progress_callback=None):
        # type: (Any, ProgressCallback) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Run all configuration exposure checks."""
        threats = []  # type: List[Threat]
        site_path = Path(site.path)
        if not site_path.exists():
            return threats

        self._emit_progress("config_scan", "Starting config checks", 0, 9)

        # 1. Dotfiles with PHP content
        self._emit_progress("config_scan", "Checking dotfiles", 1, 9)
        threats.extend(self._scan_dotfiles(site_path, site))

        # 2. .user.ini abuse
        self._emit_progress("config_scan", "Checking .user.ini", 2, 9)
        threats.extend(self._scan_user_ini(site_path, site))

        # 3. wp-config.php backup files
        self._emit_progress("config_scan", "Checking wp-config backups", 3, 9)
        threats.extend(self._scan_wp_config_backups(site_path, site))

        # 4. debug.log in webroot
        self._emit_progress("config_scan", "Checking debug.log", 4, 9)
        threats.extend(self._scan_debug_log(site_path, site))

        # 5. WP_DEBUG = true
        self._emit_progress("config_scan", "Checking WP_DEBUG", 5, 9)
        threats.extend(self._scan_wp_debug(site_path, site))

        # 6. Executable PHP files (chmod +x)
        self._emit_progress("config_scan", "Checking executable PHP", 6, 9)
        threats.extend(self._scan_executable_php(site_path, site))

        # 7. World-writable plugin/theme directories
        self._emit_progress("config_scan", "Checking directory permissions", 7, 9)
        threats.extend(self._scan_world_writable_dirs(site_path, site))

        # 8. wp-config.php permissions
        self._emit_progress("config_scan", "Checking wp-config permissions", 8, 9)
        threats.extend(self._scan_wp_config_perms(site_path, site))

        # 9. PHP files in uploads
        self._emit_progress("config_scan", "Checking PHP in uploads", 9, 9)
        threats.extend(self._scan_php_in_uploads(site_path, site))

        logger.info("ConfigScanner: %s — %d threats", site.path, len(threats))
        return threats

    def _scan_dotfiles(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Find dotfiles containing PHP code."""
        threats = []  # type: List[Threat]
        # Only scan top-level and wp-content for dotfiles
        search_dirs = [site_path, site_path / "wp-content"]
        for sdir in search_dirs:
            if not sdir.exists():
                continue
            try:
                for entry in sdir.iterdir():
                    if not entry.name.startswith("."):
                        continue
                    if not entry.is_file():
                        continue
                    if entry.name in (".htaccess", ".user.ini", ".htpasswd"):
                        continue  # Handled elsewhere
                    content = _safe_read_bytes(entry, max_bytes=8192)
                    if content and self._PHP_TAG.search(content):
                        rel = str(entry.relative_to(site_path))
                        threats.append(Threat(
                            threat_type=ThreatType.SUSPICIOUS_FILE,
                            severity=Severity.HIGH,
                            title="Dotfile with PHP: %s" % rel,
                            description="Hidden dotfile contains PHP code, likely a backdoor.",
                            location=str(entry),
                            evidence="PHP tag found in dotfile",
                            site_path=site.path,
                            details={"check": "dotfile_php"},
                        ))
            except (OSError, PermissionError):
                continue
        return threats

    def _scan_user_ini(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Check .user.ini for auto_prepend_file or allow_url_include."""
        threats = []  # type: List[Threat]
        user_ini = site_path / ".user.ini"
        if not user_ini.exists():
            return threats

        content = _safe_read_bytes(user_ini, max_bytes=4096)
        if not content:
            return threats

        if self._AUTO_PREPEND_INI.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title=".user.ini auto_prepend_file injection",
                description=(
                    ".user.ini sets auto_prepend_file which silently includes "
                    "a PHP file on every request to this directory."
                ),
                location=str(user_ini),
                evidence=self._AUTO_PREPEND_INI.search(content).group(0).decode("utf-8", errors="replace"),
                site_path=site.path,
                details={"check": "user_ini_prepend"},
            ))

        if self._ALLOW_URL_INCLUDE.search(content):
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title=".user.ini allows remote file inclusion",
                description=(
                    ".user.ini enables allow_url_include which permits "
                    "including PHP files from remote URLs."
                ),
                location=str(user_ini),
                evidence="allow_url_include=on",
                site_path=site.path,
                details={"check": "user_ini_url_include"},
            ))

        return threats

    def _scan_wp_config_backups(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Find backup copies of wp-config.php that leak credentials."""
        threats = []  # type: List[Threat]
        try:
            for entry in site_path.iterdir():
                if not entry.is_file():
                    continue
                name = entry.name
                if not name.startswith("wp-config"):
                    continue
                if name == "wp-config.php":
                    continue
                # Check for backup extensions
                is_backup = False
                for ext in self._WP_CONFIG_BACKUP_EXTS:
                    if name.endswith(ext):
                        is_backup = True
                        break
                if not is_backup and name == "wp-config.php~":
                    is_backup = True
                if is_backup:
                    threats.append(Threat(
                        threat_type=ThreatType.SUSPICIOUS_FILE,
                        severity=Severity.CRITICAL,
                        title="wp-config.php backup file: %s" % name,
                        description=(
                            "A backup of wp-config.php is publicly accessible. "
                            "It contains database credentials and secret keys."
                        ),
                        location=str(entry),
                        evidence="Backup file: %s" % name,
                        site_path=site.path,
                        details={"check": "wp_config_backup"},
                    ))
        except (OSError, PermissionError):
            pass
        return threats

    def _scan_debug_log(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Check for debug.log in webroot or wp-content."""
        threats = []  # type: List[Threat]
        for log_path in [site_path / "debug.log", site_path / "wp-content" / "debug.log"]:
            if log_path.exists():
                try:
                    size = log_path.stat().st_size
                except OSError:
                    size = 0
                rel = str(log_path.relative_to(site_path))
                threats.append(Threat(
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    severity=Severity.MEDIUM,
                    title="Debug log exposed: %s" % rel,
                    description=(
                        "WordPress debug log is present and may be publicly "
                        "accessible. It can leak sensitive paths, queries, and errors."
                    ),
                    location=str(log_path),
                    evidence="Size: %d bytes" % size,
                    site_path=site.path,
                    details={"check": "debug_log", "size_bytes": size},
                ))
        return threats

    def _scan_wp_debug(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Check if WP_DEBUG is enabled in wp-config.php."""
        threats = []  # type: List[Threat]
        wp_config = site_path / "wp-config.php"
        if not wp_config.exists():
            return threats
        content = _safe_read_bytes(wp_config, max_bytes=16384)
        if not content:
            return threats
        # Match define('WP_DEBUG', true) with various quote styles
        debug_pat = re.compile(
            rb"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)",
            re.IGNORECASE,
        )
        if debug_pat.search(content):
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=Severity.MEDIUM,
                title="WP_DEBUG is enabled in production",
                description=(
                    "WP_DEBUG is set to true in wp-config.php. In production "
                    "this exposes detailed error messages and file paths."
                ),
                location=str(wp_config),
                evidence="define('WP_DEBUG', true)",
                site_path=site.path,
                details={"check": "wp_debug_enabled"},
            ))
        return threats

    def _scan_executable_php(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Find PHP files with executable permission (chmod +x)."""
        threats = []  # type: List[Threat]
        # Spot-check key directories
        for rel_dir in [".", "wp-admin", "wp-includes", "wp-content"]:
            check_dir = site_path / rel_dir if rel_dir != "." else site_path
            if not check_dir.exists():
                continue
            try:
                for php_file in check_dir.glob("*.php"):
                    mode = php_file.stat().st_mode
                    if mode & stat.S_IXUSR or mode & stat.S_IXGRP or mode & stat.S_IXOTH:
                        rel = str(php_file.relative_to(site_path))
                        threats.append(Threat(
                            threat_type=ThreatType.PERMISSION_ISSUE,
                            severity=Severity.LOW,
                            title="Executable PHP: %s" % rel,
                            description="PHP file has executable permission which is unnecessary.",
                            location=str(php_file),
                            evidence="Permissions: %s" % oct(mode)[-3:],
                            site_path=site.path,
                            details={"check": "executable_php", "permissions": oct(mode)[-3:]},
                        ))
            except (OSError, PermissionError):
                continue
        return threats

    def _scan_world_writable_dirs(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Check plugin and theme directories for world-writable permissions."""
        threats = []  # type: List[Threat]
        check_dirs = [
            site_path / "wp-content" / "plugins",
            site_path / "wp-content" / "themes",
            site_path / "wp-content" / "uploads",
        ]
        for cdir in check_dirs:
            if not cdir.exists():
                continue
            try:
                # Check the top-level directory and immediate subdirectories
                dirs_to_check = [cdir]
                for sub in cdir.iterdir():
                    if sub.is_dir():
                        dirs_to_check.append(sub)
                for dpath in dirs_to_check:
                    mode = dpath.stat().st_mode
                    if mode & stat.S_IWOTH:
                        rel = str(dpath.relative_to(site_path))
                        threats.append(Threat(
                            threat_type=ThreatType.PERMISSION_ISSUE,
                            severity=Severity.MEDIUM,
                            title="World-writable directory: %s" % rel,
                            description="Directory is writable by all users on the server.",
                            location=str(dpath),
                            evidence="Permissions: %s" % oct(mode)[-3:],
                            site_path=site.path,
                            details={"check": "world_writable", "permissions": oct(mode)[-3:]},
                        ))
            except (OSError, PermissionError):
                continue
        return threats

    def _scan_wp_config_perms(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Check wp-config.php for overly permissive file permissions."""
        threats = []  # type: List[Threat]
        wp_config = site_path / "wp-config.php"
        if not wp_config.exists():
            return threats
        try:
            mode = wp_config.stat().st_mode
            if mode & stat.S_IROTH:
                threats.append(Threat(
                    threat_type=ThreatType.PERMISSION_ISSUE,
                    severity=Severity.HIGH,
                    title="wp-config.php is world-readable",
                    description=(
                        "wp-config.php contains database credentials and salt "
                        "keys. It should not be readable by other system users."
                    ),
                    location=str(wp_config),
                    evidence="Permissions: %s" % oct(mode)[-3:],
                    site_path=site.path,
                    details={
                        "check": "wp_config_permissions",
                        "current": oct(mode)[-3:],
                        "recommended": "600",
                        "covered_by": _covered_by_text(
                            ["CageFS"] if self.stack.cagefs else []
                        ),
                    },
                ))
        except (OSError, PermissionError):
            pass
        return threats

    def _scan_php_in_uploads(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Enhanced scan for PHP files in wp-content/uploads/."""
        threats = []  # type: List[Threat]
        uploads = site_path / "wp-content" / "uploads"
        if not uploads.exists():
            return threats
        php_extensions = (".php", ".php5", ".php7", ".phtml", ".phar", ".phps")
        _MAX_FILES = 50000
        file_count = 0
        try:
            for fpath in uploads.rglob("*"):
                file_count += 1
                if file_count > _MAX_FILES:
                    logger.warning(
                        "PHP-in-uploads scan: hit %d file limit in %s",
                        _MAX_FILES, uploads,
                    )
                    break
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in php_extensions:
                    continue
                # Skip legitimate index.php placeholders
                if fpath.name == "index.php":
                    content = _safe_read_bytes(fpath, max_bytes=256)
                    if len(content) < 100:
                        continue
                try:
                    size = fpath.stat().st_size
                except OSError:
                    size = 0
                rel = str(fpath.relative_to(site_path))
                threats.append(Threat(
                    threat_type=ThreatType.BACKDOOR_FILE,
                    severity=Severity.HIGH,
                    title="PHP in uploads: %s" % rel,
                    description=(
                        "PHP file found in the uploads directory. "
                        "Uploads should never contain executable PHP."
                    ),
                    location=str(fpath),
                    evidence="Size: %d bytes, Extension: %s" % (size, fpath.suffix),
                    site_path=site.path,
                    details={
                        "check": "php_in_uploads",
                        "size_bytes": size,
                        "extension": fpath.suffix,
                    },
                ))
        except (OSError, PermissionError):
            pass
        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer F: SystemScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SystemScanner:
    """
    Scans server-level persistence mechanisms: crontabs, /tmp scripts,
    /dev/shm, shell RC files, SSH keys, /tmp mount options, and
    symlinks pointing outside the home directory.
    """

    _SHELL_DOWNLOAD_PAT = re.compile(
        rb"(?:curl|wget|lwp-download|fetch)\s+.*https?://",
        re.IGNORECASE,
    )
    _SHELL_EVAL_PAT = re.compile(
        rb"\beval\b.*\$\(",
        re.IGNORECASE,
    )

    def __init__(self, intel, progress_callback=None):
        # type: (Any, ProgressCallback) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Run all system-level persistence checks."""
        threats = []  # type: List[Threat]
        site_path = Path(site.path)

        self._emit_progress("system_scan", "Starting system checks", 0, 8)

        # Determine user from site path ownership
        user = site.site_owner or self._detect_user(site_path)

        # 1. User crontab
        self._emit_progress("system_scan", "Checking crontab", 1, 8)
        threats.extend(self._scan_crontab(user, site))

        # 2. /etc/cron.d/ referencing the user
        self._emit_progress("system_scan", "Checking /etc/cron.d/", 2, 8)
        threats.extend(self._scan_cron_d(user, site))

        # 3. PHP scripts in /tmp/
        self._emit_progress("system_scan", "Checking /tmp/ scripts", 3, 8)
        threats.extend(self._scan_tmp_scripts(user, site))

        # 4. Scripts in /dev/shm/
        self._emit_progress("system_scan", "Checking /dev/shm/", 4, 8)
        threats.extend(self._scan_dev_shm(user, site))

        # 5. Shell RC files
        self._emit_progress("system_scan", "Checking shell RC files", 5, 8)
        threats.extend(self._scan_shell_rc(user, site))

        # 6. SSH authorized_keys
        self._emit_progress("system_scan", "Checking SSH keys", 6, 8)
        threats.extend(self._scan_ssh_keys(user, site))

        # 7. /tmp noexec check
        self._emit_progress("system_scan", "Checking /tmp mount options", 7, 8)
        threats.extend(self._scan_tmp_noexec(site))

        # 8. Symlinks pointing outside home
        self._emit_progress("system_scan", "Checking for suspicious symlinks", 8, 8)
        threats.extend(self._scan_symlinks(site_path, site))

        logger.info("SystemScanner: %s — %d threats", site.path, len(threats))
        return threats

    def _detect_user(self, site_path):
        # type: (Path) -> str
        """Detect the system user owning a site directory."""
        # Primary: use file ownership (works on both cPanel and Plesk)
        try:
            import pwd
            st = os.stat(str(site_path))
            return pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, OSError, ImportError):
            pass
        # Fallback: infer from path structure
        parts = site_path.parts if isinstance(site_path, Path) else Path(site_path).parts
        if "home" in parts:
            idx = parts.index("home")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        if "vhosts" in parts:
            idx = parts.index("vhosts")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return ""

    def _scan_crontab(self, user, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Read user crontab directly from spool."""
        threats = []  # type: List[Threat]
        if not user:
            return threats

        cron_paths = [
            "/var/spool/cron/%s" % user,
            "/var/spool/cron/crontabs/%s" % user,
        ]
        for cron_path in cron_paths:
            content = _safe_read_bytes(Path(cron_path), max_bytes=32768)
            if not content:
                continue

            lines = content.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Check for suspicious downloads or eval
                line_bytes = stripped.encode("utf-8", errors="replace")
                if self._SHELL_DOWNLOAD_PAT.search(line_bytes):
                    threats.append(Threat(
                        threat_type=ThreatType.BACKDOOR_FILE,
                        severity=Severity.CRITICAL,
                        title="Suspicious cron entry for user: %s" % user,
                        description=(
                            "Crontab contains a download command (curl/wget) "
                            "which may fetch and execute malware."
                        ),
                        location=cron_path,
                        evidence=stripped[:200],
                        site_path=site.path,
                        details={
                            "check": "crontab_download",
                            "user": user,
                            "covered_by": _covered_by_text(self.stack.covers_malware_scanning()),
                        },
                    ))
                if self._SHELL_EVAL_PAT.search(line_bytes):
                    threats.append(Threat(
                        threat_type=ThreatType.BACKDOOR_FILE,
                        severity=Severity.CRITICAL,
                        title="Eval in crontab for user: %s" % user,
                        description="Crontab entry uses eval to execute dynamically generated code.",
                        location=cron_path,
                        evidence=stripped[:200],
                        site_path=site.path,
                        details={"check": "crontab_eval", "user": user},
                    ))
        return threats

    def _scan_cron_d(self, user, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check /etc/cron.d/ files that reference the site user."""
        threats = []  # type: List[Threat]
        if not user:
            return threats
        cron_d = Path("/etc/cron.d")
        if not cron_d.exists():
            return threats
        try:
            for cronfile in cron_d.iterdir():
                if not cronfile.is_file():
                    continue
                content = _safe_read_bytes(cronfile, max_bytes=16384)
                if not content:
                    continue
                text = content.decode("utf-8", errors="replace")
                if user in text:
                    # Check if the line also has suspicious content
                    for line in text.splitlines():
                        if user not in line:
                            continue
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        line_bytes = stripped.encode("utf-8", errors="replace")
                        if self._SHELL_DOWNLOAD_PAT.search(line_bytes):
                            threats.append(Threat(
                                threat_type=ThreatType.BACKDOOR_FILE,
                                severity=Severity.HIGH,
                                title="Suspicious /etc/cron.d entry referencing %s" % user,
                                description="System cron file references user and contains download commands.",
                                location=str(cronfile),
                                evidence=stripped[:200],
                                site_path=site.path,
                                details={"check": "cron_d_download", "user": user, "file": cronfile.name},
                            ))
        except (OSError, PermissionError):
            pass
        return threats

    def _scan_tmp_scripts(self, user, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Find PHP scripts in /tmp/ owned by the user."""
        threats = []  # type: List[Threat]
        tmp_dir = Path("/tmp")
        if not tmp_dir.exists():
            return threats
        try:
            for fpath in tmp_dir.iterdir():
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in (".php", ".php5", ".php7", ".phtml"):
                    continue
                # Check ownership if user is known
                if user:
                    try:
                        fstat = os.stat(str(fpath))
                        import pwd
                        owner = pwd.getpwuid(fstat.st_uid).pw_name
                        if owner != user:
                            continue
                    except Exception:
                        pass
                threats.append(Threat(
                    threat_type=ThreatType.BACKDOOR_FILE,
                    severity=Severity.HIGH,
                    title="PHP script in /tmp: %s" % fpath.name,
                    description="PHP script found in /tmp which is a common attacker staging area.",
                    location=str(fpath),
                    evidence="Owner: %s" % user if user else "Unknown owner",
                    site_path=site.path,
                    details={"check": "tmp_php_script", "user": user},
                ))
        except (OSError, PermissionError):
            pass
        return threats

    def _scan_dev_shm(self, user, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Find scripts in /dev/shm/ (RAM-backed, survives some cleanups)."""
        threats = []  # type: List[Threat]
        shm = Path("/dev/shm")
        if not shm.exists():
            return threats
        try:
            for fpath in shm.iterdir():
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() in (".php", ".sh", ".pl", ".py"):
                    threats.append(Threat(
                        threat_type=ThreatType.BACKDOOR_FILE,
                        severity=Severity.HIGH,
                        title="Script in /dev/shm: %s" % fpath.name,
                        description=(
                            "Executable script found in /dev/shm (shared memory). "
                            "Attackers use this to hide scripts that survive /tmp cleanups."
                        ),
                        location=str(fpath),
                        evidence="File: %s" % fpath.name,
                        site_path=site.path,
                        details={"check": "dev_shm_script"},
                    ))
        except (OSError, PermissionError):
            pass
        return threats

    def _scan_shell_rc(self, user, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check .bashrc / .bash_profile for curl/wget/eval."""
        threats = []  # type: List[Threat]
        if not user:
            return threats
        try:
            import pwd
            home = pwd.getpwnam(user).pw_dir
        except (KeyError, ImportError):
            # Fallback to common paths
            for base in ["/home", "/var/www/vhosts"]:
                candidate = os.path.join(base, user)
                if os.path.isdir(candidate):
                    home = candidate
                    break
            else:
                return threats
        home_dir = Path(home)
        if not home_dir.exists():
            return threats

        rc_files = [".bashrc", ".bash_profile", ".profile", ".bash_login"]
        for rc_name in rc_files:
            rc_path = home_dir / rc_name
            if not rc_path.exists():
                continue
            content = _safe_read_bytes(rc_path, max_bytes=16384)
            if not content:
                continue
            if self._SHELL_DOWNLOAD_PAT.search(content) or self._SHELL_EVAL_PAT.search(content):
                threats.append(Threat(
                    threat_type=ThreatType.BACKDOOR_FILE,
                    severity=Severity.CRITICAL,
                    title="Malicious shell RC: %s" % rc_name,
                    description=(
                        "Shell initialization file contains download or eval "
                        "commands that execute on every login."
                    ),
                    location=str(rc_path),
                    evidence=content[:200].decode("utf-8", errors="replace"),
                    site_path=site.path,
                    details={"check": "shell_rc_injection", "user": user, "file": rc_name},
                ))
        return threats

    def _scan_ssh_keys(self, user, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check for unauthorized SSH authorized_keys."""
        threats = []  # type: List[Threat]
        if not user:
            return threats
        try:
            import pwd
            home = pwd.getpwnam(user).pw_dir
        except (KeyError, ImportError):
            for base in ["/home", "/var/www/vhosts"]:
                candidate = os.path.join(base, user)
                if os.path.isdir(candidate):
                    home = candidate
                    break
            else:
                return threats
        ssh_dir = Path(home) / ".ssh"
        auth_keys = ssh_dir / "authorized_keys"
        if not auth_keys.exists():
            return threats
        content = _safe_read_bytes(auth_keys, max_bytes=32768)
        if not content:
            return threats

        lines = content.decode("utf-8", errors="replace").splitlines()
        key_count = 0
        suspicious_keys = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key_count += 1
            # Flag keys with command= prefix (forced command backdoor)
            if stripped.startswith("command=") or "no-pty" in stripped:
                suspicious_keys.append(stripped[:100])

        if suspicious_keys:
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.CRITICAL,
                title="SSH authorized_keys with forced commands",
                description=(
                    "authorized_keys file contains keys with 'command=' prefixes. "
                    "These force-execute a specific command on SSH login and are "
                    "used as backdoors."
                ),
                location=str(auth_keys),
                evidence="%d suspicious keys found" % len(suspicious_keys),
                site_path=site.path,
                details={
                    "check": "ssh_forced_command",
                    "user": user,
                    "total_keys": key_count,
                    "suspicious_count": len(suspicious_keys),
                },
            ))

        # General info: report key count
        if key_count > 0:
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=Severity.INFO,
                title="SSH authorized_keys: %d key(s) for %s" % (key_count, user),
                description="Listing SSH authorized_keys for review.",
                location=str(auth_keys),
                evidence="%d key(s)" % key_count,
                site_path=site.path,
                details={"check": "ssh_key_audit", "user": user, "key_count": key_count},
            ))

        return threats

    def _scan_tmp_noexec(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Check if /tmp is mounted without noexec."""
        threats = []  # type: List[Threat]
        proc_mounts = Path("/proc/mounts")
        if not proc_mounts.exists():
            return threats
        content = _safe_read_bytes(proc_mounts, max_bytes=65536)
        if not content:
            return threats

        text = content.decode("utf-8", errors="replace")
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                options = parts[3]
                if "noexec" not in options:
                    sev = _adjust_severity(Severity.MEDIUM, self.stack)
                    threats.append(Threat(
                        threat_type=ThreatType.PERMISSION_ISSUE,
                        severity=sev,
                        title="/tmp is mounted without noexec",
                        description=(
                            "/tmp partition is executable, allowing attackers to "
                            "run uploaded scripts directly from /tmp."
                        ),
                        location="/tmp",
                        evidence="Mount options: %s" % options,
                        site_path=site.path,
                        details={
                            "check": "tmp_noexec",
                            "mount_options": options,
                            "covered_by": _covered_by_text(
                                ["CageFS"] if self.stack.cagefs else []
                            ),
                        },
                    ))
                break
        return threats

    def _scan_symlinks(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Find symlinks pointing outside the site's home directory."""
        threats = []  # type: List[Threat]
        # Determine the home boundary
        home_boundary = str(site_path)

        # Only scan key directories to avoid performance issues
        scan_dirs = [
            site_path,
            site_path / "wp-content",
        ]
        for sdir in scan_dirs:
            if not sdir.exists():
                continue
            try:
                for entry in sdir.iterdir():
                    if entry.is_symlink():
                        try:
                            target = str(entry.resolve())
                        except (OSError, RuntimeError):
                            continue
                        if not target.startswith(home_boundary):
                            rel = str(entry.relative_to(site_path))

                            # CageFS symlinks are CloudLinux infrastructure
                            is_cagefs = (
                                "/.cagefs/opt/alt/" in target
                                or "/.cagefs/opt/lve/" in target
                                or "/.cagefs/opt/alt/" in str(entry)
                                or "/.cagefs/opt/lve/" in str(entry)
                            )
                            if is_cagefs:
                                severity = Severity.INFO
                                desc = (
                                    "Symlink is managed by CageFS (CloudLinux). "
                                    "This is expected infrastructure and not a "
                                    "security threat."
                                )
                                logger.debug(
                                    "CageFS symlink downgraded to INFO: %s -> %s",
                                    rel, target,
                                )
                            else:
                                severity = Severity.HIGH
                                desc = (
                                    "Symlink points to '%s' which is outside "
                                    "the site directory. This may be used to read "
                                    "other users' files." % target
                                )

                            threats.append(Threat(
                                threat_type=ThreatType.SUSPICIOUS_FILE,
                                severity=severity,
                                title="Symlink escapes site root: %s" % rel,
                                description=desc,
                                location=str(entry),
                                evidence="Target: %s" % target,
                                site_path=site.path,
                                details={
                                    "check": "symlink_escape",
                                    "target": target,
                                    "cagefs_managed": is_cagefs,
                                    "covered_by": _covered_by_text(
                                        ["CageFS"] if self.stack.cagefs else []
                                    ),
                                },
                            ))
            except (OSError, PermissionError):
                continue
        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer G: NetworkScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class NetworkScanner:
    """
    Checks the HTTP-level attack surface of a WordPress site:
    REST API user enumeration, XML-RPC, wp-config.php / debug.log
    web access, and directory listing.

    Uses only urllib.request (no external dependencies). All requests
    have a 5-second timeout and the scanner degrades gracefully if the
    site is unreachable.
    """

    _REQUEST_TIMEOUT = 5  # seconds

    def __init__(self, intel, progress_callback=None):
        # type: (Any, ProgressCallback) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Run HTTP-level attack surface checks."""
        threats = []  # type: List[Threat]
        base_url = site.domain
        if not base_url:
            logger.info("NetworkScanner: No domain configured, skipping")
            return threats

        # Normalize URL
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        base_url = base_url.rstrip("/")

        host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

        # Single DNS resolution for both reachability and SSRF protection
        try:
            resolved_addrs = socket.getaddrinfo(host, 80, socket.AF_INET)
        except socket.gaierror:
            logger.info("NetworkScanner: Cannot resolve %s, skipping", host)
            return threats

        # SSRF protection: reject loopback and link-local IPs
        for _, _, _, _, sockaddr in resolved_addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_loopback or ip.is_link_local:
                logger.warning(
                    'SSRF protection: refusing to scan %s (resolves to %s)',
                    host, ip,
                )
                return threats

        # Detect Cloudflare for this domain (track locally, don't mutate shared singleton)
        cf_detected = _detect_cloudflare_for_domain(host)
        if cf_detected:
            logger.info("Cloudflare detected for domain %s", host)

        self._emit_progress("network_scan", "Checking REST API", 1, 5)
        threats.extend(self._check_rest_api_users(base_url, site))

        self._emit_progress("network_scan", "Checking XML-RPC", 2, 5)
        threats.extend(self._check_xmlrpc(base_url, site))

        self._emit_progress("network_scan", "Checking wp-config.php access", 3, 5)
        threats.extend(self._check_wp_config_access(base_url, site))

        self._emit_progress("network_scan", "Checking debug.log access", 4, 5)
        threats.extend(self._check_debug_log_access(base_url, site))

        self._emit_progress("network_scan", "Checking directory listing", 5, 5)
        threats.extend(self._check_directory_listing(base_url, site))

        logger.info("NetworkScanner: %s — %d threats", site.path, len(threats))
        return threats

    def _http_get(self, url):
        # type: (str) -> Optional[tuple]
        """
        Perform an HTTP GET request. Returns (status_code, body_snippet) or None.
        """
        try:
            import urllib.request
            import urllib.error
            import ssl

            # NOTE: SSL verification intentionally disabled for security scanning.
            # We're probing the site's own endpoints to detect exposed files,
            # not transmitting sensitive data. Many shared hosting sites have
            # self-signed or expired certs that would block legitimate scans.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={"User-Agent": "CleanShift/1.0"})
            response = urllib.request.urlopen(req, timeout=self._REQUEST_TIMEOUT, context=ctx)
            body = response.read(4096)
            return (response.getcode(), body.decode("utf-8", errors="replace"))
        except Exception as exc:
            # Return status code for HTTP errors (403, 404, etc.)
            code = getattr(exc, 'code', None)
            if code is not None:
                return (code, "")
        return None

    def _http_status(self, url):
        # type: (str) -> int
        """Return just the HTTP status code, or 0 on failure."""
        try:
            import urllib.request
            import urllib.error
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CleanShift/1.0"},
                method="HEAD",
            )
            response = urllib.request.urlopen(req, timeout=self._REQUEST_TIMEOUT, context=ctx)
            return response.getcode()
        except Exception as exc:
            # Try to extract status from HTTPError
            code = getattr(exc, "code", 0)
            if code:
                return code
            return 0

    def _check_rest_api_users(self, base_url, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check if /wp-json/wp/v2/users/ exposes usernames."""
        threats = []  # type: List[Threat]
        url = base_url + "/wp-json/wp/v2/users/"
        result = self._http_get(url)
        if result is None:
            return threats

        status, body = result
        if status == 200 and '"slug"' in body:
            sev = _adjust_severity(Severity.MEDIUM, self.stack)
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=sev,
                title="REST API exposes user list",
                description=(
                    "The WordPress REST API at /wp-json/wp/v2/users/ is publicly "
                    "accessible and returns user slugs. Attackers use this for "
                    "brute-force username enumeration."
                ),
                location=url,
                evidence="HTTP 200 with user data",
                site_path=site.path,
                details={
                    "check": "rest_api_users",
                    "covered_by": _covered_by_text(self.stack.covers_brute_force()),
                },
            ))
        return threats

    def _check_xmlrpc(self, base_url, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check if xmlrpc.php is accessible."""
        threats = []  # type: List[Threat]
        url = base_url + "/xmlrpc.php"
        status = self._http_status(url)
        if status in (200, 405):
            # 200 or 405 (Method Not Allowed for HEAD) means it's active
            sev = _adjust_severity(Severity.MEDIUM, self.stack)
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=sev,
                title="XML-RPC is enabled",
                description=(
                    "xmlrpc.php is accessible. It can be used for brute-force "
                    "amplification attacks (system.multicall) and DDoS pingback."
                ),
                location=url,
                evidence="HTTP status: %d" % status,
                site_path=site.path,
                details={
                    "check": "xmlrpc_enabled",
                    "covered_by": _covered_by_text(self.stack.covers_brute_force()),
                },
            ))
        return threats

    def _check_wp_config_access(self, base_url, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check if wp-config.php is downloadable via HTTP."""
        threats = []  # type: List[Threat]
        url = base_url + "/wp-config.php"
        result = self._http_get(url)
        if result is None:
            return threats

        status, body = result
        # If we get a 200 and body contains DB credentials patterns, it's bad
        if status == 200 and ("DB_NAME" in body or "DB_PASSWORD" in body):
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=Severity.CRITICAL,
                title="wp-config.php accessible via web",
                description=(
                    "wp-config.php is being served as plain text via HTTP, "
                    "exposing database credentials and secret keys."
                ),
                location=url,
                evidence="HTTP 200 with DB credential patterns",
                site_path=site.path,
                details={"check": "wp_config_web_access"},
            ))
        return threats

    def _check_debug_log_access(self, base_url, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check if debug.log is accessible via HTTP."""
        threats = []  # type: List[Threat]
        urls = [
            base_url + "/wp-content/debug.log",
            base_url + "/debug.log",
        ]
        for url in urls:
            result = self._http_get(url)
            if result is None:
                continue
            status, body = result
            if status == 200 and ("PHP" in body or "Stack trace" in body or "Warning" in body):
                threats.append(Threat(
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    severity=Severity.MEDIUM,
                    title="debug.log accessible via web",
                    description=(
                        "WordPress debug log is publicly downloadable. "
                        "It may contain sensitive file paths, SQL queries, and errors."
                    ),
                    location=url,
                    evidence="HTTP 200 with debug content",
                    site_path=site.path,
                    details={"check": "debug_log_web_access"},
                ))
                break  # One finding is enough
        return threats

    def _check_directory_listing(self, base_url, site):
        # type: (str, WordPressSite) -> List[Threat]
        """Check if directory listing is enabled on /wp-content/uploads/."""
        threats = []  # type: List[Threat]
        url = base_url + "/wp-content/uploads/"
        result = self._http_get(url)
        if result is None:
            return threats

        status, body = result
        if status == 200 and ("Index of" in body or "Parent Directory" in body):
            sev = _adjust_severity(Severity.MEDIUM, self.stack)
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=sev,
                title="Directory listing enabled on uploads",
                description=(
                    "The /wp-content/uploads/ directory has directory listing "
                    "enabled, allowing anyone to browse uploaded files."
                ),
                location=url,
                evidence="HTTP 200 with directory listing HTML",
                site_path=site.path,
                details={
                    "check": "directory_listing",
                    "covered_by": _covered_by_text(self.stack.covers_firewall()),
                },
            ))
        return threats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Layer I: HardeningEngine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class HardeningEngine:
    """
    Checks WordPress security configuration and produces hardening
    recommendations. Does NOT auto-modify files — each finding
    includes details about whether an auto-fix is available and what
    command would apply it.

    Severity is adjusted based on SecurityStack: if another system
    already covers a check, severity is lowered to INFO/LOW.
    """

    _DEFAULT_SALTS = [
        b"put your unique phrase here",
        b"define( 'AUTH_KEY',",
    ]

    def __init__(self, intel, progress_callback=None):
        # type: (Any, ProgressCallback) -> None
        self.intel = intel
        self.progress_callback = progress_callback
        self.stack = SecurityStack.detect()

    def _emit_progress(self, phase, detail, current=0, total=0):
        # type: (str, str, int, int) -> None
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Run all hardening checks and return recommendations."""
        threats = []  # type: List[Threat]
        site_path = Path(site.path)

        self._emit_progress("hardening", "Starting hardening checks", 0, 12)

        # Read wp-config.php once for multiple checks
        wp_config_content = b""
        wp_config_path = site_path / "wp-config.php"
        if wp_config_path.exists():
            wp_config_content = _safe_read_bytes(wp_config_path, max_bytes=32768)

        # 1. Salt keys
        self._emit_progress("hardening", "Checking salt keys", 1, 12)
        threats.extend(self._check_salts(wp_config_content, wp_config_path, site))

        # 2. FORCE_SSL_ADMIN
        self._emit_progress("hardening", "Checking FORCE_SSL_ADMIN", 2, 12)
        threats.extend(self._check_define(
            wp_config_content, wp_config_path, site,
            b"FORCE_SSL_ADMIN", "true",
            "FORCE_SSL_ADMIN not set",
            "Admin login does not enforce HTTPS, exposing credentials on insecure networks.",
            Severity.MEDIUM,
            "wp config set FORCE_SSL_ADMIN true --raw",
        ))

        # 3. DISALLOW_FILE_EDIT
        self._emit_progress("hardening", "Checking DISALLOW_FILE_EDIT", 3, 12)
        threats.extend(self._check_define(
            wp_config_content, wp_config_path, site,
            b"DISALLOW_FILE_EDIT", "true",
            "DISALLOW_FILE_EDIT not set",
            (
                "The WordPress dashboard theme/plugin editor is enabled. "
                "Attackers with admin access can inject backdoors through it."
            ),
            Severity.MEDIUM,
            "wp config set DISALLOW_FILE_EDIT true --raw",
        ))

        # 4. DISALLOW_UNFILTERED_HTML
        self._emit_progress("hardening", "Checking DISALLOW_UNFILTERED_HTML", 4, 12)
        threats.extend(self._check_define(
            wp_config_content, wp_config_path, site,
            b"DISALLOW_UNFILTERED_HTML", "true",
            "DISALLOW_UNFILTERED_HTML not set",
            "Administrators and editors can post unfiltered HTML, enabling stored XSS.",
            Severity.LOW,
            "wp config set DISALLOW_UNFILTERED_HTML true --raw",
        ))

        # 5. siteurl/home use HTTPS
        self._emit_progress("hardening", "Checking HTTPS usage", 5, 12)
        threats.extend(self._check_https_urls(site))

        # 6. Default 'admin' username
        self._emit_progress("hardening", "Checking default admin username", 6, 12)
        threats.extend(self._check_default_admin(site))

        # 7. XML-RPC hardening
        self._emit_progress("hardening", "XML-RPC recommendation", 7, 12)
        threats.extend(self._recommend_xmlrpc(site))

        # 8. User enumeration hardening
        self._emit_progress("hardening", "User enumeration recommendation", 8, 12)
        threats.extend(self._recommend_user_enum(site))

        # 9. Directory listing hardening
        self._emit_progress("hardening", "Directory listing recommendation", 9, 12)
        threats.extend(self._recommend_directory_listing(site))

        # 10. open_basedir check
        self._emit_progress("hardening", "Checking open_basedir", 10, 12)
        threats.extend(self._check_open_basedir(site_path, site))

        # 11. Application passwords check (requires DB)
        self._emit_progress("hardening", "Checking application passwords", 11, 12)
        threats.extend(self._check_application_passwords(site))

        # 12. Excessive active sessions (requires DB)
        self._emit_progress("hardening", "Checking active sessions", 12, 12)
        threats.extend(self._check_excessive_sessions(site))

        logger.info("HardeningEngine: %s — %d recommendations", site.path, len(threats))
        return threats

    def _check_salts(self, content, config_path, site):
        # type: (bytes, Path, WordPressSite) -> List[Threat]
        """Verify WP salt keys are unique and not defaults."""
        threats = []  # type: List[Threat]
        if not content:
            return threats

        for default_salt in self._DEFAULT_SALTS:
            if default_salt in content:
                threats.append(Threat(
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    severity=Severity.HIGH,
                    title="WordPress salt keys are default/empty",
                    description=(
                        "wp-config.php uses default salt values. This weakens "
                        "cookie and nonce security significantly."
                    ),
                    location=str(config_path),
                    evidence="Default salt phrase detected",
                    site_path=site.path,
                    details={
                        "check": "default_salts",
                        "auto_fix_available": True,
                        "fix_command": "wp config shuffle-salts",
                    },
                ))
                break  # One finding is enough
        return threats

    def _check_define(self, content, config_path, site, const_name,
                      expected_val, title, description, severity, fix_cmd):
        # type: (bytes, Path, WordPressSite, bytes, str, str, str, Severity, str) -> List[Threat]
        """Check if a wp-config.php define() constant is set to the expected value."""
        threats = []  # type: List[Threat]
        if not content:
            return threats

        # Build a regex to find define('CONST_NAME', ...)
        pattern = re.compile(
            rb"define\s*\(\s*['\"]" + re.escape(const_name) + rb"['\"]\s*,\s*(\w+)\s*\)",
            re.IGNORECASE,
        )
        match = pattern.search(content)
        if match:
            val = match.group(1).decode("utf-8", errors="replace").lower()
            if val == expected_val.lower():
                return threats  # Already set correctly

        # Constant not set or not set to expected value
        effective_sev = severity
        covered = []  # type: List[str]
        if const_name == b"FORCE_SSL_ADMIN" and self.stack.cloudflare:
            covered.append("Cloudflare (flexible SSL)")
            effective_sev = _adjust_severity(severity, self.stack)
        if self.stack.is_standalone():
            # Elevate severity for standalone systems
            order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            idx = order.index(severity) if severity in order else 2
            if idx < len(order) - 1:
                effective_sev = order[idx + 1]

        threats.append(Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=effective_sev,
            title=title,
            description=description,
            location=str(config_path),
            evidence="Constant %s not set to %s" % (
                const_name.decode("utf-8", errors="replace"), expected_val
            ),
            site_path=site.path,
            details={
                "check": "wp_config_define",
                "constant": const_name.decode("utf-8", errors="replace"),
                "auto_fix_available": True,
                "fix_command": fix_cmd,
                "covered_by": _covered_by_text(covered),
            },
        ))
        return threats

    def _check_https_urls(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Check if siteurl/home use HTTPS."""
        threats = []  # type: List[Threat]
        domain = site.domain or ""
        if domain and domain.startswith("http://"):
            sev = Severity.MEDIUM if self.stack.is_standalone() else Severity.LOW
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=sev,
                title="Site URL uses HTTP instead of HTTPS",
                description=(
                    "The site URL uses plain HTTP. All traffic including login "
                    "credentials is transmitted unencrypted."
                ),
                location="Site option: siteurl",
                evidence="URL: %s" % domain,
                site_path=site.path,
                details={
                    "check": "https_siteurl",
                    "auto_fix_available": True,
                    "fix_command": "wp option update siteurl '%s'" % domain.replace("http://", "https://"),
                    "covered_by": _covered_by_text(
                        ["Cloudflare"] if self.stack.cloudflare else []
                    ),
                },
            ))
        return threats

    def _check_default_admin(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Flag if a user with login 'admin' exists (requires DB query via site info)."""
        threats = []  # type: List[Threat]
        # We can only check this if we have DB access; for now emit a
        # recommendation to check manually or via the DatabaseScanner
        # This is a lightweight heuristic based on site metadata
        threats.append(Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=Severity.LOW,
            title="Check for default 'admin' username",
            description=(
                "The default 'admin' username is a well-known target for "
                "brute-force attacks. Verify no account uses this login."
            ),
            location="Database: %susers" % site.db_prefix,
            evidence="Recommendation — verify via DB scan",
            site_path=site.path,
            details={
                "check": "default_admin_username",
                "auto_fix_available": False,
                "fix_command": "wp user update admin --user_login=<new_name> (manual rename required)",
                "covered_by": _covered_by_text(self.stack.covers_brute_force()),
            },
        ))
        return threats

    def _recommend_xmlrpc(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Recommend disabling XML-RPC if no protection exists."""
        sev = Severity.LOW if not self.stack.is_standalone() else Severity.MEDIUM
        return [Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=sev,
            title="Recommendation: Disable XML-RPC",
            description=(
                "XML-RPC enables brute-force amplification and DDoS pingback "
                "attacks. Disable it unless required by Jetpack or mobile apps."
            ),
            location="xmlrpc.php",
            evidence="Hardening recommendation",
            site_path=site.path,
            details={
                "check": "xmlrpc_hardening",
                "auto_fix_available": True,
                "fix_command": (
                    "Add to .htaccess: <Files xmlrpc.php>\\n"
                    "  Require all denied\\n</Files>"
                ),
                "covered_by": _covered_by_text(self.stack.covers_brute_force()),
            },
        )]

    def _recommend_user_enum(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Recommend blocking REST API user enumeration."""
        sev = Severity.LOW if not self.stack.is_standalone() else Severity.MEDIUM
        return [Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=sev,
            title="Recommendation: Block user enumeration",
            description=(
                "The REST API exposes usernames at /wp-json/wp/v2/users/. "
                "Block unauthenticated access to prevent username harvesting."
            ),
            location="/wp-json/wp/v2/users/",
            evidence="Hardening recommendation",
            site_path=site.path,
            details={
                "check": "user_enum_hardening",
                "auto_fix_available": True,
                "fix_command": (
                    "Add filter: add_filter('rest_authentication_errors', "
                    "function($result) { if (!is_user_logged_in()) { "
                    "return new WP_Error('rest_forbidden', '', "
                    "array('status' => 401)); } return $result; });"
                ),
                "covered_by": _covered_by_text(self.stack.covers_firewall()),
            },
        )]

    def _recommend_directory_listing(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Recommend disabling directory listing."""
        sev = Severity.LOW if not self.stack.is_standalone() else Severity.MEDIUM
        return [Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=sev,
            title="Recommendation: Disable directory listing",
            description=(
                "Directory listing may expose uploaded files and site structure. "
                "Add Options -Indexes to .htaccess."
            ),
            location=".htaccess",
            evidence="Hardening recommendation",
            site_path=site.path,
            details={
                "check": "directory_listing_hardening",
                "auto_fix_available": True,
                "fix_command": "Add to .htaccess: Options -Indexes",
                "covered_by": _covered_by_text(self.stack.covers_firewall()),
            },
        )]

    def _check_open_basedir(self, site_path, site):
        # type: (Path, WordPressSite) -> List[Threat]
        """Check if open_basedir is set via .user.ini."""
        threats = []  # type: List[Threat]
        user_ini = site_path / ".user.ini"
        has_open_basedir = False

        if user_ini.exists():
            content = _safe_read_bytes(user_ini, max_bytes=4096)
            if content and b"open_basedir" in content:
                has_open_basedir = True

        if not has_open_basedir and not self.stack.cagefs:
            sev = Severity.LOW if not self.stack.is_standalone() else Severity.MEDIUM
            threats.append(Threat(
                threat_type=ThreatType.SUSPICIOUS_FILE,
                severity=sev,
                title="open_basedir not configured",
                description=(
                    "PHP open_basedir is not set, allowing PHP scripts to "
                    "read files anywhere on the filesystem."
                ),
                location=str(user_ini),
                evidence="open_basedir not found in .user.ini",
                site_path=site.path,
                details={
                    "check": "open_basedir",
                    "auto_fix_available": True,
                    "fix_command": (
                        "Add to .user.ini: open_basedir=%s:/tmp" % str(site_path)
                    ),
                    "covered_by": _covered_by_text(
                        ["CageFS"] if self.stack.cagefs else []
                    ),
                },
            ))
        return threats

    def _check_application_passwords(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Flag if application passwords exist (requires DB access via wp-cli)."""
        threats = []  # type: List[Threat]
        # We note the recommendation; actual DB check would be done by DatabaseScanner
        threats.append(Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=Severity.INFO,
            title="Audit application passwords",
            description=(
                "WordPress application passwords provide API access that "
                "bypasses 2FA. Review usermeta for _application_passwords entries."
            ),
            location="Database: %susermeta" % site.db_prefix,
            evidence="Hardening recommendation — verify via DB scan",
            site_path=site.path,
            details={
                "check": "application_passwords",
                "auto_fix_available": False,
                "fix_command": "wp user application-password list <user_id>",
            },
        ))
        return threats

    def _check_excessive_sessions(self, site):
        # type: (WordPressSite) -> List[Threat]
        """Flag recommendation to audit active sessions."""
        threats = []  # type: List[Threat]
        threats.append(Threat(
            threat_type=ThreatType.SUSPICIOUS_FILE,
            severity=Severity.INFO,
            title="Audit active user sessions",
            description=(
                "Excessive active sessions (>5 per user) may indicate stolen "
                "credentials or session hijacking. Review usermeta session_tokens."
            ),
            location="Database: %susermeta" % site.db_prefix,
            evidence="Hardening recommendation — verify via DB scan",
            site_path=site.path,
            details={
                "check": "excessive_sessions",
                "auto_fix_available": True,
                "fix_command": "wp user session destroy <user_id> --all",
            },
        ))
        return threats
