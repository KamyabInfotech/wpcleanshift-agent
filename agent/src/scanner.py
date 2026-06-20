"""
CleanShift Scanning Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Multi-layered scanning engine that detects malware, backdoors, rogue
admin accounts, script injections, vulnerable plugins, and core file
tampering. Each scanner layer is independent and produces Threat objects.

Architecture:
    ServerScanner
      └─ SiteScanner (per WordPress site)
           ├─ FileScanner         — filesystem-level threats
           ├─ DatabaseScanner     — database-level threats
           ├─ PluginAuditor       — known vulnerable plugins
           ├─ CoreIntegrityChecker — core file tampering
           ├─ YaraScanner         — YARA signature detection (optional)
           └─ VulnScanner         — CVE database lookup (optional)

Production hardening:
    - Per-file scan timeout (default 30s)
    - Total scan timeout per site (default 600s)
    - Memory usage guard (abort if >512MB RSS)
    - Progress callback logging
    - Dynamic IOC-based backdoor filename detection
    - SHA256 computation for all flagged files
    - Scan modes: 'quick' (known IOCs only) vs 'deep' (full pattern scan)
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
try:
    import resource
    _RESOURCE_AVAILABLE = True
except ImportError:
    _RESOURCE_AVAILABLE = False
import stat
import subprocess
import signal
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

try:
    import pymysql
    _PYMYSQL_AVAILABLE = True
except ImportError:
    _PYMYSQL_AVAILABLE = False
    logger = logging.getLogger("cleanshift.scanner")
    logger.debug('pymysql not available — database scanning disabled')

from .intelligence import IntelligenceDB, DetectionQuery
from .models import (
    NonWPSite,
    ScanResult,
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)
from .wp import build_site_info, discover_wp_sites, run_wp_cli

logger = logging.getLogger("cleanshift.scanner")


# ─── Scan Modes ─────────────────────────────────────────────────────

class ScanMode(str, Enum):
    """Controls scan depth and performance trade-offs."""
    QUICK = "quick"  # Known IOCs only — fast, low resource usage
    DEEP = "deep"    # Full pattern scan + heuristics — thorough


# ─── Timeout / Resource Exceptions ──────────────────────────────────

class FileScanTimeout(Exception):
    """Raised when a single file scan exceeds the per-file timeout."""
    pass


class SiteScanTimeout(Exception):
    """Raised when total scan time for a site exceeds the limit."""
    pass


class MemoryLimitExceeded(Exception):
    """Raised when process RSS exceeds the configured memory guard."""
    pass


# ─── Progress Callback Type ────────────────────────────────────────

# progress_callback(phase: str, detail: str, current: int, total: int)
ProgressCallback = Optional[Callable[[str, str, int, int], None]]


# Directories that symlinks should never point to (prevents reading system files)
_UNSAFE_SYMLINK_TARGETS = ('/etc/', '/proc/', '/sys/', '/dev/', '/run/', '/boot/', '/root/')

# ─── CPU / IO Throttling ───────────────────────────────────────────

_NICE_APPLIED = False

def _apply_nice_priority() -> None:
    """Lower process CPU and I/O priority (idempotent)."""
    global _NICE_APPLIED
    if _NICE_APPLIED:
        return
    try:
        os.nice(10)  # Lower CPU priority
    except (OSError, PermissionError):
        pass
    try:
        subprocess.run(
            ['ionice', '-c', '3', '-p', str(os.getpid())],
            capture_output=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass  # ionice not available on this system
    _NICE_APPLIED = True


def _throttle_if_overloaded(
    max_load_per_cpu: float = 2.0,
    pause_seconds: float = 5.0,
    max_pauses: int = 12,
) -> None:
    """Pause scanning if 1-min load average exceeds threshold.

    Prevents the scanner from overloading shared hosting servers
    with 200+ sites. Will pause up to max_pauses times (60s total
    at default settings) before giving up and continuing.
    """
    cpu_count = os.cpu_count() or 1
    for _ in range(max_pauses):
        try:
            load_1min = os.getloadavg()[0]
        except (OSError, AttributeError):
            return  # getloadavg not available (e.g. Windows)
        if load_1min / cpu_count <= max_load_per_cpu:
            return
        logger.info(
            "System load %.1f (%.1f/cpu) exceeds threshold %.1f — pausing %ds",
            load_1min, load_1min / cpu_count, max_load_per_cpu, pause_seconds,
        )
        time.sleep(pause_seconds)

def _cpu_throttle(batch_size: int = 50, current_idx: int = 0) -> None:
    """Strictly throttle CPU usage by forcing microscopic sleeps.
    
    Prevents the scanner from monopolizing a CPU core during
    deep file analysis and regex matching.
    """
    if current_idx % batch_size == 0:
        time.sleep(0.05)

def _is_safe_symlink(filepath) -> bool:
    """Check if a symlink target is safe to follow.
    
    Allows: Composer plugin symlinks, CageFS symlinks, shared hosting paths.
    Blocks: Symlinks to system directories that could leak sensitive data.
    """
    try:
        target = os.path.realpath(str(filepath))
        # Always allow CageFS managed symlinks
        if '/.cagefs/' in target:
            return True
        # Block symlinks to system directories
        for prefix in _UNSAFE_SYMLINK_TARGETS:
            if target.startswith(prefix):
                return False
        # Allow everything else (shared plugins, staging dirs, etc.)
        return True
    except OSError:
        return False


# ─── Resource Guards ────────────────────────────────────────────────

def _check_memory(limit_mb: int = 512) -> None:
    """
    Check current RSS memory usage and raise if over limit.

    Uses the resource module to read RSS. Falls back gracefully
    on platforms where ru_maxrss is in bytes vs KB.

    Args:
        limit_mb: Maximum allowed RSS in megabytes.

    Raises:
        MemoryLimitExceeded: If current RSS exceeds the limit.
    """
    if not _RESOURCE_AVAILABLE:
        return
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        rss_raw = usage.ru_maxrss
        # macOS (Darwin) reports ru_maxrss in bytes, Linux in KB
        if platform.system() == "Darwin":
            rss_mb = rss_raw / (1024 * 1024)
        else:
            rss_mb = rss_raw / 1024

        if rss_mb > limit_mb:
            raise MemoryLimitExceeded(
                f"RSS memory {rss_mb:.0f}MB exceeds limit of {limit_mb}MB"
            )
    except (AttributeError, ValueError):
        # resource module not fully available on this platform
        pass


def _compute_sha256(file_path: Path) -> str:
    """
    Compute SHA256 hash of a file. Returns empty string on error.

    Reads in 64KB chunks to avoid loading large files into memory.
    """
    if Path(file_path).is_symlink() and not _is_safe_symlink(file_path):
        return ''
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _run_with_file_timeout(func, timeout_seconds: int = 30):
    """
    Run a callable with a per-file timeout using threading.Timer.

    This is safer than signal.alarm because it works in non-main
    threads and on all platforms.

    Uses a threading.Event to signal cancellation to the worker
    thread, preventing zombie thread accumulation.

    Returns the function result, or raises FileScanTimeout.
    """
    result = [None]
    exception = [None]
    cancel_event = threading.Event()

    def wrapper():
        try:
            result[0] = func()
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        # Signal cancellation to any code that checks the event
        cancel_event.set()
        # Give the thread a brief grace period to notice and exit
        thread.join(timeout=2)
        if thread.is_alive():
            logger.warning(
                "File scan thread still alive after timeout+grace — "
                "thread will be cleaned up on process exit"
            )
        raise FileScanTimeout(
            f"File scan timed out after {timeout_seconds}s"
        )

    if exception[0] is not None:
        raise exception[0]

    return result[0]


# ─── File Scanner ───────────────────────────────────────────────────

class FileScanner:
    """
    Scans the filesystem for backdoor files, suspicious uploads,
    and incorrect file permissions.

    Detection methods:
      1. Known backdoor filenames from the IoC database (dynamic)
      2. PHP files in wp-content/uploads/ (should never exist)
      3. Large .ico files (disguised webshells)
      4. Files with dangerous permissions (world-writable)
      5. Content-based heuristics (base64_decode, eval, gzinflate)
      6. SHA256 hash matching against known backdoor hashes
    """

    # PHP patterns that strongly indicate malware when found together
    _SUSPICIOUS_PATTERNS = [
        re.compile(rb"base64_decode\s*\(", re.IGNORECASE),
        re.compile(rb"eval\s*\(", re.IGNORECASE),
        re.compile(rb"gzinflate\s*\(", re.IGNORECASE),
        re.compile(rb"str_rot13\s*\(", re.IGNORECASE),
        re.compile(rb"assert\s*\(", re.IGNORECASE),
        re.compile(rb"preg_replace\s*\(\s*['\"]/.*/e", re.IGNORECASE),
        re.compile(rb"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", re.IGNORECASE),
        re.compile(rb"shell_exec\s*\(", re.IGNORECASE),
        re.compile(rb"system\s*\(", re.IGNORECASE),
        re.compile(rb"passthru\s*\(", re.IGNORECASE),
        re.compile(rb"exec\s*\(", re.IGNORECASE),
        # chr() obfuscation chains — 4+ consecutive chr() calls indicate obfuscation
        re.compile(rb"chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)", re.IGNORECASE),
        # create_function — deprecated PHP function abused for code execution
        re.compile(rb"create_function\s*\(", re.IGNORECASE),
        # file_put_contents with PHP code — writing backdoors to disk
        re.compile(rb"file_put_contents\s*\([^)]*<\?php", re.IGNORECASE),
    ]

    # Minimum number of suspicious patterns to flag a file as a backdoor
    _PATTERN_THRESHOLD = 2

    def __init__(
        self,
        intel: IntelligenceDB,
        scan_mode: ScanMode = ScanMode.DEEP,
        per_file_timeout: int = 30,
        memory_limit_mb: int = 512,
        progress_callback: ProgressCallback = None,
        trust_engine=None,
        hash_cache=None,
        capability_mapper=None,
        entropy_scorer=None,
    ) -> None:
        self.intel = intel
        self.scan_mode = scan_mode
        self.per_file_timeout = per_file_timeout
        self.memory_limit_mb = memory_limit_mb
        self.progress_callback = progress_callback
        self.trust_engine = trust_engine
        self.hash_cache = hash_cache
        self.capability_mapper = capability_mapper
        self.entropy_scorer = entropy_scorer

    def _emit_progress(self, phase: str, detail: str, current: int = 0, total: int = 0) -> None:
        """Emit progress via callback and log."""
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass  # Never let callback errors crash the scanner

    def scan(self, site: WordPressSite) -> List[Threat]:
        """
        Run all file-based scans on a WordPress site.

        Args:
            site: The WordPress site to scan.

        Returns:
            List of detected file-level threats.
        """
        threats: List[Threat] = []
        site_path = Path(site.path)

        if not site_path.exists():
            logger.error("Site path does not exist: %s", site_path)
            return threats

        logger.info("File scan starting: %s (mode=%s)", site_path, self.scan_mode.value)

        # Phase 1: Known backdoors (always runs in both modes)
        self._emit_progress("file_scan", "Checking known backdoor filenames", 1, 4)
        _check_memory(self.memory_limit_mb)
        threats.extend(self._scan_known_backdoors(site_path, site))

        # Phase 2: Uploads PHP (always runs)
        self._emit_progress("file_scan", "Scanning uploads for PHP files", 2, 4)
        _check_memory(self.memory_limit_mb)
        threats.extend(self._scan_uploads_for_php(site_path, site))

        # Phase 3: Permissions (always runs)
        self._emit_progress("file_scan", "Checking file permissions", 3, 4)
        _check_memory(self.memory_limit_mb)
        threats.extend(self._scan_permissions(site_path, site))

        # Phase 4: wp-config.php content scan (always runs)
        config_path = site_path / "wp-config.php"
        if config_path.exists():
            self._emit_progress("file_scan", "Scanning wp-config.php content", 4, 5)
            _check_memory(self.memory_limit_mb)
            threats.extend(self._scan_wp_config_content(config_path, site))

        # Phase 5: Content heuristics (deep mode only)
        if self.scan_mode == ScanMode.DEEP:
            self._emit_progress("file_scan", "Running content heuristic analysis", 5, 5)
            _check_memory(self.memory_limit_mb)
            threats.extend(self._scan_suspicious_content(site_path, site))
        else:
            self._emit_progress("file_scan", "Skipping content heuristics (quick mode)", 5, 5)

        # Compute SHA256 for flagged files that don't already have one (L6: avoid duplicate)
        for threat in threats:
            if threat.location and "sha256" not in threat.details and Path(threat.location).is_file():
                sha256 = _compute_sha256(Path(threat.location))
                if sha256:
                    threat.details["sha256"] = sha256

        logger.info(
            "File scan complete: %s — %d threats found",
            site_path, len(threats),
        )
        return threats

    def _scan_known_backdoors(
        self, site_path: Path, site: WordPressSite
    ) -> List[Threat]:
        """Check for known backdoor filenames from IoC database (dynamic)."""
        threats: List[Threat] = []

        # Build check_paths dynamically from the IOC database
        check_paths = self._build_dynamic_check_paths(site_path)

        for idx, (target, bd_entry) in enumerate(check_paths):
            try:
                if not target.exists():
                    continue
                rel_path = str(target.relative_to(site_path))
                ioc = self.intel.match_filename(rel_path)
                severity = Severity.HIGH
                if ioc:
                    severity = Severity(ioc.severity) if ioc.severity in [s.value for s in Severity] else Severity.HIGH

                sha256 = _compute_sha256(target)
                file_size = target.stat().st_size

                threats.append(Threat(
                    threat_type=ThreatType.BACKDOOR_FILE,
                    severity=severity,
                    title=f"Known backdoor file: {target.name}",
                    description=(
                        f"File matches known backdoor pattern from IoC database. "
                        f"{ioc.details.get('note', '') if ioc else bd_entry.get('note', '')}"
                    ),
                    location=str(target),
                    evidence=f"File exists at {rel_path} (size: {file_size} bytes)",
                    site_path=site.path,
                    details={
                        **(ioc.details if ioc else {"filename": target.name}),
                        "sha256": sha256,
                    },
                ))
            except (OSError, FileNotFoundError):
                # M4: File may be deleted between exists() and stat() — skip
                continue

            if idx % 10 == 0:
                self._emit_progress("backdoor_scan", f"Checked {idx}/{len(check_paths)} paths", idx, len(check_paths))

        # Also scan for large .ico files (disguised webshells)
        ico_count = 0
        for ico_file in site_path.rglob("*.ico"):
            if ico_file.is_symlink() and not _is_safe_symlink(ico_file):
                continue
            ico_count += 1
            if ico_count > 10000:  # H1: limit ico scan
                break
            try:
                if ico_file.stat().st_size > 50 * 1024:  # >50KB
                    sha256 = _compute_sha256(ico_file)
                    threats.append(Threat(
                        threat_type=ThreatType.BACKDOOR_FILE,
                        severity=Severity.CRITICAL,
                        title=f"Suspicious .ico file: {ico_file.name}",
                        description="Large .ico file may be a disguised PHP webshell",
                        location=str(ico_file),
                        evidence=f"Size: {ico_file.stat().st_size} bytes (>50KB threshold)",
                        site_path=site.path,
                        details={"size": ico_file.stat().st_size, "sha256": sha256},
                    ))
            except OSError:
                continue

        return threats

    def _build_dynamic_check_paths(self, site_path: Path) -> list:
        """
        Build list of (Path, dict) tuples from the IOC database backdoor_filenames.

        This replaces the old hardcoded check_paths list with dynamic entries
        pulled from intel.backdoor_filenames.
        """
        check_paths = []

        for bd in self.intel.backdoor_filenames:
            name = bd.name
            location = bd.location or ""

            # Skip glob-only entries like *.php and *.ico (handled elsewhere)
            if name.startswith("*"):
                continue

            # Map IOC location descriptions to actual site-relative directories
            if "wp-admin" in location:
                target = site_path / "wp-admin" / name
            elif "wp-includes" in location:
                target = site_path / "wp-includes" / name
            elif "wp-content/uploads" in location:
                target = site_path / "wp-content" / "uploads" / name
            elif "wp-content/mu-plugins" in location:
                target = site_path / "wp-content" / "mu-plugins" / name
            elif "webroot" in location or "public_html" in location or location == ".":
                target = site_path / name
            elif location == "any" or not location:
                target = site_path / name
            else:
                target = site_path / name

            entry = {
                "name": name,
                "location": location,
                "note": bd.note,
                "risk": bd.risk,
            }
            check_paths.append((target, entry))

        # Always include fallback common locations if not already covered
        fallback_names = [
            ("wp-admin", "defaults.php"),
            ("wp-includes", "wp-img.php"),
            (".", "about.php"),
            (".", "test.php"),
            (".", "admin.php"),
            (".", "shell.php"),
        ]
        existing_names = {p.name for p, _ in check_paths}
        for rel_dir, filename in fallback_names:
            if filename not in existing_names:
                target = site_path / rel_dir / filename
                check_paths.append((target, {"name": filename, "note": "Fallback check path"}))

        return check_paths

    def _scan_uploads_for_php(
        self, site_path: Path, site: WordPressSite
    ) -> List[Threat]:
        """Find PHP files in wp-content/uploads/ — these should never exist.

        Context-aware severity:
          - 0-byte index.php files → INFO (directory listing protection, harmless)
          - .afm.php / .ufm.php files → INFO (WooCommerce PDF font files, legitimate)
          - All other PHP files → HIGH (confirmed attack vector)
        """
        threats: List[Threat] = []
        uploads_dir = site_path / "wp-content" / "uploads"

        if not uploads_dir.exists():
            return threats

        file_idx = 0
        for php_file in uploads_dir.rglob("*.php"):
            file_idx += 1
            _cpu_throttle(batch_size=50, current_idx=file_idx)
            
            if php_file.is_symlink() and not _is_safe_symlink(php_file):
                continue
            # Skip legitimate index.php files (short content = directory listing protection)
            if php_file.name == "index.php":
                try:
                    content = php_file.read_bytes()[:256]
                    # Legitimate index.php is usually empty or "<?php // Silence is golden."
                    if len(content) < 100:
                        continue
                except OSError:
                    continue

            file_size = 0
            try:
                file_size = php_file.stat().st_size
            except OSError:
                pass

            # Context-aware severity assignment
            name_lower = php_file.name.lower()
            if file_size == 0:
                # 0-byte PHP file — directory listing protection placeholder
                severity = Severity.INFO
                note = "0-byte PHP file — likely directory listing protection (harmless)"
            elif name_lower.endswith((".afm.php", ".ufm.php")):
                # WooCommerce PDF font metric files — legitimate
                severity = Severity.INFO
                note = "WooCommerce PDF font metric file (legitimate)"
            else:
                # PHP file in uploads — confirmed attack vector
                severity = Severity.HIGH
                note = "PHP file in uploads directory — confirmed attack vector"

            sha256 = _compute_sha256(php_file)

            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=severity,
                title=f"PHP in uploads: {php_file.name}",
                description=note,
                location=str(php_file),
                evidence=f"Size: {file_size} bytes",
                site_path=site.path,
                details={"size": file_size, "zero_byte": file_size == 0, "sha256": sha256},
            ))

        return threats

    def _scan_permissions(
        self, site_path: Path, site: WordPressSite
    ) -> List[Threat]:
        """Check for dangerous file permissions.

        Note: wp-config.php world-readable check is handled by
        ConfigScanner in extended_scanners.py to avoid duplication.
        """
        threats: List[Threat] = []

        # Spot-check for world-writable directories (sample a few key dirs)
        for rel_dir in ["wp-content", "wp-admin", "wp-includes"]:
            target_dir = site_path / rel_dir
            if target_dir.exists():
                try:
                    mode = target_dir.stat().st_mode
                    if mode & stat.S_IWOTH:
                        threats.append(Threat(
                            threat_type=ThreatType.PERMISSION_ISSUE,
                            severity=Severity.MEDIUM,
                            title=f"World-writable directory: {rel_dir}/",
                            description="Directory is writable by all users on the server",
                            location=str(target_dir),
                            evidence=f"Permissions: {oct(mode)[-3:]}",
                            site_path=site.path,
                            details={"current_permissions": oct(mode)[-3:], "recommended": "755"},
                        ))
                except OSError:
                    continue

        return threats

    def _scan_suspicious_content(
        self, site_path: Path, site: WordPressSite
    ) -> List[Threat]:
        """
        Heuristic scan: check PHP files for clusters of suspicious function calls.

        Only scans files in specific high-risk locations to avoid performance
        issues on large sites. A file must contain multiple suspicious patterns
        to be flagged (reduces false positives).

        Uses per-file timeout to prevent hangs on very large or network-mounted files.
        """
        threats: List[Threat] = []

        # High-risk directories to deep-scan for content heuristics.
        # NOTE: wp-admin/ and wp-includes/ are EXCLUDED — they contain legitimate
        # uses of eval(), base64_decode(), exec() etc. and produce dozens of false
        # positives. Core file tampering is handled by CoreIntegrityChecker via
        # hash comparison, so excluding them from heuristics loses no coverage.
        # NOTE: wp-content/plugins/ and wp-content/themes/ are also EXCLUDED —
        # legitimate plugins (especially security plugins like Wordfence) use
        # eval(), base64_decode(), exec() etc. Plugin security is handled by
        # PluginAuditor (CVE matching). Only uploads/ (PHP should never be there)
        # and mu-plugins/ (small, high-risk, attacker-favored) are scanned.
        scan_dirs = [
            site_path / "wp-content" / "uploads",
            site_path / "wp-content" / "mu-plugins",
        ]

        # Also check root-level PHP files (skip known WP core)
        scan_files: List[Path] = []
        for f in site_path.glob("*.php"):
            if f.is_symlink() and not _is_safe_symlink(f):
                continue
            if f.name not in ("wp-config.php", "index.php", "wp-login.php",
                              "wp-cron.php", "wp-settings.php", "wp-blog-header.php",
                              "wp-load.php", "wp-mail.php", "wp-signup.php",
                              "wp-activate.php", "wp-comments-post.php",
                              "wp-links-opml.php", "wp-trackback.php", "xmlrpc.php"):
                scan_files.append(f)

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue
            for php_file in scan_dir.rglob("*.php"):
                if php_file.is_symlink() and not _is_safe_symlink(php_file):
                    continue
                # Skip CleanShift's own guard/mu-plugin files
                rel = str(php_file.relative_to(site_path))
                if "cleanshift" in rel.lower():
                    continue
                scan_files.append(php_file)

        total_files = len(scan_files)
        seen_locations: set = set()  # Deduplicate threats across analyzers

        for file_idx, php_file in enumerate(scan_files):
            _cpu_throttle(batch_size=20, current_idx=file_idx)
            
            if file_idx % 50 == 0:
                self._emit_progress(
                    "content_scan",
                    f"Scanning {php_file.name}",
                    file_idx,
                    total_files,
                )
                # Memory check every 50 files
                _check_memory(self.memory_limit_mb)

            try:
                def _scan_single_file(fpath=php_file):
                    return self._analyze_file_content(fpath, site_path, site)

                file_threats = _run_with_file_timeout(
                    _scan_single_file,
                    timeout_seconds=self.per_file_timeout,
                )
                if file_threats:
                    for t in file_threats:
                        key = (t.location, t.threat_type)
                        if key not in seen_locations:
                            seen_locations.add(key)
                            threats.append(t)

                # Trust-integrated analysis (deep mode only, if TrustEngine available)
                trust_engine = getattr(self, 'trust_engine', None)
                hash_cache = getattr(self, 'hash_cache', None)
                if self.scan_mode == ScanMode.DEEP and trust_engine is not None:
                    try:
                        def _scan_unified(fpath=php_file):
                            return self._scan_file_unified(
                                fpath, site, trust_engine, hash_cache,
                            )

                        unified_threats = _run_with_file_timeout(
                            _scan_unified,
                            timeout_seconds=self.per_file_timeout,
                        )
                        if unified_threats:
                            for t in unified_threats:
                                key = (t.location, t.threat_type)
                                if key not in seen_locations:
                                    seen_locations.add(key)
                                    threats.append(t)
                    except (FileScanTimeout, Exception):
                        pass  # Don't let unified scan failures break the pipeline

            except FileScanTimeout:
                logger.warning(
                    "Per-file timeout (%ds) for %s — skipping",
                    self.per_file_timeout, php_file,
                )
            except (OSError, PermissionError):
                continue

        self._emit_progress("content_scan", "Content scan complete", total_files, total_files)
        return threats

    def _analyze_file_content(
        self, php_file: Path, site_path: Path, site: WordPressSite
    ) -> List[Threat]:
        """Analyze a single PHP file for suspicious patterns. Returns threats list."""
        if php_file.is_symlink() and not _is_safe_symlink(php_file):
            return []
        threats: List[Threat] = []

        # Read only first 64KB — enough to catch injected headers
        content = php_file.read_bytes()[:65536]
        matched_patterns = []

        for pattern in self._SUSPICIOUS_PATTERNS:
            if pattern.search(content):
                matched_patterns.append(pattern.pattern.decode("utf-8", errors="replace"))

        if len(matched_patterns) >= self._PATTERN_THRESHOLD:
            rel_path = str(php_file.relative_to(site_path))
            sha256 = _compute_sha256(php_file)
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.HIGH,
                title=f"Suspicious PHP: {rel_path}",
                description=(
                    f"File contains {len(matched_patterns)} suspicious code patterns. "
                    f"Manual review recommended."
                ),
                location=str(php_file),
                evidence=f"Matched patterns: {', '.join(matched_patterns[:5])}",
                site_path=site.path,
                details={
                    "pattern_count": len(matched_patterns),
                    "patterns": matched_patterns,
                    "file_size": php_file.stat().st_size,
                    "sha256": sha256,
                },
            ))

        return threats

    # ── Unified per-file scan (trust-aware) ──────────────────────────

    def _check_patterns(self, filepath: Path, content: bytes, site: WordPressSite) -> List[Threat]:
        """
        Run pattern-matching heuristics on file content.

        Reuses the existing _SUSPICIOUS_PATTERNS and _PATTERN_THRESHOLD
        to detect clusters of suspicious function calls.

        Args:
            filepath: Path to the file.
            content:  Raw file content as bytes.
            site:     WordPressSite instance.

        Returns:
            List of Threat objects for suspicious patterns.
        """
        threats: List[Threat] = []
        matched_patterns = []

        for pattern in self._SUSPICIOUS_PATTERNS:
            if pattern.search(content):
                matched_patterns.append(pattern.pattern.decode("utf-8", errors="replace"))

        if len(matched_patterns) >= self._PATTERN_THRESHOLD:
            site_path = Path(site.path)
            try:
                rel_path = str(filepath.relative_to(site_path))
            except ValueError:
                rel_path = filepath.name
            sha256 = _compute_sha256(filepath)
            threats.append(Threat(
                threat_type=ThreatType.BACKDOOR_FILE,
                severity=Severity.HIGH,
                title=f"Suspicious PHP: {rel_path}",
                description=(
                    f"File contains {len(matched_patterns)} suspicious code patterns. "
                    f"Manual review recommended."
                ),
                location=str(filepath),
                evidence=f"Matched patterns: {', '.join(matched_patterns[:5])}",
                site_path=site.path,
                details={
                    "pattern_count": len(matched_patterns),
                    "patterns": matched_patterns,
                    "file_size": filepath.stat().st_size,
                    "sha256": sha256,
                },
            ))

        return threats

    def _scan_file_unified(
        self,
        filepath: Path,
        site: WordPressSite,
        trust_engine,
        hash_cache,
    ) -> List[Threat]:
        """
        Unified per-file scan pipeline with trust evaluation.

        This method integrates TrustEngine and HashCache to:
        - Skip VERIFIED files entirely
        - Run reduced analysis for KNOWN plugin files
        - Run full analysis for UNKNOWN/MODIFIED files
        - Cache results for incremental scanning

        Args:
            filepath:     Path object for the file.
            site:         WordPressSite instance.
            trust_engine: TrustEngine instance (may be None).
            hash_cache:   HashCache instance (may be None).

        Returns:
            List of Threat objects found for this file.
        """
        site_path = Path(site.path)

        try:
            rel_path = str(filepath.relative_to(site_path))
        except ValueError:
            rel_path = str(filepath)

        try:
            stat_info = filepath.stat()
        except (OSError, PermissionError):
            return []

        # Skip unchanged files (HashCache)
        if hash_cache is not None:
            try:
                if not hash_cache.needs_rescan(
                    site.path, rel_path, stat_info.st_mtime, stat_info.st_size,
                ):
                    return []  # File unchanged since last clean scan
            except Exception:
                pass  # If cache fails, proceed with scan

        # Trust evaluation
        trust_level = None
        trust_result = None
        allowed_capabilities = []  # type: List[str]

        if trust_engine is not None:
            try:
                trust_result = trust_engine.evaluate(str(filepath), site)
                trust_level = trust_result.level
                allowed_capabilities = trust_result.allowed_capabilities
            except Exception:
                pass

        # VERIFIED -> skip entirely
        if trust_level is not None and trust_level == 'verified':
            if hash_cache is not None:
                try:
                    hash_cache.update(
                        site.path, rel_path,
                        stat_info.st_mtime, stat_info.st_size,
                        '', 'clean',
                    )
                except Exception:
                    pass
            return []

        # Read content once
        try:
            with open(str(filepath), 'rb') as fh:
                content = fh.read(262144)  # 256KB max
        except (OSError, IOError, PermissionError):
            return []

        if not content:
            return []

        threats: List[Threat] = []

        # Pattern matching (existing FileScanner patterns)
        try:
            threats.extend(self._check_patterns(filepath, content, site))
        except Exception:
            pass

        # Capability mapping (if deep mode and file is in wp-content/)
        if self.scan_mode == ScanMode.DEEP and self.capability_mapper:
            try:
                cap_profile = self.capability_mapper.analyze_file(
                    str(filepath), content,
                )
                # For KNOWN plugins: only flag capabilities OUTSIDE allowlist
                if trust_level == 'known' and allowed_capabilities:
                    allowed_set = set(allowed_capabilities)
                    flagged_caps = {
                        k: v for k, v in cap_profile.capabilities.items()
                        if k not in allowed_set
                    }
                    if flagged_caps and cap_profile.dangerous_combos:
                        # Re-check combos with only non-allowed capabilities
                        combo_descriptions = [
                            desc for _, _, desc in cap_profile.dangerous_combos
                        ]
                        if combo_descriptions:
                            threats.append(Threat(
                                threat_type=ThreatType.SUSPICIOUS_FILE,
                                severity=Severity.MEDIUM,
                                title="Unexpected capabilities in known plugin file: %s" % rel_path,
                                description=(
                                    "File in known plugin has capabilities outside "
                                    "the expected allowlist: %s" % ", ".join(sorted(flagged_caps.keys()))
                                ),
                                location=str(filepath),
                                evidence="Non-allowed capabilities: %s" % ", ".join(sorted(flagged_caps.keys())),
                                site_path=site.path,
                                details={
                                    "flagged_capabilities": list(flagged_caps.keys()),
                                    "allowed_capabilities": allowed_capabilities,
                                    "analyzer": "trust_capability_check",
                                },
                            ))
                elif cap_profile.dangerous_combos:
                    # Full analysis for UNKNOWN/MODIFIED
                    critical_count = sum(
                        1 for _, sev, _ in cap_profile.dangerous_combos
                        if sev == Severity.CRITICAL
                    )
                    if len(cap_profile.dangerous_combos) >= 2 or critical_count >= 1:
                        combo_descriptions = [
                            desc for _, _, desc in cap_profile.dangerous_combos
                        ]
                        cap_names = sorted(cap_profile.capabilities.keys())
                        threats.append(Threat(
                            threat_type=ThreatType.SUSPICIOUS_FILE,
                            severity=Severity.HIGH,
                            title="Behavioral: dangerous capabilities in %s" % rel_path,
                            description=(
                                "File combines %d dangerous capability patterns: %s" % (
                                    len(cap_profile.dangerous_combos),
                                    "; ".join(combo_descriptions[:3]),
                                )
                            ),
                            location=str(filepath),
                            evidence="Capabilities: %s" % ", ".join(cap_names),
                            site_path=site.path,
                            details={
                                "risk_score": cap_profile.risk_score,
                                "analyzer": "trust_capability_check",
                            },
                        ))
            except Exception:
                pass

        # Entropy scoring (if deep mode)
        if self.scan_mode == ScanMode.DEEP and self.entropy_scorer:
            try:
                entropy_result = self.entropy_scorer.score_file(str(filepath))
                if entropy_result is not None and entropy_result.risk_level in ('high', 'critical'):
                    severity = (
                        Severity.CRITICAL
                        if entropy_result.risk_level == 'critical'
                        else Severity.HIGH
                    )
                    threats.append(Threat(
                        threat_type=ThreatType.SUSPICIOUS_FILE,
                        severity=severity,
                        title="High-entropy PHP file: %s" % rel_path,
                        description=(
                            "File has overall entropy %.2f bits/char with %d "
                            "suspicious lines." % (
                                entropy_result.overall_entropy,
                                entropy_result.suspicious_line_count,
                            )
                        ),
                        location=str(filepath),
                        evidence=(
                            "Overall entropy: %.2f, max line entropy: %.2f" % (
                                entropy_result.overall_entropy,
                                entropy_result.max_line_entropy,
                            )
                        ),
                        site_path=site.path,
                        details={
                            "overall_entropy": entropy_result.overall_entropy,
                            "risk_level": entropy_result.risk_level,
                            "analyzer": "trust_entropy_check",
                        },
                    ))
            except Exception:
                pass

        # Update hash cache
        if hash_cache is not None:
            try:
                status = 'threat' if threats else 'clean'
                sha256 = hashlib.sha256(content).hexdigest()
                hash_cache.update(
                    site.path, rel_path,
                    stat_info.st_mtime, stat_info.st_size,
                    sha256, status,
                )
            except Exception:
                pass

        return threats


# ─── Database Scanner ───────────────────────────────────────────────

class DatabaseScanner:
    """
    Connects to a site's MySQL database and runs detection queries
    from the IoC database to find rogue admins, DB markers, and
    script injections.

    Uses PyMySQL for direct connections — does not rely on wp-cli
    for database operations to work even on severely compromised sites.
    """

    def __init__(
        self,
        intel: IntelligenceDB,
        progress_callback: ProgressCallback = None,
    ) -> None:
        self.intel = intel
        self.progress_callback = progress_callback

    def _emit_progress(self, phase: str, detail: str, current: int = 0, total: int = 0) -> None:
        """Emit progress via callback and log."""
        logger.debug("Progress [%s]: %s (%d/%d)", phase, detail, current, total)
        if self.progress_callback:
            try:
                self.progress_callback(phase, detail, current, total)
            except Exception:
                pass

    def scan(self, site: WordPressSite) -> List[Threat]:
        """
        Run all database-level scans on a WordPress site.

        Args:
            site: The WordPress site to scan (must have DB credentials).

        Returns:
            List of detected database-level threats.
        """
        threats: List[Threat] = []

        if not _PYMYSQL_AVAILABLE:
            logger.warning("pymysql not installed — skipping database scan for %s", site.path)
            return threats

        if not site.db_name:
            logger.warning("No database configured for %s, skipping DB scan", site.path)
            return threats

        # Security: re-validate db_prefix to prevent SQL injection via table identifiers
        # This is defense-in-depth — wp.py validates at parse time, but prefix could come
        # from deserialized JSON or other sources that bypass parse_wp_config()
        if not re.match(r'^[a-zA-Z0-9_]{1,64}$', site.db_prefix):
            logger.error(
                'Unsafe db_prefix rejected for %s: %r — skipping DB scan',
                site.path, site.db_prefix,
            )
            return threats

        logger.info("Database scan starting: %s (db=%s)", site.path, site.db_name)

        conn = self._connect(site)
        if not conn:
            return threats

        try:
            self._emit_progress("db_scan", "Scanning for rogue admins", 1, 9)
            threats.extend(self._scan_rogue_admins(conn, site))

            self._emit_progress("db_scan", "Scanning for DB markers", 2, 9)
            threats.extend(self._scan_db_markers(conn, site))

            self._emit_progress("db_scan", "Scanning for script injections", 3, 9)
            threats.extend(self._scan_script_injections(conn, site))

            self._emit_progress("db_scan", "Running detection queries", 4, 9)
            threats.extend(self._run_detection_queries(conn, site))

            self._emit_progress("db_scan", "Scanning for SQL triggers", 5, 9)
            threats.extend(self._scan_sql_triggers(conn, site))

            self._emit_progress("db_scan", "Scanning for recent admins", 6, 9)
            threats.extend(self._scan_recent_admins(conn, site))

            self._emit_progress("db_scan", "Scanning for JS injections in posts", 7, 9)
            threats.extend(self._scan_js_injections(conn, site))

            self._emit_progress("db_scan", "Scanning for application passwords", 8, 9)
            threats.extend(self._scan_application_passwords(conn, site))

            self._emit_progress("db_scan", "Scanning for WP-Cron abuse", 9, 9)
            db_config = {
                "host": site.db_host,
                "user": site.db_user,
                "password": site.db_pass,
                "name": site.db_name,
                "prefix": site.db_prefix,
            }
            threats.extend(self._scan_wp_cron_jobs(conn, site, db_config))
        finally:
            conn.close()

        logger.info(
            "Database scan complete: %s — %d threats found",
            site.path, len(threats),
        )
        return threats

    def _connect(self, site: WordPressSite) -> Optional[pymysql.Connection]:
        """Establish a MySQL connection to the site's database.

        When db_host is 'localhost', attempts Unix socket connection first
        (required on Plesk and some cPanel servers where MySQL doesn't listen
        on TCP port 3306). Falls back to TCP if no socket is found.
        """
        # Common MySQL socket paths (Plesk, cPanel, Debian/Ubuntu, generic)
        _SOCKET_PATHS = [
            "/var/lib/mysql/mysql.sock",
            "/var/run/mysqld/mysqld.sock",
            "/tmp/mysql.sock",
            "/var/lib/mysql/data/mysql.sock",
        ]

        connect_kwargs = {
            "user": site.db_user,
            "password": site.db_pass,
            "database": site.db_name,
            "charset": "utf8mb4",
            "connect_timeout": 10,
            "read_timeout": 30,
            "cursorclass": pymysql.cursors.DictCursor,
        }

        try:
            # For localhost connections, try Unix socket first
            # Strip port from db_host (e.g. 'localhost:3306' -> 'localhost')
            host_part = site.db_host.split(":")[0] if site.db_host else ""
            if host_part in ("localhost", "127.0.0.1", "::1", ""):
                # Check if a socket file exists
                socket_path = None
                for sock in _SOCKET_PATHS:
                    if os.path.exists(sock):
                        socket_path = sock
                        break

                if socket_path:
                    try:
                        conn = pymysql.connect(
                            unix_socket=socket_path,
                            **connect_kwargs,
                        )
                        logger.debug(
                            "Connected to MySQL via socket %s: %s@%s",
                            socket_path, site.db_user, site.db_name,
                        )
                        return conn
                    except pymysql.Error:
                        logger.debug(
                            "Socket connection failed (%s), falling back to TCP",
                            socket_path,
                        )

            # TCP connection (non-localhost or socket fallback)
            conn = pymysql.connect(
                host=site.db_host,
                **connect_kwargs,
            )
            logger.debug("Connected to MySQL: %s@%s/%s", site.db_user, site.db_host, site.db_name)
            return conn
        except pymysql.Error as e:
            logger.error(
                "Failed to connect to MySQL for %s: %s",
                site.path, e,
            )
            return None

    def _scan_rogue_admins(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """Check for attacker-created admin accounts using IoC patterns."""
        threats: List[Threat] = []
        prefix = site.db_prefix

        try:
            with conn.cursor() as cursor:
                # Find all administrators
                sql = (
                    f"SELECT u.ID, u.user_login, u.user_email, u.user_registered "
                    f"FROM {prefix}users u "
                    f"JOIN {prefix}usermeta m ON u.ID = m.user_id "
                    f"WHERE m.meta_key = %s "
                    f"AND m.meta_value LIKE %s "
                    f"ORDER BY u.user_registered DESC "
                    f"LIMIT 200"
                )
                cursor.execute(sql, (f"{prefix}capabilities", "%administrator%"))
                admins = cursor.fetchall()

                # Check each admin against known rogue patterns
                flagged_user_ids = set()  # Track admins already caught by IOC patterns
                for admin in admins:
                    for pattern in self.intel.get_rogue_admin_patterns():
                        is_rogue = False
                        reasons: List[str] = []

                        # Check username pattern
                        if (pattern.username_pattern and
                                admin.get("user_login") and
                                pattern.username_pattern.lower() in admin["user_login"].lower()):
                            is_rogue = True
                            reasons.append(f"Username matches pattern: {pattern.username_pattern}")

                        # Check email pattern (supports wildcards)
                        if pattern.email_pattern and admin.get("user_email"):
                            email = admin["user_email"].lower()
                            email_pattern = pattern.email_pattern.lower()
                            if email_pattern.startswith("*"):
                                if email.endswith(email_pattern[1:]):
                                    is_rogue = True
                                    reasons.append(f"Email matches pattern: {pattern.email_pattern}")
                            elif email_pattern == email:
                                is_rogue = True
                                reasons.append(f"Email exact match: {pattern.email_pattern}")

                        if is_rogue:
                            flagged_user_ids.add(admin["ID"])
                            threats.append(Threat(
                                threat_type=ThreatType.ROGUE_ADMIN,
                                severity=Severity.CRITICAL,
                                title=f"Rogue admin: {admin['user_login']}",
                                description=(
                                    f"Admin account matches known attacker pattern. "
                                    f"{'; '.join(reasons)}"
                                ),
                                location=f"{prefix}users (ID: {admin['ID']})",
                                evidence=(
                                    f"user_login={admin['user_login']}, "
                                    f"user_email={admin['user_email']}, "
                                    f"registered={admin['user_registered']}"
                                ),
                                site_path=site.path,
                                cve=pattern.cve,
                                details={
                                    "user_id": admin["ID"],
                                    "user_login": admin["user_login"],
                                    "user_email": admin["user_email"],
                                    "user_registered": str(admin["user_registered"]),
                                    "pattern_source": pattern.source,
                                },
                            ))

                # Heuristic scoring for admins that don't match known IOC patterns
                for admin in admins:
                    already_flagged = admin["ID"] in flagged_user_ids
                    if already_flagged:
                        continue

                    user_login = admin.get("user_login", "")
                    user_email = admin.get("user_email", "")
                    user_registered = str(admin.get("user_registered", ""))

                    heuristic_score = self._score_rogue_likelihood(
                        user_login=user_login,
                        user_email=user_email,
                        user_registered=user_registered,
                    )
                    if heuristic_score >= 50:
                        severity = Severity.CRITICAL if heuristic_score >= 70 else Severity.HIGH
                        threats.append(Threat(
                            threat_type=ThreatType.ROGUE_ADMIN,
                            severity=severity,
                            title=f"Suspicious admin account: {user_login}",
                            description=(
                                f"Admin user '{user_login}' ({user_email}) scored {heuristic_score}/100 "
                                f"on rogue likelihood heuristics. This account shows signs of being "
                                f"attacker-created and should be verified."
                            ),
                            location=f"{prefix}users.{user_login}",
                            evidence=f"login={user_login} email={user_email} registered={user_registered} score={heuristic_score}",
                            site_path=site.path,
                            details={"check": "rogue_admin_heuristic", "score": heuristic_score},
                        ))

        except pymysql.Error as e:
            logger.error("Rogue admin scan failed for %s: %s", site.path, e)

        return threats

    def _scan_db_markers(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """Check for known malware persistence markers in wp_options and other tables."""
        threats: List[Threat] = []
        prefix = site.db_prefix

        try:
            with conn.cursor() as cursor:
                # Check each known DB marker
                for marker in self.intel.db_markers:
                    # M1: Use precise prefix replacement (only at start)
                    table = marker.table
                    if table.startswith("wp_"):
                        table = prefix + table[3:]
                    else:
                        table = marker.table

                    if not marker.option_name:
                        continue

                    # Determine column names based on table type
                    # wp_options uses option_name/option_value
                    # wp_usermeta uses meta_key/meta_value
                    # wp_postmeta uses meta_key/meta_value
                    base_table = marker.table  # original table name before prefix
                    if base_table in ("wp_usermeta", "wp_postmeta", "wp_termmeta", "wp_commentmeta"):
                        key_col = "meta_key"
                        val_col = "meta_value"
                    else:
                        key_col = "option_name"
                        val_col = "option_value"

                    try:
                        cursor.execute(
                            f"SELECT {key_col}, {val_col} FROM {table} "
                            f"WHERE {key_col} = %s LIMIT 100",
                            (marker.option_name,),
                        )
                        rows = cursor.fetchall()
                        for row in rows:
                            ioc = self.intel.match_db_option(
                                row[key_col],
                                str(row[val_col] or ""),
                            )
                            if ioc:
                                threats.append(Threat(
                                    threat_type=ThreatType.DB_MARKER,
                                    severity=Severity.CRITICAL,
                                    title=f"Malware DB marker: {row[key_col]}",
                                    description=ioc.details.get("purpose", "Malware persistence marker"),
                                    location=f"{table}.{row[key_col]}",
                                    evidence=(
                                        f"{val_col}={str(row[val_col])[:200]}"
                                    ),
                                    site_path=site.path,
                                    cve=ioc.cve,
                                    details=ioc.details,
                                ))
                    except pymysql.Error as table_err:
                        # Table might not exist (e.g. site not fully installed)
                        logger.debug(
                            "DB marker check skipped for %s.%s on %s: %s",
                            table, marker.option_name, site.path, table_err,
                        )

        except pymysql.Error as e:
            logger.error("DB marker scan failed for %s: %s", site.path, e)

        return threats

    # Whitelist patterns for options that legitimately contain script-like content
    _SCRIPT_INJECTION_WHITELIST = [
        re.compile(r"^_transient_imunify_security_rules_"),
        re.compile(r"^_transient_timeout_"),
        re.compile(r"^wp-all-import-pro_"),
        re.compile(r"^wp-all-export-pro_"),
    ]

    # Known plugin prefixes for _site_transient_ options that are legitimate
    _SITE_TRANSIENT_LEGIT_PREFIXES = (
        "a:0:{}",       # empty serialized array
        "a:1:{s:7",     # typical WP serialization
        "O:8:\"stdClass",
    )

    def _is_whitelisted_option(self, option_name, option_value=""):
        """Check if an option name matches known legitimate patterns."""
        for pattern in self._SCRIPT_INJECTION_WHITELIST:
            if pattern.match(option_name):
                return True
        # _site_transient_ options with known plugin value prefixes
        if option_name.startswith("_site_transient_"):
            for prefix in self._SITE_TRANSIENT_LEGIT_PREFIXES:
                if option_value.startswith(prefix):
                    return True
        return False

    def _scan_script_injections(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """Find injected scripts in wp_options values."""
        threats: List[Threat] = []
        prefix = site.db_prefix

        try:
            with conn.cursor() as cursor:
                # Find any options with <script src= in the value
                sql = (
                    f"SELECT option_name, LEFT(option_value, 500) as option_value "
                    f"FROM {prefix}options "
                    f"WHERE option_value LIKE %s "
                    f"AND option_name NOT IN ('blogdescription', 'blogname') "
                    f"LIMIT 100"
                )
                cursor.execute(sql, ("%<script%src=%",))
                rows = cursor.fetchall()

                for row in rows:
                    opt_name = row["option_name"]
                    value = str(row["option_value"] or "")

                    # Skip whitelisted options (Imunify, transients, etc.)
                    if self._is_whitelisted_option(opt_name, value):
                        logger.debug(
                            "Skipping whitelisted option: %s", opt_name
                        )
                        continue

                    # Check if the injected domain is known
                    domain_ioc = self.intel.match_domain(value)

                    threats.append(Threat(
                        threat_type=ThreatType.SCRIPT_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Script injection in: %s" % row['option_name'],
                        description=(
                            "Malicious <script> tag found in database option. "
                            "%s" % ('Known malware domain: ' + domain_ioc.matched_value if domain_ioc else 'Unknown script source.')
                        ),
                        location="%s" % (prefix + "options." + row['option_name']),
                        evidence=value[:300],
                        site_path=site.path,
                        cve=domain_ioc.cve if domain_ioc else None,
                        details={
                            "option_name": row["option_name"],
                            "malware_domain": domain_ioc.matched_value if domain_ioc else None,
                        },
                    ))

        except pymysql.Error as e:
            logger.error("Script injection scan failed for %s: %s", site.path, e)

        return threats

    def _run_detection_queries(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """Run IoC detection queries and flag any results."""
        threats: List[Threat] = []
        prefix = site.db_prefix

        # Only run queries that detect new threat types (avoid duplicating
        # results from the specific scans above)
        skip_queries = {"rogue_admins", "hack_file_marker", "script_injections"}

        for dq in self.intel.get_detection_queries():
            if dq.name in skip_queries:
                continue

            sql = dq.sql.replace("{prefix}", prefix)

            # Safety: only allow SELECT queries from intelligence files
            sql_stripped = sql.strip().upper()
            if not sql_stripped.startswith("SELECT"):
                logger.warning(
                    "Skipping non-SELECT detection query %r: %s",
                    dq.name, sql[:80],
                )
                continue

            # Reject dangerous keywords even in SELECT queries
            _DANGEROUS = {"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE", "EXEC"}
            sql_words = set(sql_stripped.split())
            if sql_words & _DANGEROUS:
                logger.warning(
                    "Skipping detection query %r with dangerous keywords",
                    dq.name,
                )
                continue

            # Reject multi-statement queries (semicolons)
            if ';' in sql.rstrip(';'):
                logger.warning(
                    'Skipping multi-statement detection query %r',
                    dq.name,
                )
                continue

            try:
                with conn.cursor() as cursor:
                    cursor.execute(sql)
                    rows = cursor.fetchall()

                    if rows and len(rows) > 0:
                        # Determine if results indicate a threat
                        if dq.name == "suspicious_options":
                            for row in rows:
                                threats.append(Threat(
                                    threat_type=ThreatType.SCRIPT_INJECTION,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious option: {row.get('option_name', 'unknown')}",
                                    description=(
                                        f"{dq.description}. "
                                        f"Contains obfuscated code (base64/eval/gzinflate)."
                                    ),
                                    location=f"{prefix}options",
                                    evidence=str(row)[:300],
                                    site_path=site.path,
                                    details={
                                        "query_name": dq.name,
                                        "row_data": {k: str(v) for k, v in row.items()},
                                    },
                                ))
                        elif dq.name == "litespeed_artifacts":
                            # Not a threat per se, but informational
                            count = 0
                            for row in rows:
                                for v in row.values():
                                    if isinstance(v, int):
                                        count = v
                                        break
                            if count > 50:
                                threats.append(Threat(
                                    threat_type=ThreatType.VULNERABLE_PLUGIN,
                                    severity=Severity.INFO,
                                    title=f"LiteSpeed Cache DB artifacts: {count} entries",
                                    description=(
                                        f"Found {count} LiteSpeed Cache entries in wp_options. "
                                        f"These should be cleaned up after plugin removal."
                                    ),
                                    location=f"{prefix}options",
                                    evidence=f"{count} rows matching 'litespeed%'",
                                    site_path=site.path,
                                    details={"entry_count": count, "query_name": dq.name},
                                ))

            except pymysql.Error as e:
                logger.debug(
                    "Detection query '%s' failed for %s: %s",
                    dq.name, site.path, e,
                )

        return threats

    def _scan_sql_triggers(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """
        Check for SQL triggers in the database.

        WordPress databases should NEVER have triggers. Any trigger found
        is suspicious and likely indicates post-exploitation persistence.
        """
        threats = []  # type: List[Threat]

        try:
            with conn.cursor() as cursor:
                cursor.execute("SHOW TRIGGERS")
                triggers = cursor.fetchall()

                for trigger in triggers:
                    trigger_name = trigger.get("Trigger", "unknown")
                    table_name = trigger.get("Table", "unknown")
                    event = trigger.get("Event", "unknown")
                    timing = trigger.get("Timing", "unknown")
                    statement = str(trigger.get("Statement", ""))[:500]

                    threats.append(Threat(
                        threat_type=ThreatType.DB_MARKER,
                        severity=Severity.CRITICAL,
                        title="SQL trigger found: %s" % trigger_name,
                        description=(
                            "WordPress databases should never have SQL triggers. "
                            "This trigger fires %s %s on table '%s' and likely "
                            "indicates post-exploitation persistence or data "
                            "exfiltration." % (timing, event, table_name)
                        ),
                        location="%s (trigger on %s)" % (site.db_name, table_name),
                        evidence="%s %s %s: %s" % (timing, event, trigger_name, statement[:200]),
                        site_path=site.path,
                        details={
                            "trigger_name": trigger_name,
                            "table": table_name,
                            "event": event,
                            "timing": timing,
                            "statement": statement,
                        },
                    ))

        except pymysql.Error as e:
            logger.error("SQL trigger scan failed for %s: %s", site.path, e)

        return threats

    def _scan_recent_admins(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """
        Check for recently created admin accounts (last 90 days).

        Flags admins that:
        - Don't match the site's domain email pattern
        - Use @wordpress.com/@wordpress.org emails (nobody uses these legitimately)
        - Use known disposable email domains
        """
        threats = []  # type: List[Threat]
        prefix = site.db_prefix

        # Known disposable email domains
        disposable_domains = {
            "tempmail.com", "yopmail.com", "guerrillamail.com",
            "mailinator.com", "10minutemail.com", "throwaway.email",
            "guerrillamail.info", "grr.la", "guerrillamail.net",
            "sharklasers.com", "guerrillamail.de", "trbvm.com",
            "dispostable.com", "maildrop.cc", "temp-mail.org",
        }

        # Fake WordPress emails — nobody legitimately registers with these
        fake_wp_domains = {"wordpress.com", "wordpress.org"}

        try:
            with conn.cursor() as cursor:
                sql = (
                    "SELECT u.ID, u.user_login, u.user_email, u.user_registered "
                    "FROM %susers u "
                    "JOIN %susermeta m ON u.ID = m.user_id "
                    "WHERE m.meta_key = %%s "
                    "AND m.meta_value LIKE %%s "
                    "AND u.user_registered > DATE_SUB(NOW(), INTERVAL 90 DAY) "
                    "ORDER BY u.user_registered DESC "
                    "LIMIT 200"
                ) % (prefix, prefix)
                cursor.execute(sql, (prefix + "capabilities", "%administrator%"))
                admins = cursor.fetchall()

                # Extract site domain for pattern matching
                site_domain = site.domain.lower().replace("www.", "") if site.domain else ""

                for admin in admins:
                    email = admin["user_email"].lower()
                    reasons = []  # type: List[str]

                    # Extract email domain
                    email_parts = email.split("@")
                    email_domain = email_parts[1] if len(email_parts) == 2 else ""

                    # Check for fake WordPress emails
                    if email_domain in fake_wp_domains:
                        reasons.append(
                            "Uses @%s email (nobody legitimately registers with this)" % email_domain
                        )

                    # Check for disposable email domains
                    if email_domain in disposable_domains:
                        reasons.append(
                            "Uses disposable email domain: %s" % email_domain
                        )

                    # Check if email doesn't match site domain
                    if site_domain and email_domain and email_domain != site_domain:
                        # Only flag if also using suspicious domain
                        if email_domain in disposable_domains or email_domain in fake_wp_domains:
                            reasons.append(
                                "Email domain '%s' does not match site domain '%s'" % (
                                    email_domain, site_domain
                                )
                            )

                    if reasons:
                        threats.append(Threat(
                            threat_type=ThreatType.ROGUE_ADMIN,
                            severity=Severity.HIGH,
                            title="Suspicious recent admin: %s" % admin["user_login"],
                            description=(
                                "Admin account created in last 90 days with "
                                "suspicious characteristics. %s" % "; ".join(reasons)
                            ),
                            location="%susers (ID: %s)" % (prefix, admin["ID"]),
                            evidence=(
                                "user_login=%s, user_email=%s, "
                                "registered=%s" % (
                                    admin["user_login"],
                                    admin["user_email"],
                                    admin["user_registered"],
                                )
                            ),
                            site_path=site.path,
                            details={
                                "user_id": admin["ID"],
                                "user_login": admin["user_login"],
                                "user_email": admin["user_email"],
                                "user_registered": str(admin["user_registered"]),
                                "reasons": reasons,
                            },
                        ))

        except pymysql.Error as e:
            logger.error("Recent admin scan failed for %s: %s", site.path, e)

        return threats

    def _scan_js_injections(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """
        Check for JavaScript injections in wp_posts and suspicious
        base64-encoded values in wp_options.

        Detects:
        - String.fromCharCode() obfuscation in post content
        - document.createElement('script') in post content
        - Base64-encoded values >1000 chars in non-standard options
        """
        threats = []  # type: List[Threat]
        prefix = site.db_prefix

        # Standard options that may legitimately have long values
        legit_long_options = (
            "'active_plugins'", "'cron'", "'widget_text'",
            "'widget_custom_html'", "'theme_mods_%'",
            "'auto_updater.lock'", "'rewrite_rules'",
            "'sidebars_widgets'",
        )

        try:
            with conn.cursor() as cursor:
                # Check wp_posts for String.fromCharCode() obfuscation
                sql = (
                    "SELECT ID, post_title, post_type, "
                    "LEFT(post_content, 300) as content_preview "
                    "FROM %sposts "
                    "WHERE post_content LIKE %%s "
                    "LIMIT 50"
                ) % prefix
                cursor.execute(sql, ("%String.fromCharCode(%",))
                rows = cursor.fetchall()

                for row in rows:
                    threats.append(Threat(
                        threat_type=ThreatType.SCRIPT_INJECTION,
                        severity=Severity.HIGH,
                        title="JS obfuscation in post: %s (ID %s)" % (
                            row.get("post_title", "unknown")[:50], row["ID"]
                        ),
                        description=(
                            "String.fromCharCode() found in post content. "
                            "This JavaScript obfuscation technique is commonly "
                            "used to hide malicious redirects and injections."
                        ),
                        location="%sposts (ID: %s)" % (prefix, row["ID"]),
                        evidence=str(row.get("content_preview", ""))[:200],
                        site_path=site.path,
                        details={
                            "post_id": row["ID"],
                            "post_type": row.get("post_type", "unknown"),
                            "injection_type": "String.fromCharCode",
                        },
                    ))

                # Check wp_posts for document.createElement('script')
                sql2 = (
                    "SELECT ID, post_title, post_type, "
                    "LEFT(post_content, 300) as content_preview "
                    "FROM %sposts "
                    "WHERE post_content LIKE %%s "
                    "LIMIT 50"
                ) % prefix
                cursor.execute(sql2, ("%document.createElement%script%",))
                rows2 = cursor.fetchall()

                for row in rows2:
                    threats.append(Threat(
                        threat_type=ThreatType.SCRIPT_INJECTION,
                        severity=Severity.HIGH,
                        title="Dynamic script injection in post ID %s" % row["ID"],
                        description=(
                            "document.createElement('script') found in post content. "
                            "This dynamically injects JavaScript and is a common "
                            "malware persistence technique."
                        ),
                        location="%sposts (ID: %s)" % (prefix, row["ID"]),
                        evidence=str(row.get("content_preview", ""))[:200],
                        site_path=site.path,
                        details={
                            "post_id": row["ID"],
                            "post_type": row.get("post_type", "unknown"),
                            "injection_type": "createElement_script",
                        },
                    ))

                # Check wp_options for base64-encoded values >1000 chars
                # in non-standard option names
                legit_list = ", ".join(legit_long_options)
                sql3 = (
                    "SELECT option_name, LENGTH(option_value) as val_length, "
                    "LEFT(option_value, 200) as value_preview "
                    "FROM %soptions "
                    "WHERE LENGTH(option_value) > 1000 "
                    "AND option_value REGEXP 'base64' "
                    "AND option_name NOT IN (%s) "
                    "AND option_name NOT LIKE '_transient_%%' "
                    "AND option_name NOT LIKE '_site_transient_%%' "
                    "LIMIT 20"
                ) % (prefix, legit_list)
                cursor.execute(sql3)
                rows3 = cursor.fetchall()

                for row in rows3:
                    threats.append(Threat(
                        threat_type=ThreatType.SCRIPT_INJECTION,
                        severity=Severity.HIGH,
                        title="Suspicious base64 option: %s" % row["option_name"],
                        description=(
                            "Option contains base64-encoded data (%s chars). "
                            "Large encoded payloads in non-standard options often "
                            "indicate obfuscated malware." % row["val_length"]
                        ),
                        location="%soptions.%s" % (prefix, row["option_name"]),
                        evidence=str(row.get("value_preview", ""))[:200],
                        site_path=site.path,
                        details={
                            "option_name": row["option_name"],
                            "value_length": row["val_length"],
                            "injection_type": "base64_payload",
                        },
                    ))

        except pymysql.Error as e:
            logger.error("JS injection scan failed for %s: %s", site.path, e)

        return threats

    def _scan_application_passwords(
        self, conn: pymysql.Connection, site: WordPressSite
    ) -> List[Threat]:
        """
        Check for WordPress Application Passwords in usermeta.

        Application Passwords (wp_usermeta._application_passwords) provide
        persistent REST API access. While legitimate for integrations,
        they should be audited as attackers use them for persistent access
        that survives password resets.
        """
        threats = []  # type: List[Threat]
        prefix = site.db_prefix

        try:
            with conn.cursor() as cursor:
                sql = (
                    "SELECT u.ID, u.user_login, u.user_email, "
                    "LEFT(m.meta_value, 500) as app_passwords "
                    "FROM %susers u "
                    "JOIN %susermeta m ON u.ID = m.user_id "
                    "WHERE m.meta_key = '_application_passwords' "
                    "AND m.meta_value != '' "
                    "AND m.meta_value IS NOT NULL "
                    "LIMIT 100"
                ) % (prefix, prefix)
                cursor.execute(sql)
                rows = cursor.fetchall()

                for row in rows:
                    # Try to count the number of app passwords
                    app_pw_data = str(row.get("app_passwords", ""))
                    # Serialized PHP array — count 'name' occurrences
                    pw_count = app_pw_data.count('"name"')
                    if pw_count == 0:
                        pw_count = app_pw_data.count("s:4:\"name\"")
                    if pw_count == 0:
                        pw_count = 1  # At least one exists

                    threats.append(Threat(
                        threat_type=ThreatType.ROGUE_ADMIN,
                        severity=Severity.MEDIUM,
                        title="Application password for: %s" % row["user_login"],
                        description=(
                            "User '%s' has %d application password(s) configured. "
                            "These provide persistent REST API access that survives "
                            "password resets. Review if these are legitimate "
                            "integrations." % (row["user_login"], pw_count)
                        ),
                        location="%susermeta (user ID: %s)" % (prefix, row["ID"]),
                        evidence="user=%s, email=%s, app_passwords=%d" % (
                            row["user_login"], row["user_email"], pw_count
                        ),
                        site_path=site.path,
                        details={
                            "user_id": row["ID"],
                            "user_login": row["user_login"],
                            "user_email": row["user_email"],
                            "app_password_count": pw_count,
                            "note": "Review and revoke if not recognized",
                        },
                    ))

        except pymysql.Error as e:
            logger.error("Application password scan failed for %s: %s", site.path, e)

        return threats

    # ── WP-Cron Abuse Detection ──────────────────────────────────────

    # WordPress core cron event names that are always legitimate
    _WP_CORE_CRON_EVENTS = {
        "wp_version_check", "wp_update_plugins", "wp_update_themes",
        "wp_scheduled_delete", "wp_scheduled_auto_draft_delete",
        "delete_expired_transients", "wp_privacy_delete_old_export_files",
        "wp_cron_delete_expired", "recovery_mode_clean_expired_keys",
        "wp_site_health_scheduled_check", "wp_https_detection",
        "wp_delete_temp_updater_backups",
    }

    # Regex for obfuscated callback names (random hex/base64 strings)
    _OBFUSCATED_CALLBACK_RE = re.compile(
        r'^[a-f0-9]{16,}$|^[A-Za-z0-9+/]{20,}={0,2}$',
    )

    def _scan_wp_cron_jobs(
        self,
        conn: 'pymysql.Connection',
        site: WordPressSite,
        db_config: dict,
    ) -> List[Threat]:
        """Detect abused WP-Cron scheduled events.

        Queries the ``cron`` option from wp_options and parses the PHP
        serialized array using regex to extract URLs, callback names,
        and schedule intervals.  Flags:

        - External URLs (not the site's own domain)
        - Known malicious domains from the IoC database
        - Suspiciously frequent schedules (< hourly for non-core events)
        - Callback names matching obfuscation patterns

        Args:
            conn: Active PyMySQL connection.
            site: The WordPress site being scanned.
            db_config: Database connection config dict with host, user,
                       password, name, prefix keys.

        Returns:
            List of threats with type WP_CRON_ABUSE.
        """
        threats: List[Threat] = []
        prefix = db_config["prefix"]

        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    f"SELECT option_value FROM {prefix}options "
                    f"WHERE option_name = %s LIMIT 1",
                    ("cron",),
                )
                row = cursor.fetchone()
                if not row:
                    logger.debug("No cron option found for %s", site.path)
                    return threats

                cron_value = str(row.get("option_value", ""))
                if not cron_value:
                    return threats

        except pymysql.Error as e:
            logger.error("WP-Cron scan failed for %s: %s", site.path, e)
            return threats

        # Extract the site's own domain for comparison
        site_domain = ""
        if site.domain:
            # Strip protocol and trailing slash
            site_domain = re.sub(r'^https?://', '', site.domain).strip('/').lower()

        # Extract all URLs from the serialized cron data
        url_pattern = re.compile(r'https?://[^\s";\'{}]+', re.IGNORECASE)
        urls_found = url_pattern.findall(cron_value)

        for url in urls_found:
            url_lower = url.lower()
            # Extract domain from URL
            url_domain_match = re.match(r'https?://([^/:\s]+)', url_lower)
            if not url_domain_match:
                continue
            url_domain = url_domain_match.group(1)

            # Skip if URL points to the site's own domain
            if site_domain and (
                url_domain == site_domain
                or url_domain == "www." + site_domain
                or url_domain.endswith("." + site_domain)
            ):
                continue

            # Skip wordpress.org API calls (legitimate)
            if url_domain.endswith(".wordpress.org") or url_domain == "wordpress.org":
                continue

            # Check against known malicious domains
            domain_ioc = self.intel.match_domain(url)
            severity = Severity.CRITICAL if domain_ioc else Severity.HIGH

            threats.append(Threat(
                threat_type=ThreatType.WP_CRON_ABUSE,
                severity=severity,
                title="WP-Cron external URL: %s" % url_domain,
                description=(
                    "WP-Cron job references an external URL (%s). "
                    "%s"
                    "Malware often abuses wp-cron to phone home, "
                    "exfiltrate data, or download additional payloads."
                ) % (
                    url[:100],
                    ("Known malicious domain: %s. " % domain_ioc.matched_value)
                    if domain_ioc else "",
                ),
                location="%soptions.cron" % prefix,
                evidence=url[:300],
                site_path=site.path,
                cve=domain_ioc.cve if domain_ioc else None,
                details={
                    "check": "wp_cron_abuse",
                    "url": url[:500],
                    "url_domain": url_domain,
                    "malware_domain": domain_ioc.matched_value if domain_ioc else None,
                },
            ))

        # Extract event/callback names from serialized data
        # PHP serialized format: s:LEN:"event_name"; — extract quoted strings
        event_pattern = re.compile(r's:\d+:"([^"]+)"')
        event_names = event_pattern.findall(cron_value)

        # Deduplicate while preserving order
        seen_events: set = set()
        unique_events: list = []
        for name in event_names:
            if name not in seen_events:
                seen_events.add(name)
                unique_events.append(name)

        for event_name in unique_events:
            # Skip known WordPress core events
            if event_name in self._WP_CORE_CRON_EVENTS:
                continue

            # Skip common legitimate values that aren't event names
            # (PHP serialized keys, schedule names, etc.)
            if event_name in (
                "schedule", "args", "interval", "display",
                "version", "cron", "hourly", "twicedaily", "daily",
                "weekly", "monthly",
            ):
                continue

            # Check for obfuscated callback names
            if self._OBFUSCATED_CALLBACK_RE.match(event_name):
                threats.append(Threat(
                    threat_type=ThreatType.WP_CRON_ABUSE,
                    severity=Severity.HIGH,
                    title="WP-Cron obfuscated event: %s" % event_name[:50],
                    description=(
                        "WP-Cron event '%s' has a name matching obfuscation "
                        "patterns (random hex or base64 string). Legitimate "
                        "plugins use readable event names." % event_name[:80]
                    ),
                    location="%soptions.cron" % prefix,
                    evidence="Event name: %s" % event_name[:200],
                    site_path=site.path,
                    details={
                        "check": "wp_cron_abuse",
                        "event_name": event_name,
                        "detection": "obfuscated_name",
                    },
                ))

        # Check for suspiciously frequent schedules (< 3600s = hourly)
        # PHP serialized interval: i:SECONDS;
        interval_pattern = re.compile(r'"interval";i:(\d+);')
        intervals = interval_pattern.findall(cron_value)

        for interval_str in intervals:
            try:
                interval = int(interval_str)
            except ValueError:
                continue
            # Flag intervals under 1 hour (3600s) that aren't 0
            # (0 = one-shot event, not recurring)
            if 0 < interval < 3600:
                threats.append(Threat(
                    threat_type=ThreatType.WP_CRON_ABUSE,
                    severity=Severity.HIGH,
                    title="WP-Cron suspicious schedule: every %ds" % interval,
                    description=(
                        "A WP-Cron event runs every %d seconds (%d minutes). "
                        "WordPress core events run at most hourly. Very frequent "
                        "schedules may indicate malware C2 beaconing or data "
                        "exfiltration." % (interval, interval // 60)
                    ),
                    location="%soptions.cron" % prefix,
                    evidence="Cron interval: %ds" % interval,
                    site_path=site.path,
                    details={
                        "check": "wp_cron_abuse",
                        "interval_seconds": interval,
                        "detection": "frequent_schedule",
                    },
                ))

        if threats:
            logger.warning(
                "WP-Cron abuse scan: %d threat(s) for %s",
                len(threats), site.path,
            )
        else:
            logger.debug("WP-Cron scan clean: %s", site.path)

        return threats

    # ── Rogue Admin Heuristic Helpers ─────────────────────────────────

    @staticmethod
    def _is_high_entropy(s: str) -> bool:
        """Check if a string has high character entropy (suggests random/generated)."""
        import math
        from collections import Counter
        if len(s) < 5:
            return False
        freq = Counter(s.lower())
        entropy = -sum((c / len(s)) * math.log2(c / len(s)) for c in freq.values())
        # Threshold: natural words typically have entropy < 3.5
        return entropy > 3.5 and len(s) > 6

    def _score_rogue_likelihood(self, user_login: str, user_email: str,
                                 user_registered: str = "") -> int:
        """
        Score 0-100 for likelihood a WordPress admin is attacker-created.

        Returns a composite score based on multiple heuristic signals.
        Scores >= 50 should be flagged as HIGH, >= 70 as CRITICAL.
        """
        score = 0

        # 1. Admin typosquats: admln, adm1n, adrnin, etc.
        admin_typos = ["admln", "adm1n", "adrnin", "aadmin", "admiln", "admlc",
                       "administrater", "administartor"]
        if any(t in user_login.lower() for t in admin_typos):
            score += 40

        # 2. System-pretending usernames
        sys_prefixes = ["sys_", "system_", "service_", "wp_update", "temp_",
                        "wpservicebot", "license_key", "wordpress_api", "megauser"]
        if any(user_login.lower().startswith(p) or user_login.lower() == p.rstrip("_")
               for p in sys_prefixes):
            score += 30

        # 3. Username is exactly "bot" or starts with "bot_"
        if user_login.lower() in ("bot", "bot_admin", "is_admin") or \
           user_login.lower().startswith("bot_"):
            score += 35

        # 4. Gibberish/high-entropy username (e.g. "admlcpw7x", "FHHGJadmin")
        if self._is_high_entropy(user_login):
            score += 25

        # 5. Disposable/example/invalid email domains
        bad_domains = ["@example.com", "@local.invalid", "@test.com",
                       "@tempmail.com", "@yopmail.com", "@guerrillamail.com",
                       "@mailinator.com", "@throwaway.email"]
        if any(user_email.lower().endswith(d) for d in bad_domains):
            score += 30

        # 6. High-entropy email local part
        email_local = user_email.split("@")[0] if "@" in user_email else ""
        if email_local and self._is_high_entropy(email_local):
            score += 15

        # 7. Known rogue email domain patterns
        rogue_email_domains = ["@org.com", "@protonmail.com", "@mail.ru"]
        if any(user_email.lower().endswith(d) for d in rogue_email_domains):
            score += 20

        # 8. Recent registration (< 30 days) — bonus signal, not standalone
        if user_registered:
            try:
                from datetime import datetime, timedelta
                reg_date = datetime.strptime(user_registered[:19], "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() - reg_date < timedelta(days=30):
                    score += 10
            except (ValueError, TypeError):
                pass

        return min(score, 100)


# ─── Plugin Auditor ─────────────────────────────────────────────────

class PluginAuditor:
    """
    Checks installed plugins against the known-vulnerable plugins
    in the IoC database.
    """

    def __init__(
        self,
        intel: IntelligenceDB,
        progress_callback: ProgressCallback = None,
    ) -> None:
        self.intel = intel
        self.progress_callback = progress_callback

    def scan(self, site: WordPressSite) -> List[Threat]:
        """
        Audit all installed plugins for known vulnerabilities.

        Args:
            site: The WordPress site to audit.

        Returns:
            List of threats for vulnerable plugins.
        """
        threats: List[Threat] = []

        logger.info(
            "Plugin audit starting: %s (%d plugins)",
            site.path, len(site.plugins),
        )

        for plugin in site.plugins:
            ioc = self.intel.match_plugin(plugin.slug, plugin.version)
            if ioc:
                severity = Severity.CRITICAL
                try:
                    severity = Severity(ioc.severity)
                except ValueError:
                    pass

                threats.append(Threat(
                    threat_type=ThreatType.VULNERABLE_PLUGIN,
                    severity=severity,
                    title=f"Vulnerable plugin: {plugin.name} ({plugin.version})",
                    description=(
                        f"{ioc.details.get('exploit_type', 'Known vulnerability')}. "
                        f"Patched in version {ioc.details.get('patched_version', 'unknown')}. "
                        f"{ioc.details.get('note', '')}"
                    ),
                    location=str(Path(site.path) / "wp-content" / "plugins" / plugin.slug),
                    evidence=f"Installed: {plugin.version}, Vulnerable: {ioc.details.get('vulnerable_versions', '')}",
                    site_path=site.path,
                    cve=ioc.cve,
                    details={
                        "plugin_slug": plugin.slug,
                        "plugin_version": plugin.version,
                        "plugin_status": plugin.status,
                        **ioc.details,
                    },
                ))

        logger.info(
            "Plugin audit complete: %s — %d vulnerable plugins",
            site.path, len(threats),
        )
        return threats


# ─── Core Integrity Checker ─────────────────────────────────────────

class CoreIntegrityChecker:
    """
    Verifies WordPress core file integrity using wp-cli's
    `core verify-checksums` command.
    """

    def scan(self, site: WordPressSite) -> List[Threat]:
        """
        Run core checksum verification.

        Args:
            site: The WordPress site to verify.

        Returns:
            List of threats for modified core files.
        """
        threats: List[Threat] = []
        site_path = Path(site.path)

        logger.info("Core integrity check starting: %s", site_path)

        success, output = run_wp_cli(site_path, "core verify-checksums")

        if success:
            logger.info("Core checksums verified OK: %s", site_path)
        else:
            # Parse the wp-cli output for modified files
            modified_files = self._parse_checksum_output(output)

            if modified_files:
                # P1: Detect checksum API gap — if >20 files fail, likely a
                # new WP version where checksums aren't available yet.
                is_api_gap = (
                    len(modified_files) > 20
                    or "Checksum not available" in output
                    or "couldn't find checksums" in output.lower()
                )

                for filepath in modified_files:
                    full_path = site_path / filepath
                    sha256 = _compute_sha256(full_path) if full_path.exists() else ""

                    # Determine severity and title based on file location
                    severity, title, description = self._classify_modified_file(
                        filepath, is_api_gap,
                    )

                    threats.append(Threat(
                        threat_type=ThreatType.CORE_MODIFIED,
                        severity=severity,
                        title=title,
                        description=description,
                        location=str(full_path),
                        evidence=f"Checksum mismatch for {filepath}",
                        site_path=site.path,
                        details={
                            "file": filepath,
                            "sha256": sha256,
                            "api_gap": is_api_gap,
                        },
                    ))

                if is_api_gap:
                    logger.info(
                        "Core checksum: %d mismatches (likely API gap for WP %s) — demoted to INFO",
                        len(modified_files), site.wp_version or "unknown",
                    )
            else:
                # wp-cli failed for other reasons (e.g. no internet)
                logger.warning(
                    "Core checksum verification failed (non-file error): %s — %s",
                    site_path, output[:200],
                )

        return threats

    # Default theme directory prefixes — these ship with WP but are
    # maintained separately and frequently lag behind core checksums.
    _DEFAULT_THEME_PREFIXES = (
        "wp-content/themes/twenty",
    )

    @staticmethod
    def _is_default_theme_file(filepath: str) -> bool:
        """Return True if *filepath* belongs to a bundled default theme (twenty*)."""
        normalised = filepath.replace("\\", "/")
        return normalised.startswith(CoreIntegrityChecker._DEFAULT_THEME_PREFIXES[0])

    @staticmethod
    def _classify_modified_file(
        filepath: str, is_api_gap: bool,
    ) -> tuple:
        """Determine severity, title, and description for a modified file.

        Returns:
            Tuple of ``(Severity, title_str, description_str)``.
        """
        if is_api_gap:
            return (
                Severity.INFO,
                f"Modified core file: {filepath}",
                "WordPress checksum API may not have checksums for this version yet. "
                "This is likely a false positive — re-scan in a few days.",
            )

        if CoreIntegrityChecker._is_default_theme_file(filepath):
            return (
                Severity.INFO,
                f"Theme version mismatch: {filepath}",
                "Bundled default theme file differs from the expected checksum. "
                "This is common after theme updates or customisations and is "
                "generally not a security concern.",
            )

        # True core files (wp-admin/, wp-includes/, root files)
        return (
            Severity.HIGH,
            f"Modified core file: {filepath}",
            "WordPress core file has been modified from its original. "
            "This may indicate malware injection or unauthorized changes.",
        )

    @staticmethod
    def _parse_checksum_output(output: str) -> List[str]:
        """
        Extract file paths from wp-cli verify-checksums error output.

        wp-cli outputs lines like:
            Warning: File doesn't verify against checksum: wp-admin/about.php
            Warning: File was added: wp-includes/wp-img.php
        """
        modified: List[str] = []
        for line in output.split("\n"):
            line = line.strip()
            # Match both "doesn't verify" and "was added" patterns
            match = re.search(
                r"(?:doesn't verify against checksum|File was added):\s*(.+)",
                line,
                re.IGNORECASE,
            )
            if match:
                modified.append(match.group(1).strip())
        return modified


# ─── Extended Scanner Imports (graceful fallback) ──────────────────

try:
    from .extended_scanners import (
        HtaccessScanner,
        MuPluginScanner,
        ImageScanner,
        NetworkScanner,
        ConfigScanner,
        SystemScanner,
    )
    _EXTENDED_SCANNERS_AVAILABLE = True
except ImportError:
    _EXTENDED_SCANNERS_AVAILABLE = False
    logger.debug("Extended scanners not available — running with core scanners only")

try:
    from .verifier import ChecksumVerifier, HashCache, VerifyResult
    _VERIFIER_AVAILABLE = True
except ImportError:
    _VERIFIER_AVAILABLE = False
    logger.debug("Verifier module not available — checksum verification disabled")

try:
    from .behavioral import CapabilityMapper, EntropyScorer
    _BEHAVIORAL_AVAILABLE = True
except ImportError:
    _BEHAVIORAL_AVAILABLE = False
    logger.debug("Behavioral module not available — capability/entropy analysis disabled")

try:
    from .trust import TrustEngine, TrustLevel
    _TRUST_AVAILABLE = True
except ImportError:
    _TRUST_AVAILABLE = False
    logger.debug("Trust module not available — trust evaluation disabled")

try:
    from .platform import PlatformDetector, PlatformType, PlatformInfo
    _PLATFORM_AVAILABLE = True
except ImportError:
    _PLATFORM_AVAILABLE = False
    logger.debug("Platform module not available — platform detection disabled")

try:
    from .universal import UniversalScanner
    _UNIVERSAL_AVAILABLE = True
except ImportError:
    _UNIVERSAL_AVAILABLE = False
    logger.debug("Universal module not available — universal scanning disabled")

try:
    from .concordance import ConcordanceEngine
    _CONCORDANCE_AVAILABLE = True
except ImportError:
    _CONCORDANCE_AVAILABLE = False
    logger.debug("Concordance module not available — cross-referencing disabled")

try:
    from .yara_scanner import YaraScanner, YaraFinding
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.debug("YARA module not available — YARA scanning disabled")

try:
    from .vuln_scanner import VulnScanner, VulnFinding
    _VULN_SCANNER_AVAILABLE = True
except ImportError:
    _VULN_SCANNER_AVAILABLE = False
    logger.debug("VulnScanner not available — vulnerability scanning disabled")


# ─── Site Scanner (Orchestrator) ────────────────────────────────────

class SiteScanner:
    """
    Orchestrates all scanner layers for a single WordPress site.

    Runs file scanning, database scanning, plugin auditing, core
    integrity checking, and extended scanners (htaccess, mu-plugins,
    images, network, config, system) in sequence.

    Enforces a total scan timeout per site (default 600s).
    """

    def __init__(
        self,
        intel: IntelligenceDB,
        scan_mode: ScanMode = ScanMode.DEEP,
        per_file_timeout: int = 30,
        total_site_timeout: int = 600,
        memory_limit_mb: int = 512,
        progress_callback: ProgressCallback = None,
    ) -> None:
        self.intel = intel
        self.scan_mode = scan_mode
        self.per_file_timeout = per_file_timeout
        self.total_site_timeout = total_site_timeout
        self.memory_limit_mb = memory_limit_mb
        self.progress_callback = progress_callback
        self._shutdown_requested = False
        # Only install signal handlers in the main thread — prevents
        # ValueError when SiteScanner is used from worker threads
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, self._handle_signal)
            signal.signal(signal.SIGINT, self._handle_signal)

        self.file_scanner = FileScanner(
            intel,
            scan_mode=scan_mode,
            per_file_timeout=per_file_timeout,
            memory_limit_mb=memory_limit_mb,
            progress_callback=progress_callback,
        )
        self.db_scanner = DatabaseScanner(intel, progress_callback=progress_callback)
        self.plugin_auditor = PluginAuditor(intel, progress_callback=progress_callback)
        self.core_checker = CoreIntegrityChecker()

        # Extended scanners — initialized only if available
        self.htaccess_scanner = None
        self.mu_plugin_scanner = None
        self.image_scanner = None
        self.network_scanner = None
        self.config_scanner = None
        self.system_scanner = None

        if _EXTENDED_SCANNERS_AVAILABLE:
            try:
                self.htaccess_scanner = HtaccessScanner(intel, progress_callback=progress_callback)
                self.mu_plugin_scanner = MuPluginScanner(intel, progress_callback=progress_callback)
                self.image_scanner = ImageScanner(intel, progress_callback=progress_callback)
                self.network_scanner = NetworkScanner(intel, progress_callback=progress_callback)
                self.config_scanner = ConfigScanner(intel, progress_callback=progress_callback)
                self.system_scanner = SystemScanner(intel, progress_callback=progress_callback)
            except Exception as e:
                logger.warning("Failed to initialize some extended scanners: %s", e)

        # Verifier and behavioral modules — initialized only if available
        self.checksum_verifier = None
        self.capability_mapper = None
        self.entropy_scorer = None
        self.trust_engine = None
        self.hash_cache = None

        # Platform detection and universal scanning
        self.platform_detector = None
        self.universal_scanner = None
        self.concordance_engine = None

        # YARA and vulnerability scanning
        self.yara_scanner = None
        self.vuln_scanner = None

        if _VERIFIER_AVAILABLE:
            try:
                self.checksum_verifier = ChecksumVerifier()
            except Exception as e:
                logger.warning("Failed to initialize ChecksumVerifier: %s", e)

        if _BEHAVIORAL_AVAILABLE:
            try:
                self.capability_mapper = CapabilityMapper()
                self.entropy_scorer = EntropyScorer()
            except Exception as e:
                logger.warning("Failed to initialize behavioral analyzers: %s", e)

        if _TRUST_AVAILABLE:
            try:
                self.trust_engine = TrustEngine(
                    checksum_verifier=self.checksum_verifier,
                )
                logger.info("TrustEngine initialized")
            except Exception as e:
                logger.warning("Failed to initialize TrustEngine: %s", e)

        if _PLATFORM_AVAILABLE:
            try:
                self.platform_detector = PlatformDetector()
                logger.info("PlatformDetector initialized")
            except Exception as e:
                logger.warning("Failed to initialize PlatformDetector: %s", e)

        if _UNIVERSAL_AVAILABLE:
            try:
                self.universal_scanner = UniversalScanner()
                logger.info("UniversalScanner initialized")
            except Exception as e:
                logger.warning("Failed to initialize UniversalScanner: %s", e)

        if _CONCORDANCE_AVAILABLE:
            try:
                self.concordance_engine = ConcordanceEngine()
                logger.info("ConcordanceEngine initialized")
            except Exception as e:
                logger.warning("Failed to initialize ConcordanceEngine: %s", e)

        if _YARA_AVAILABLE:
            try:
                self.yara_scanner = YaraScanner()
                if self.yara_scanner.rules_loaded:
                    logger.info("YaraScanner initialized (%s rules loaded)",
                               self.yara_scanner.rules_dir)
                else:
                    logger.warning("YaraScanner initialized but no rules loaded")
            except Exception as e:
                logger.warning("Failed to initialize YaraScanner: %s", e)

        if _VULN_SCANNER_AVAILABLE:
            try:
                self.vuln_scanner = VulnScanner()
                logger.info("VulnScanner initialized")
            except Exception as e:
                logger.warning("Failed to initialize VulnScanner: %s", e)

        # Pass trust_engine, hash_cache, and behavioral modules to FileScanner
        self.file_scanner.trust_engine = self.trust_engine
        self.file_scanner.hash_cache = self.hash_cache
        self.file_scanner.capability_mapper = self.capability_mapper
        self.file_scanner.entropy_scorer = self.entropy_scorer

    def _handle_signal(self, signum, frame):
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        logger.warning('Shutdown signal received (%s), finishing current layer...', signum)
        self._shutdown_requested = True

    def scan(self, site: WordPressSite) -> List[Threat]:
        """
        Run a full scan on a single WordPress site.

        Each scanner layer runs independently — if one fails, the
        others still execute. This ensures partial results are always
        available even on heavily compromised sites.

        Enforces total_site_timeout. If exceeded, returns partial results.
        Checks _shutdown_requested between layers for graceful shutdown.

        Args:
            site: The WordPress site to scan.

        Returns:
            Aggregated list of all threats found.
        """
        all_threats: List[Threat] = []
        scan_start = time.monotonic()

        logger.info("═" * 60)
        logger.info("Full scan starting: %s (mode=%s, timeout=%ds)",
                     site.path, self.scan_mode.value, self.total_site_timeout)
        logger.info("═" * 60)

        def _check_timeout():
            if self._shutdown_requested:
                logger.warning('Shutdown requested — returning partial results for %s', site.path)
                raise SiteScanTimeout('Shutdown signal received')
            elapsed = time.monotonic() - scan_start
            if elapsed > self.total_site_timeout:
                raise SiteScanTimeout(
                    f"Total scan timeout ({self.total_site_timeout}s) exceeded "
                    f"after {elapsed:.0f}s"
                )

        # Layer 1: File scanning
        try:
            _check_timeout()
            _check_memory(self.memory_limit_mb)
            all_threats.extend(self.file_scanner.scan(site))
        except SiteScanTimeout:
            logger.error("Site scan timeout reached during file scan for %s", site.path)
            return all_threats
        except MemoryLimitExceeded as e:
            logger.error("Memory limit exceeded during file scan for %s: %s", site.path, e)
            return all_threats
        except Exception as e:
            logger.error("File scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 2: Database scanning
        try:
            _check_timeout()
            _check_memory(self.memory_limit_mb)
            all_threats.extend(self.db_scanner.scan(site))
        except SiteScanTimeout:
            logger.error("Site scan timeout reached during DB scan for %s", site.path)
            return all_threats
        except MemoryLimitExceeded as e:
            logger.error("Memory limit exceeded during DB scan for %s: %s", site.path, e)
            return all_threats
        except Exception as e:
            logger.error("Database scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 3: Plugin auditing
        try:
            _check_timeout()
            all_threats.extend(self.plugin_auditor.scan(site))
        except SiteScanTimeout:
            logger.error("Site scan timeout reached during plugin audit for %s", site.path)
            return all_threats
        except Exception as e:
            logger.error("Plugin auditor crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 4: Core integrity (deep mode only)
        if self.scan_mode == ScanMode.DEEP:
            try:
                _check_timeout()
                all_threats.extend(self.core_checker.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during core integrity check for %s", site.path)
                return all_threats
            except Exception as e:
                logger.error("Core integrity checker crashed for %s: %s", site.path, e, exc_info=True)
        else:
            logger.info("Skipping core integrity check (quick mode): %s", site.path)

        # Layer 5: .htaccess scanning
        if self.htaccess_scanner:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                all_threats.extend(self.htaccess_scanner.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during htaccess scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during htaccess scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Htaccess scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 6: mu-plugins scanning
        if self.mu_plugin_scanner:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                all_threats.extend(self.mu_plugin_scanner.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during mu-plugin scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during mu-plugin scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("MuPlugin scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 7: Image scanning (deep mode only — resource intensive)
        if self.image_scanner and self.scan_mode == ScanMode.DEEP:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                all_threats.extend(self.image_scanner.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during image scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during image scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Image scanner crashed for %s: %s", site.path, e, exc_info=True)
        elif self.image_scanner:
            logger.info("Skipping image scan (quick mode): %s", site.path)

        # Layer 8: Network scanning (deep mode only)
        if self.network_scanner and self.scan_mode == ScanMode.DEEP:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                all_threats.extend(self.network_scanner.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during network scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during network scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Network scanner crashed for %s: %s", site.path, e, exc_info=True)
        elif self.network_scanner:
            logger.info("Skipping network scan (quick mode): %s", site.path)

        # Layer 9: Config scanning
        if self.config_scanner:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                all_threats.extend(self.config_scanner.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during config scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during config scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Config scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 10: System scanning
        if self.system_scanner:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                all_threats.extend(self.system_scanner.scan(site))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during system scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during system scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("System scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 11: Checksum verification (validates core files against wordpress.org)
        if self.checksum_verifier:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                core_threats = self.checksum_verifier.verify_core(site)
                all_threats.extend(core_threats)
                logger.info("Checksum verification: %s — %d modified core files",
                           site.path, len(core_threats))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during checksum verification for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during checksum verification for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Checksum verifier crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 12: Capability mapping (behavioral analysis — deep mode only)
        if self.capability_mapper and self.scan_mode == ScanMode.DEEP:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                cap_threats = self.capability_mapper.scan(site)
                all_threats.extend(cap_threats)
                logger.info("Capability mapping: %s — %d behavioral threats",
                           site.path, len(cap_threats))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during capability mapping for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during capability mapping for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Capability mapper crashed for %s: %s", site.path, e, exc_info=True)
        elif self.capability_mapper:
            logger.info("Skipping capability mapping (quick mode): %s", site.path)

        # Layer 13: Entropy scoring (obfuscation detection — deep mode only)
        if self.entropy_scorer and self.scan_mode == ScanMode.DEEP:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                entropy_threats = self.entropy_scorer.scan(site)
                all_threats.extend(entropy_threats)
                logger.info("Entropy scoring: %s — %d obfuscation threats",
                           site.path, len(entropy_threats))
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during entropy scoring for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during entropy scoring for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Entropy scorer crashed for %s: %s", site.path, e, exc_info=True)
        elif self.entropy_scorer:
            logger.info("Skipping entropy scoring (quick mode): %s", site.path)

        # Layer 14: Platform detection + platform-specific config audit
        if self.platform_detector:
            try:
                _check_timeout()
                platform_info = self.platform_detector.detect(site.path)
                logger.info(
                    "Platform detection: %s — %s v%s (confidence: %.0f%%)",
                    site.path, platform_info.platform_type,
                    platform_info.version, platform_info.detection_confidence * 100,
                )
                # Store platform info on site for downstream use
                site.platform_info = platform_info
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during platform detection for %s", site.path)
                return all_threats
            except Exception as e:
                logger.error("Platform detector crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 15: Universal scanning (.env, .git, backups, debug mode, PHP config,
        #           Composer audit, admin tool exposure, symlink attacks)
        if self.universal_scanner:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                platform_info = getattr(site, 'platform_info', None)
                uni_threats = self.universal_scanner.scan(
                    site.path, platform_info=platform_info,
                )
                all_threats.extend(uni_threats)
                logger.info(
                    "Universal scanning: %s — %d cross-platform threats",
                    site.path, len(uni_threats),
                )
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during universal scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during universal scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("Universal scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 16: YARA signature scanning (runs in both quick and deep modes)
        if self.yara_scanner and self.yara_scanner.rules_loaded:
            try:
                _check_timeout()
                _check_memory(self.memory_limit_mb)
                yara_findings = self.yara_scanner.scan_directory(site.path)
                # Convert YaraFinding → Threat objects
                yara_threats = []
                for yf in yara_findings:
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'medium': Severity.MEDIUM,
                        'low': Severity.LOW,
                    }
                    threat = Threat(
                        threat_type=ThreatType.BACKDOOR_FILE,
                        severity=severity_map.get(yf.severity, Severity.MEDIUM),
                        title=f"YARA: {yf.rule_name}",
                        description=yf.description or f"YARA rule '{yf.rule_name}' matched",
                        location=yf.file_path,
                        evidence=str(yf.matched_strings[:5]) if yf.matched_strings else "",
                        site_path=site.path,
                        confidence=0.9,  # YARA signatures are high-confidence
                        details={
                            'check': f'yara_{yf.rule_name}',
                            'scanner': 'yara',
                            'rule_name': yf.rule_name,
                            'tags': yf.tags,
                            'meta': yf.meta,
                        },
                    )
                    yara_threats.append(threat)
                all_threats.extend(yara_threats)
                logger.info(
                    "YARA scanning: %s — %d signature matches",
                    site.path, len(yara_threats),
                )
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during YARA scan for %s", site.path)
                return all_threats
            except MemoryLimitExceeded as e:
                logger.error("Memory limit exceeded during YARA scan for %s: %s", site.path, e)
                return all_threats
            except Exception as e:
                logger.error("YARA scanner crashed for %s: %s", site.path, e, exc_info=True)

        # Layer 17: Vulnerability scanning (WPScan API — checks plugins/themes/core)
        if self.vuln_scanner:
            try:
                _check_timeout()
                vuln_findings: list = []
                vuln_findings.extend(self.vuln_scanner.check_plugins(site.path))
                vuln_findings.extend(self.vuln_scanner.check_themes(site.path))
                if site.wp_version:
                    vuln_findings.extend(
                        self.vuln_scanner.check_core(site.path, site.wp_version)
                    )
                # Convert VulnFinding → Threat objects
                vuln_threats = []
                for vf in vuln_findings:
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'medium': Severity.MEDIUM,
                        'low': Severity.LOW,
                    }
                    cve_str = ', '.join(vf.cve_ids) if vf.cve_ids else None
                    threat = Threat(
                        threat_type=ThreatType.VULNERABLE_PLUGIN,
                        severity=severity_map.get(vf.severity, Severity.MEDIUM),
                        title=vf.title or f"Vulnerable: {vf.plugin_slug} {vf.installed_version}",
                        description=(
                            f"{vf.plugin_slug} {vf.installed_version} has a known vulnerability. "
                            f"Fixed in: {vf.fixed_version or 'N/A'}. "
                            f"CVSS: {vf.cvss_score or 'N/A'}"
                        ),
                        location=f"wp-content/plugins/{vf.plugin_slug}/" if vf.component_type == 'plugin' else f"wp-content/themes/{vf.plugin_slug}/",
                        site_path=site.path,
                        cve=cve_str,
                        confidence=1.0,  # CVE database matches are definitive
                        details={
                            'check': f'vuln_{vf.plugin_slug}_{cve_str or "unknown"}',
                            'scanner': 'vuln_scanner',
                            'plugin_slug': vf.plugin_slug,
                            'installed_version': vf.installed_version,
                            'fixed_version': vf.fixed_version,
                            'cve_ids': vf.cve_ids,
                            'cvss_score': vf.cvss_score,
                            'references': vf.references,
                            'component_type': getattr(vf, 'component_type', 'plugin'),
                        },
                    )
                    vuln_threats.append(threat)
                all_threats.extend(vuln_threats)
                logger.info(
                    "Vulnerability scanning: %s — %d known CVEs found",
                    site.path, len(vuln_threats),
                )
            except SiteScanTimeout:
                logger.error("Site scan timeout reached during vulnerability scan for %s", site.path)
                return all_threats
            except Exception as e:
                logger.error("Vulnerability scanner crashed for %s: %s", site.path, e, exc_info=True)

        # After all layers complete, deduplicate overlapping findings
        all_threats = self._deduplicate_threats(all_threats)

        # Post-scan: Cross-reference with external tools (concordance)
        if self.concordance_engine:
            try:
                concordance_report = self.concordance_engine.concordance(
                    site.path, all_threats,
                )
                # Store report on site for downstream consumption
                site.concordance_report = concordance_report
                stats = concordance_report.stats
                logger.info(
                    "Concordance: %s — %d confirmed, %d CleanShift-only, "
                    "%d external-only (%.0f%% avg confidence)",
                    site.path,
                    stats["confirmed"],
                    stats["cleanshift_only"],
                    stats["external_only"],
                    stats["average_confidence"] * 100,
                )
            except Exception as e:
                logger.error("Concordance engine crashed for %s: %s", site.path, e, exc_info=True)

        elapsed = time.monotonic() - scan_start
        logger.info(
            "Full scan complete: %s — %d total threats in %.1fs (17 layers)",
            site.path, len(all_threats), elapsed,
        )
        return all_threats

    def _deduplicate_threats(self, threats: List[Threat]) -> List[Threat]:
        """
        Remove duplicate findings from overlapping scanners.

        Multiple scanner layers (e.g. FileScanner, ConfigScanner,
        NetworkScanner, HardeningEngine) may flag the same issue.
        This deduplication pass collapses overlapping findings by
        keying on (check_type, location).

        Threats without a 'check' key in details are always kept.

        Args:
            threats: List of all threats collected from all layers.

        Returns:
            Deduplicated list of threats.
        """
        seen = set()  # type: set  # (check_type, location) tuples
        deduped = []  # type: List[Threat]
        for t in threats:
            check = t.details.get('check', '') if t.details else ''
            key = (check, t.location or '')
            if check and key in seen:
                continue  # Already reported by another scanner
            if check:
                seen.add(key)
            deduped.append(t)
        return deduped


# ─── Server Scanner ────────────────────────────────────────────────

class ServerScanner:
    """
    Discovers all WordPress sites on a server and runs SiteScanner
    on each one, producing a complete ScanResult.

    This is the top-level entry point for server-wide scanning.
    """

    def __init__(
        self,
        intel: IntelligenceDB,
        agent_id: str = "",
        server_hostname: str = "",
        scan_mode: ScanMode = ScanMode.DEEP,
        per_file_timeout: int = 30,
        total_site_timeout: int = 600,
        memory_limit_mb: int = 512,
        progress_callback: ProgressCallback = None,
        all_cms: bool = False,
    ) -> None:
        self.intel = intel
        self.scan_mode = scan_mode
        self.site_scanner = SiteScanner(
            intel,
            scan_mode=scan_mode,
            per_file_timeout=per_file_timeout,
            total_site_timeout=total_site_timeout,
            memory_limit_mb=memory_limit_mb,
            progress_callback=progress_callback,
        )
        self.agent_id = agent_id
        self.server_hostname = server_hostname or self._get_hostname()
        self.all_cms = all_cms
        # Lower process priority to avoid overloading shared hosting
        _apply_nice_priority()

    def scan_server(
        self,
        base_path: str = "/home",
        exclude_paths: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Discover all WordPress sites and scan each one.

        Args:
            base_path: Root directory to search for WordPress sites.
            exclude_paths: Paths to skip during scanning.

        Returns:
            Complete ScanResult with all sites and threats.
        """
        result = ScanResult(
            agent_id=self.agent_id,
            server_hostname=self.server_hostname,
        )

        # Discover sites
        wp_roots = discover_wp_sites(base_path)

        if exclude_paths:
            wp_roots = [
                r for r in wp_roots
                if not any(str(r).startswith(ex) for ex in exclude_paths)
            ]

        logger.info("Scanning %d WordPress site(s) ...", len(wp_roots))

        for idx, wp_root in enumerate(wp_roots):
            # Throttle between sites to avoid overloading the server
            if idx > 0:
                _throttle_if_overloaded()
            try:
                site = build_site_info(wp_root)
                result.sites.append(site)

                threats = self.site_scanner.scan(site)
                result.threats.extend(threats)

                logger.info(
                    "Site %d/%d scanned: %s (%d threats)",
                    idx + 1, len(wp_roots), wp_root, len(threats),
                )
            except Exception as e:
                logger.error(
                    "Failed to scan site at %s: %s",
                    wp_root, e, exc_info=True,
                )

        # ── Non-WordPress CMS scanning (when --all-cms is active) ──
        if self.all_cms and _PLATFORM_AVAILABLE and _UNIVERSAL_AVAILABLE:
            logger.info("All-CMS mode: scanning for non-WordPress sites in %s", base_path)
            non_wp_sites = self._discover_non_wp_sites(
                base_path, wp_roots, exclude_paths or [],
            )
            logger.info("Found %d non-WordPress site(s)", len(non_wp_sites))

            for nw_site in non_wp_sites:
                try:
                    result.non_wp_sites.append(nw_site)
                    # Run universal scanners on non-WP sites
                    uni_scanner = self.site_scanner.universal_scanner
                    if uni_scanner:
                        platform_info = PlatformInfo(
                            platform_type=nw_site.platform_type,
                            version=nw_site.version,
                            config_file=nw_site.config_file,
                            detection_confidence=nw_site.detection_confidence,
                        )
                        uni_threats = uni_scanner.scan(
                            nw_site.path, platform_info=platform_info,
                        )
                        result.threats.extend(uni_threats)
                        logger.info(
                            "Non-WP site %s (%s v%s): %d threats",
                            nw_site.path, nw_site.platform_type,
                            nw_site.version, len(uni_threats),
                        )
                except Exception as e:
                    logger.error(
                        "Failed to scan non-WP site at %s: %s",
                        nw_site.path, e, exc_info=True,
                    )

        result.finalize()
        return result

    def scan_site(self, site_path: str) -> ScanResult:
        """
        Scan a single site (WordPress or non-WordPress if all_cms is enabled).

        Args:
            site_path: Absolute path to the site root.

        Returns:
            ScanResult with site details and its threats.
        """
        result = ScanResult(
            agent_id=self.agent_id,
            server_hostname=self.server_hostname,
        )

        path = Path(site_path).resolve()
        is_wp = (path / "wp-config.php").exists()

        if is_wp:
            site = build_site_info(path)
            result.sites.append(site)
            threats = self.site_scanner.scan(site)
            result.threats.extend(threats)
        elif self.all_cms and _PLATFORM_AVAILABLE and _UNIVERSAL_AVAILABLE:
            from .platform import PlatformDetector, PlatformInfo, PlatformType
            detector = PlatformDetector()
            info = detector.detect(str(path))

            # Determine owner from path
            owner = ""
            parts = str(path).split(os.sep)
            if len(parts) >= 3 and parts[1] in ('home', 'Users'):
                owner = parts[2]

            nw_site = NonWPSite(
                path=str(path),
                platform_type=info.platform_type or PlatformType.CUSTOM_PHP,
                version=info.version or "unknown",
                config_file=info.config_file or "",
                detection_confidence=info.detection_confidence or 0.5,
                site_owner=owner,
            )
            result.non_wp_sites.append(nw_site)

            # Run universal scanner
            uni_scanner = self.site_scanner.universal_scanner
            if uni_scanner:
                platform_info = PlatformInfo(
                    platform_type=nw_site.platform_type,
                    version=nw_site.version,
                    config_file=nw_site.config_file,
                    detection_confidence=nw_site.detection_confidence,
                )
                uni_threats = uni_scanner.scan(
                    nw_site.path, platform_info=platform_info,
                )
                result.threats.extend(uni_threats)
        else:
            raise FileNotFoundError(
                f"No WordPress installation found at {site_path}. Use --all-cms to scan."
            )

        result.finalize()
        return result

    def scan_user_home(self, user_or_domain: str) -> ScanResult:
        """
        Scan all WordPress sites under a specific user/domain's directory.

        Used by --post-migration mode. Supports both cPanel and Plesk layouts.

        Args:
            user_or_domain: The cPanel username or Plesk domain name.

        Returns:
            ScanResult with all sites found under the user's home.
        """
        # Try cPanel layout first, then Plesk
        user_home = f"/home/{user_or_domain}"
        if not Path(user_home).exists():
            plesk_home = f"/var/www/vhosts/{user_or_domain}"
            if Path(plesk_home).exists():
                user_home = plesk_home
                logger.info("Plesk layout detected for: %s", user_or_domain)
        logger.info("Post-migration scan for: %s (%s)", user_or_domain, user_home)
        return self.scan_server(base_path=user_home)

    @staticmethod
    def _get_hostname() -> str:
        """Get the server hostname."""
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "unknown"

    def _discover_non_wp_sites(
        self,
        base_path: str,
        wp_roots: List[Path],
        exclude_paths: List[str],
    ) -> 'List[NonWPSite]':
        """
        Walk directories under base_path, skip known WP roots,
        and detect non-WordPress CMS platforms.

        Uses PlatformDetector to identify platforms. Only returns
        directories where a known CMS/framework was detected with
        confidence > 0.3 and where the platform is NOT WordPress
        (since WP sites are already handled by the main pipeline).

        Args:
            base_path: Root directory to search.
            wp_roots: Already-discovered WordPress site paths.
            exclude_paths: Paths to skip.

        Returns:
            List of NonWPSite objects for discovered sites.
        """
        non_wp_sites: List[NonWPSite] = []
        wp_root_strs = {str(r) for r in wp_roots}
        detector = PlatformDetector()

        # Candidate directories: immediate children of user home dirs
        # e.g. /home/user/public_html, /home/user/example.com
        candidates = set()  # type: set
        base = Path(base_path)

        try:
            for user_dir in base.iterdir():
                if not user_dir.is_dir():
                    continue
                user_str = str(user_dir)
                if any(user_str.startswith(ex) for ex in exclude_paths):
                    continue

                # Check immediate subdirectories of each user home
                try:
                    for site_dir in user_dir.iterdir():
                        if not site_dir.is_dir():
                            continue
                        site_str = str(site_dir)

                        # Skip if already a known WP site
                        if site_str in wp_root_strs:
                            continue

                        # Skip if inside an exclude path
                        if any(site_str.startswith(ex) for ex in exclude_paths):
                            continue

                        # Skip dot-directories and common non-site dirs
                        if site_dir.name.startswith('.'):
                            continue
                        skip_names = {
                            'mail', 'logs', 'tmp', 'cache', 'etc',
                            'ssl', '.trash', '.cpanel', '.cagefs',
                            'cpanel3-skel', '.softaculous',
                        }
                        if site_dir.name.lower() in skip_names:
                            continue

                        candidates.add(site_dir)
                except PermissionError:
                    continue
        except PermissionError:
            logger.warning("Permission denied scanning base path: %s", base_path)
            return non_wp_sites

        logger.info("Checking %d candidate directories for non-WP platforms", len(candidates))

        for candidate in sorted(candidates):
            try:
                info = detector.detect(str(candidate))

                # Skip WordPress (already handled), unknown, and low-confidence
                if not info.platform_type:
                    continue
                if info.platform_type == PlatformType.WORDPRESS:
                    continue
                if info.platform_type in (PlatformType.STATIC, PlatformType.CUSTOM_PHP):
                    continue
                if info.detection_confidence < 0.3:
                    continue

                # Determine site owner from path
                owner = ""
                parts = str(candidate).split(os.sep)
                if len(parts) >= 3 and parts[1] in ('home', 'Users'):
                    owner = parts[2]

                non_wp_sites.append(NonWPSite(
                    path=str(candidate),
                    platform_type=info.platform_type,
                    version=info.version,
                    config_file=info.config_file,
                    detection_confidence=info.detection_confidence,
                    site_owner=owner,
                ))

                logger.info(
                    "Detected non-WP site: %s (%s v%s, confidence: %.0f%%)",
                    candidate, info.platform_type, info.version,
                    info.detection_confidence * 100,
                )
            except Exception as e:
                logger.debug("Platform detection failed for %s: %s", candidate, e)

        return non_wp_sites
