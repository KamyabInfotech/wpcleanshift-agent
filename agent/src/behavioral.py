"""
CleanShift Behavioral Analysis Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Detects AI-generated and sophisticated malware that evades traditional
signature-based detection.  Two complementary approaches:

1. **CapabilityMapper** — analyses *what* PHP code can do, then flags
   dangerous *combinations* of capabilities.  A file that reads
   wp-config.php AND makes outbound HTTP calls is exfiltrating
   credentials, even if every individual function call is legitimate.

2. **EntropyScorer** — measures Shannon entropy per line to detect
   obfuscated / packed payloads.  Normal PHP sits around 4.0-5.5
   bits/char; base64 blobs and hex-encoded shells push above 5.8.

Both scanners follow the same ``scan(site) -> List[Threat]`` contract
used by FileScanner, DatabaseScanner, and the extended scanners.

Python 3.6+.  No external dependencies — stdlib only.
"""

import logging
import itertools
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)

logger = logging.getLogger("cleanshift.behavioral")


# ─── Supporting Data Classes ────────────────────────────────────────

@dataclass
class CapabilityProfile:
    """
    Result of capability analysis for a single PHP file.

    Attributes:
        filepath:         Absolute path to the analysed file.
        capabilities:     Mapping of capability name to a list of
                          evidence strings (matched snippets).
        dangerous_combos: List of (combo_names, severity, description)
                          tuples for every matched dangerous combination.
        risk_score:       Aggregate risk score from 0 (benign) to 100.
    """
    filepath = ""           # type: str
    capabilities = None     # type: Dict[str, List[str]]
    dangerous_combos = None  # type: List[Tuple[List[str], Severity, str]]
    risk_score = 0          # type: int

    def __init__(
        self,
        filepath="",                        # type: str
        capabilities=None,                  # type: Optional[Dict[str, List[str]]]
        dangerous_combos=None,              # type: Optional[List[Tuple[List[str], Severity, str]]]
        risk_score=0,                       # type: int
    ):
        # type: (...) -> None
        self.filepath = filepath
        self.capabilities = capabilities if capabilities is not None else {}
        self.dangerous_combos = dangerous_combos if dangerous_combos is not None else []
        self.risk_score = risk_score


@dataclass
class EntropyResult:
    """
    Entropy analysis result for a single file.

    Attributes:
        filepath:              Absolute path.
        overall_entropy:       Weighted average entropy across all lines.
        max_line_entropy:      Highest per-line entropy observed.
        suspicious_line_count: Number of lines exceeding the entropy
                               threshold *and* the minimum line length.
        longest_line_length:   Character count of the longest line.
        risk_level:            One of 'low', 'medium', 'high', 'critical'.
    """
    filepath = ""                # type: str
    overall_entropy = 0.0        # type: float
    max_line_entropy = 0.0       # type: float
    suspicious_line_count = 0    # type: int
    longest_line_length = 0      # type: int
    risk_level = "low"           # type: str

    def __init__(
        self,
        filepath="",                # type: str
        overall_entropy=0.0,        # type: float
        max_line_entropy=0.0,       # type: float
        suspicious_line_count=0,    # type: int
        longest_line_length=0,      # type: int
        risk_level="low",           # type: str
    ):
        # type: (...) -> None
        self.filepath = filepath
        self.overall_entropy = overall_entropy
        self.max_line_entropy = max_line_entropy
        self.suspicious_line_count = suspicious_line_count
        self.longest_line_length = longest_line_length
        self.risk_level = risk_level


# ─── Helpers ────────────────────────────────────────────────────────

def _safe_read_bytes(filepath, max_bytes=262144):
    # type: (str, int) -> bytes
    """Read up to *max_bytes* from *filepath*, returning b'' on error."""
    try:
        with open(filepath, "rb") as fh:
            return fh.read(max_bytes)
    except (OSError, IOError, PermissionError):
        return b""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CapabilityMapper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CapabilityMapper:
    """
    Behavioral analysis engine that detects malware by analysing
    what PHP code CAN DO rather than what it LOOKS LIKE.

    Works by:
      1. Scanning file content for capability indicators
      2. Building a capability profile for the file
      3. Checking for dangerous capability combinations
      4. Scoring the file's risk level

    This catches AI-generated 'clean-looking' malware that uses
    only legitimate WordPress API functions but combines them
    in dangerous ways.
    """

    # ── Capability patterns (compiled once) ──────────────────────────

    CAPABILITIES = {
        "reads_credentials": [
            re.compile(rb"file_get_contents\s*\(.*wp-config", re.IGNORECASE),
            re.compile(rb"DB_PASSWORD", re.IGNORECASE),
            re.compile(rb"DB_USER", re.IGNORECASE),
            re.compile(rb"readfile\s*\(.*wp-config", re.IGNORECASE),
            re.compile(rb"include\s*\(.*wp-config", re.IGNORECASE),
            re.compile(rb"\.htpasswd"),
            re.compile(rb"/etc/passwd"),
            re.compile(rb"/etc/shadow"),
        ],
        "makes_http_calls": [
            re.compile(rb"wp_remote_post\s*\(", re.IGNORECASE),
            re.compile(rb"wp_remote_get\s*\(", re.IGNORECASE),
            re.compile(rb"wp_remote_request\s*\(", re.IGNORECASE),
            re.compile(rb"curl_exec\s*\(", re.IGNORECASE),
            re.compile(rb"curl_init\s*\(", re.IGNORECASE),
            re.compile(rb"file_get_contents\s*\(\s*['\"]https?://", re.IGNORECASE),
            re.compile(rb"fsockopen\s*\(", re.IGNORECASE),
            re.compile(rb"stream_socket_client\s*\(", re.IGNORECASE),
            re.compile(rb"fopen\s*\(\s*['\"]https?://", re.IGNORECASE),
        ],
        "creates_users": [
            re.compile(rb"wp_create_user\s*\(", re.IGNORECASE),
            re.compile(rb"wp_insert_user\s*\(", re.IGNORECASE),
            re.compile(rb"set_role\s*\(\s*['\"]administrator", re.IGNORECASE),
            re.compile(rb"->add_role\s*\(", re.IGNORECASE),
            re.compile(rb"INSERT\s+INTO.*users", re.IGNORECASE),
        ],
        "modifies_files": [
            re.compile(rb"file_put_contents\s*\(", re.IGNORECASE),
            re.compile(rb"fwrite\s*\(", re.IGNORECASE),
            re.compile(rb"fputs\s*\(", re.IGNORECASE),
            re.compile(rb"copy\s*\(", re.IGNORECASE),
            re.compile(rb"rename\s*\(", re.IGNORECASE),
            re.compile(rb"move_uploaded_file\s*\(", re.IGNORECASE),
            re.compile(rb"unlink\s*\(", re.IGNORECASE),
        ],
        "executes_dynamic_code": [
            re.compile(rb"eval\s*\(", re.IGNORECASE),
            re.compile(rb"assert\s*\(", re.IGNORECASE),
            re.compile(rb"preg_replace\s*\(\s*['\"]/.*/e", re.IGNORECASE),
            re.compile(rb"create_function\s*\(", re.IGNORECASE),
            re.compile(rb"call_user_func\s*\(", re.IGNORECASE),
            re.compile(rb"call_user_func_array\s*\(", re.IGNORECASE),
            re.compile(rb"ReflectionFunction", re.IGNORECASE),
            re.compile(rb"\$\{.*\}\s*\("),
        ],
        "reads_http_input": [
            re.compile(rb"\$_GET\b"),
            re.compile(rb"\$_POST\b"),
            re.compile(rb"\$_REQUEST\b"),
            re.compile(rb"\$_COOKIE\b"),
            re.compile(rb"\$_SERVER\[.*HTTP_"),
            re.compile(rb"php://input"),
            re.compile(rb"getallheaders\s*\(", re.IGNORECASE),
        ],
        "accesses_database": [
            re.compile(rb"\$wpdb->query\s*\(", re.IGNORECASE),
            re.compile(rb"\$wpdb->prepare\s*\(", re.IGNORECASE),
            re.compile(rb"\$wpdb->get_results\s*\(", re.IGNORECASE),
            re.compile(rb"mysqli_query\s*\(", re.IGNORECASE),
            re.compile(rb"mysql_query\s*\(", re.IGNORECASE),
            re.compile(rb"PDO::query", re.IGNORECASE),
        ],
        "manipulates_options": [
            re.compile(rb"update_option\s*\(", re.IGNORECASE),
            re.compile(rb"add_option\s*\(", re.IGNORECASE),
            re.compile(rb"delete_option\s*\(", re.IGNORECASE),
            re.compile(rb"update_site_option\s*\(", re.IGNORECASE),
        ],
        "filesystem_discovery": [
            re.compile(rb"scandir\s*\(", re.IGNORECASE),
            re.compile(rb"glob\s*\(", re.IGNORECASE),
            re.compile(rb"opendir\s*\(", re.IGNORECASE),
            re.compile(rb"readdir\s*\(", re.IGNORECASE),
            re.compile(rb"RecursiveDirectoryIterator", re.IGNORECASE),
            re.compile(rb"DirectoryIterator", re.IGNORECASE),
        ],
        "process_execution": [
            re.compile(rb"system\s*\(", re.IGNORECASE),
            re.compile(rb"exec\s*\(", re.IGNORECASE),
            re.compile(rb"passthru\s*\(", re.IGNORECASE),
            re.compile(rb"shell_exec\s*\(", re.IGNORECASE),
            re.compile(rb"popen\s*\(", re.IGNORECASE),
            re.compile(rb"proc_open\s*\(", re.IGNORECASE),
            re.compile(rb"pcntl_exec\s*\(", re.IGNORECASE),
            re.compile(rb"`[^`]+`"),
        ],
        "obfuscation": [
            re.compile(rb"base64_decode\s*\(", re.IGNORECASE),
            re.compile(rb"gzinflate\s*\(", re.IGNORECASE),
            re.compile(rb"gzuncompress\s*\(", re.IGNORECASE),
            re.compile(rb"str_rot13\s*\(", re.IGNORECASE),
            re.compile(rb"rawurldecode\s*\(", re.IGNORECASE),
            re.compile(rb"chr\s*\(\d+\)\s*\.\s*chr\s*\(\d+\)", re.IGNORECASE),
            re.compile(rb"pack\s*\(\s*['\"]H\*", re.IGNORECASE),
            re.compile(rb"\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.IGNORECASE),
        ],
        "disables_security": [
            re.compile(rb"error_reporting\s*\(\s*0\s*\)", re.IGNORECASE),
            re.compile(rb"ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?0", re.IGNORECASE),
            re.compile(rb"ini_set\s*\(\s*['\"]log_errors['\"]\s*,\s*['\"]?0", re.IGNORECASE),
            re.compile(rb"@\s*ini_set", re.IGNORECASE),
            re.compile(rb"set_time_limit\s*\(\s*0\s*\)", re.IGNORECASE),
            re.compile(rb"ignore_user_abort\s*\(\s*true\s*\)", re.IGNORECASE),
        ],
    }

    # ── Dangerous capability combinations ────────────────────────────

    DANGEROUS_COMBOS = [
        # Exfiltration patterns
        (
            ["reads_credentials", "makes_http_calls"],
            Severity.CRITICAL,
            "File reads credentials and makes outbound HTTP calls (data exfiltration)",
        ),
        # Remote admin creation
        (
            ["creates_users", "reads_http_input"],
            Severity.CRITICAL,
            "File creates users based on HTTP input (remote admin injection)",
        ),
        # Dropper / downloader
        (
            ["modifies_files", "makes_http_calls"],
            Severity.HIGH,
            "File downloads content and writes to filesystem (dropper)",
        ),
        # Classic webshell
        (
            ["executes_dynamic_code", "reads_http_input"],
            Severity.CRITICAL,
            "File executes dynamic code from HTTP input (webshell)",
        ),
        # Database manipulation via HTTP
        (
            ["accesses_database", "reads_http_input", "disables_security"],
            Severity.CRITICAL,
            "File runs database queries from HTTP input with security disabled (SQL injection backdoor)",
        ),
        # Reconnaissance + exfiltration
        (
            ["filesystem_discovery", "makes_http_calls"],
            Severity.HIGH,
            "File scans filesystem and sends data externally (reconnaissance)",
        ),
        # Process execution webshell
        (
            ["process_execution", "reads_http_input"],
            Severity.CRITICAL,
            "File executes system commands from HTTP input (command shell)",
        ),
        # Stealth backdoor
        (
            ["executes_dynamic_code", "obfuscation", "disables_security"],
            Severity.CRITICAL,
            "File uses obfuscation, disables security, and executes dynamic code (stealth backdoor)",
        ),
        # Option manipulation backdoor
        (
            ["manipulates_options", "makes_http_calls", "reads_http_input"],
            Severity.HIGH,
            "File modifies WordPress options based on external input (persistent backdoor)",
        ),
        # Full control backdoor
        (
            ["process_execution", "modifies_files", "disables_security"],
            Severity.CRITICAL,
            "File executes commands, modifies files, and disables security (full control backdoor)",
        ),
    ]

    # ── Known-safe frameworks (skip to reduce false positives) ───────

    _SAFE_FRAMEWORK_MARKERS = [
        b"woocommerce",
        b"elementor",
        b"jetpack",
        b"akismet",
        b"yoast",
        b"wordfence",
        b"sucuri",
        b"ithemes-security",
        b"updraftplus",
        b"wpforms",
        b"contact-form-7",
    ]

    # Severity ordering for threshold comparisons
    _SEVERITY_ORDER = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def __init__(self, min_combo_severity=Severity.MEDIUM):
        # type: (Severity) -> None
        """
        Initialise the capability mapper.

        Args:
            min_combo_severity: Minimum combo severity to include in
                                results.  Combos below this level are
                                silently discarded.
        """
        self.min_combo_severity = min_combo_severity

    # ── Public API ───────────────────────────────────────────────────

    def analyze_file(self, filepath, content_bytes):
        # type: (str, bytes) -> CapabilityProfile
        """
        Analyse a single file's content and return its capability profile.

        Args:
            filepath:      Absolute path (used for logging / reporting).
            content_bytes: Raw file content as bytes.

        Returns:
            A populated CapabilityProfile.
        """
        caps = self._extract_capabilities(content_bytes)
        combos = self._check_dangerous_combos(caps)
        score = self._calculate_risk_score(caps, combos)
        return CapabilityProfile(
            filepath=filepath,
            capabilities=caps,
            dangerous_combos=combos,
            risk_score=score,
        )

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """
        Scan all eligible PHP files in a WordPress site.

        Skips core directories (wp-admin/, wp-includes/) and known
        safe plugin frameworks.  Only analyses files in wp-content/
        sub-directories and the site root.

        Args:
            site: The WordPress site to scan.

        Returns:
            List of Threat objects for files with dangerous capability
            combinations.
        """
        threats = []  # type: List[Threat]
        site_path = Path(site.path)

        if not site_path.exists():
            logger.error("Site path does not exist: %s", site_path)
            return threats

        logger.info("CapabilityMapper scan starting: %s", site_path)

        php_files = self._collect_php_files(site_path)
        total = len(php_files)
        logger.info("CapabilityMapper: %d PHP files to analyse", total)

        for idx, php_file in enumerate(php_files):
            if idx % 100 == 0:
                logger.debug(
                    "CapabilityMapper progress: %d/%d (%s)",
                    idx, total, php_file.name,
                )

            try:
                rel_path = str(php_file.relative_to(site_path))

                # Skip WP core files
                if self._is_wp_core_file(rel_path):
                    continue

                content = _safe_read_bytes(str(php_file), max_bytes=262144)
                if not content:
                    continue

                # Skip known-safe frameworks
                if self._is_known_framework(content):
                    logger.debug("Skipping known framework: %s", rel_path)
                    continue

                profile = self.analyze_file(str(php_file), content)

                # Flagging logic:
                #   - At least 2 dangerous combos, OR
                #   - 1 combo at CRITICAL severity
                if not profile.dangerous_combos:
                    continue

                critical_count = sum(
                    1 for _, sev, _ in profile.dangerous_combos
                    if sev == Severity.CRITICAL
                )
                if len(profile.dangerous_combos) < 2 and critical_count < 1:
                    continue

                # Build the threat
                combo_descriptions = [desc for _, _, desc in profile.dangerous_combos]
                cap_names = sorted(profile.capabilities.keys())
                highest_severity = self._highest_severity(profile.dangerous_combos)

                threats.append(Threat(
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    severity=highest_severity,
                    title="Behavioral: dangerous capability combination in %s" % rel_path,
                    description=(
                        "File combines %d dangerous capability patterns "
                        "(risk score %d/100): %s"
                        % (
                            len(profile.dangerous_combos),
                            profile.risk_score,
                            "; ".join(combo_descriptions[:3]),
                        )
                    ),
                    location=str(php_file),
                    evidence="Capabilities: %s" % ", ".join(cap_names),
                    site_path=site.path,
                    details={
                        "capabilities": {
                            k: v[:3] for k, v in profile.capabilities.items()
                        },
                        "dangerous_combos": [
                            {"combo": c, "severity": s.value, "description": d}
                            for c, s, d in profile.dangerous_combos
                        ],
                        "risk_score": profile.risk_score,
                        "analyzer": "capability_mapper",
                    },
                ))

            except Exception as exc:
                logger.warning(
                    "CapabilityMapper error on %s: %s", php_file, exc,
                )

        logger.info(
            "CapabilityMapper scan complete: %s — %d threats found",
            site_path, len(threats),
        )
        return threats

    # ── Internal methods ─────────────────────────────────────────────

    def _extract_capabilities(self, content):
        # type: (bytes) -> Dict[str, List[str]]
        """
        Scan *content* for capability indicators.

        Returns:
            Dict mapping capability name to a list of evidence strings
            (the matched regex snippets).
        """
        found = {}  # type: Dict[str, List[str]]
        for cap_name, patterns in self.CAPABILITIES.items():
            evidence = []  # type: List[str]
            for pat in patterns:
                try:
                    matches = pat.findall(content)
                    for m in matches:
                        snippet = m if isinstance(m, bytes) else m
                        evidence.append(
                            snippet.decode("utf-8", errors="replace")[:120]
                        )
                except Exception:
                    continue
            if evidence:
                found[cap_name] = evidence
        return found

    def _check_dangerous_combos(self, caps):
        # type: (Dict[str, List[str]]) -> List[Tuple[List[str], Severity, str]]
        """
        Check whether the extracted capabilities form any dangerous
        combinations.

        Args:
            caps: Output of ``_extract_capabilities``.

        Returns:
            List of matched (combo_names, severity, description) tuples.
        """
        matched = []  # type: List[Tuple[List[str], Severity, str]]
        cap_names = set(caps.keys())

        for combo_caps, severity, description in self.DANGEROUS_COMBOS:
            # All capabilities in the combo must be present
            if all(c in cap_names for c in combo_caps):
                # Apply minimum severity filter
                if self._SEVERITY_ORDER.get(severity, 0) >= self._SEVERITY_ORDER.get(self.min_combo_severity, 0):
                    matched.append((combo_caps, severity, description))

        return matched

    # Root-level WP core files that legitimately use dangerous capabilities
    _WP_ROOT_CORE_FILES = frozenset({
        "wp-login.php", "wp-cron.php", "wp-settings.php",
        "wp-blog-header.php", "wp-load.php", "wp-mail.php",
        "wp-signup.php", "wp-activate.php", "wp-comments-post.php",
        "wp-links-opml.php", "wp-trackback.php", "xmlrpc.php",
        "index.php", "wp-config.php",
    })

    def _is_wp_core_file(self, rel_path):
        # type: (str) -> bool
        """
        Return True if *rel_path* belongs to a WP core directory or
        is a known WP core root-level file.

        Core files and legitimate plugins/themes contain many capability
        patterns and would cause false positives.  Plugin/theme security
        is handled by PluginAuditor (CVE matching), not behavioral
        heuristics.
        """
        normalized = rel_path.replace("\\", "/").lower()
        if normalized.startswith("wp-admin/"):
            return True
        if normalized.startswith("wp-includes/"):
            return True
        # Known root-level WP core files
        basename = normalized.split("/")[-1]
        if "/" not in normalized and basename in self._WP_ROOT_CORE_FILES:
            return True
        # Plugin and theme files — handled by PluginAuditor, not behavioral
        if normalized.startswith("wp-content/plugins/"):
            return True
        if normalized.startswith("wp-content/themes/"):
            return True
        return False

    def _is_known_framework(self, content):
        # type: (bytes) -> bool
        """
        Return True if file content matches a well-known plugin
        framework that legitimately uses many capabilities.
        """
        content_lower = content[:4096].lower()
        for marker in self._SAFE_FRAMEWORK_MARKERS:
            if marker in content_lower:
                return True
        return False

    def _calculate_risk_score(self, caps, combos):
        # type: (Dict[str, List[str]], List[Tuple[List[str], Severity, str]]) -> int
        """
        Calculate a 0–100 risk score based on capabilities and combos.

        Scoring heuristic:
          - Base: 5 points per distinct capability (max 60)
          - Combo bonus: 15 per HIGH combo, 25 per CRITICAL combo
          - Capped at 100
        """
        # Base score from capability count
        base = min(len(caps) * 5, 60)

        # Combo bonus
        combo_bonus = 0
        for _, severity, _ in combos:
            if severity == Severity.CRITICAL:
                combo_bonus += 25
            elif severity == Severity.HIGH:
                combo_bonus += 15
            elif severity == Severity.MEDIUM:
                combo_bonus += 10
            else:
                combo_bonus += 5

        return min(base + combo_bonus, 100)

    def _collect_php_files(self, site_path):
        # type: (Path) -> List[Path]
        """
        Collect PHP files eligible for capability scanning.

        Only scans high-risk locations where malicious files are planted:
          - Site root (non-core *.php, filtered by _is_wp_core_file)
          - wp-content/uploads/ (PHP should never be here)
          - wp-content/mu-plugins/ (small dir, attacker-favored)

        Plugins and themes are NOT scanned here — their security is
        handled by PluginAuditor (CVE matching against WPVulnDB).
        """
        files = []  # type: List[Path]

        # Root-level PHP files (core files excluded by _is_wp_core_file later)
        try:
            for f in site_path.glob("*.php"):
                if f.is_file():
                    files.append(f)
        except (OSError, PermissionError) as exc:
            logger.warning("Error listing root PHP files: %s", exc)

        # wp-content sub-directories — only high-risk ones
        scan_dirs = [
            site_path / "wp-content" / "uploads",
            site_path / "wp-content" / "mu-plugins",
        ]
        for scan_dir in scan_dirs:
            try:
                if scan_dir.exists():
                    for f in itertools.islice(scan_dir.rglob("*.php"), 50000):
                        if f.is_file():
                            files.append(f)
            except (OSError, PermissionError) as exc:
                logger.warning("Error scanning %s: %s", scan_dir, exc)

        return files

    def _highest_severity(self, combos):
        # type: (List[Tuple[List[str], Severity, str]]) -> Severity
        """Return the highest severity among a list of matched combos."""
        if not combos:
            return Severity.LOW
        return max(
            (sev for _, sev, _ in combos),
            key=lambda s: self._SEVERITY_ORDER.get(s, 0),
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EntropyScorer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class EntropyScorer:
    """
    Measures Shannon entropy of PHP file content to detect obfuscation.

    Normal PHP code:        entropy ~4.0–5.5 bits/char
    Obfuscated code:        entropy ~5.8–6.5+ bits/char
    Base64 / hex strings:   entropy ~5.5–6.0 bits/char

    High-entropy lines in a PHP file strongly indicate obfuscation,
    especially when combined with long line lengths.
    """

    def __init__(
        self,
        entropy_threshold=5.8,    # type: float
        min_line_length=200,      # type: int
        min_suspicious_lines=3,   # type: int
    ):
        # type: (...) -> None
        """
        Initialise the entropy scorer.

        Args:
            entropy_threshold:    Per-line entropy above which the line
                                  is considered suspicious (bits/char).
            min_line_length:      Lines shorter than this are ignored
                                  when counting suspicious lines.
            min_suspicious_lines: Number of suspicious lines needed to
                                  flag the file.
        """
        self.entropy_threshold = entropy_threshold
        self.min_line_length = min_line_length
        self.min_suspicious_lines = min_suspicious_lines

    # ── Public API ───────────────────────────────────────────────────

    def score_file(self, filepath):
        # type: (str) -> Optional[EntropyResult]
        """
        Compute entropy metrics for a single file.

        Args:
            filepath: Absolute path to the file.

        Returns:
            An EntropyResult, or None if the file is too small, binary,
            or otherwise not analysable.
        """
        if self._is_likely_data_file(filepath):
            logger.debug("Skipping data/binary file: %s", filepath)
            return None

        content = _safe_read_bytes(filepath, max_bytes=524288)
        if len(content) < 100:
            logger.debug("Skipping tiny file (%d bytes): %s", len(content), filepath)
            return None

        # Rough binary check: if > 30 % of bytes are non-text, skip.
        non_text = sum(1 for b in content[:2048] if b < 9 or (13 < b < 32))
        sample_size = min(len(content), 2048)
        if sample_size > 0 and non_text / sample_size > 0.30:
            logger.debug("Skipping binary file: %s", filepath)
            return None

        overall = self._shannon_entropy(content)
        line_analysis = self._analyze_lines(content)

        suspicious_count = line_analysis["suspicious_count"]
        max_entropy = line_analysis["max_entropy"]
        longest = line_analysis["longest_line"]

        risk = self._determine_risk_level(
            overall, suspicious_count, max_entropy, longest,
        )

        return EntropyResult(
            filepath=filepath,
            overall_entropy=round(overall, 4),
            max_line_entropy=round(max_entropy, 4),
            suspicious_line_count=suspicious_count,
            longest_line_length=longest,
            risk_level=risk,
        )

    def scan(self, site):
        # type: (WordPressSite) -> List[Threat]
        """
        Scan all PHP files in a WordPress site for high-entropy content.

        Args:
            site: The WordPress site to scan.

        Returns:
            List of Threat objects for files with suspiciously high
            entropy.
        """
        threats = []  # type: List[Threat]
        site_path = Path(site.path)

        if not site_path.exists():
            logger.error("Site path does not exist: %s", site_path)
            return threats

        logger.info("EntropyScorer scan starting: %s", site_path)

        # Root-level WP core files with legitimately high entropy (e.g., random salts)
        _WP_ROOT_CORE = {
            "wp-config.php", "index.php", "wp-login.php",
            "wp-cron.php", "wp-settings.php", "wp-blog-header.php",
            "wp-load.php", "wp-mail.php", "wp-signup.php",
            "wp-activate.php", "wp-comments-post.php",
            "wp-links-opml.php", "wp-trackback.php", "xmlrpc.php",
        }

        php_files = []  # type: List[Path]
        try:
            for f in itertools.islice(site_path.rglob("*.php"), 50000):
                if f.is_file():
                    # Skip WP core directories, plugins, themes
                    try:
                        rel = str(f.relative_to(site_path)).replace("\\", "/").lower()
                    except ValueError:
                        continue
                    if rel.startswith("wp-admin/") or rel.startswith("wp-includes/"):
                        continue
                    # Skip plugins and themes — minified/cached code has high entropy
                    if rel.startswith("wp-content/plugins/") or rel.startswith("wp-content/themes/"):
                        continue
                    # Skip root-level WP core files
                    basename = rel.split("/")[-1]
                    if "/" not in rel and basename in _WP_ROOT_CORE:
                        continue
                    php_files.append(f)
        except (OSError, PermissionError) as exc:
            logger.warning("Error collecting PHP files: %s", exc)

        total = len(php_files)
        logger.info("EntropyScorer: %d PHP files to analyse", total)

        for idx, php_file in enumerate(php_files):
            if idx % 100 == 0:
                logger.debug(
                    "EntropyScorer progress: %d/%d (%s)",
                    idx, total, php_file.name,
                )
            try:
                result = self.score_file(str(php_file))
                if result is None:
                    continue

                if result.risk_level in ("high", "critical"):
                    try:
                        rel_path = str(php_file.relative_to(site_path))
                    except ValueError:
                        rel_path = php_file.name

                    severity = (
                        Severity.CRITICAL
                        if result.risk_level == "critical"
                        else Severity.HIGH
                    )

                    threats.append(Threat(
                        threat_type=ThreatType.SUSPICIOUS_FILE,
                        severity=severity,
                        title="High-entropy PHP file: %s" % rel_path,
                        description=(
                            "File has overall entropy %.2f bits/char with %d "
                            "suspicious lines (max line entropy %.2f). "
                            "This strongly indicates obfuscated or packed "
                            "malware."
                            % (
                                result.overall_entropy,
                                result.suspicious_line_count,
                                result.max_line_entropy,
                            )
                        ),
                        location=str(php_file),
                        evidence=(
                            "Overall entropy: %.2f, max line entropy: %.2f, "
                            "suspicious lines: %d, longest line: %d chars"
                            % (
                                result.overall_entropy,
                                result.max_line_entropy,
                                result.suspicious_line_count,
                                result.longest_line_length,
                            )
                        ),
                        site_path=site.path,
                        details={
                            "overall_entropy": result.overall_entropy,
                            "max_line_entropy": result.max_line_entropy,
                            "suspicious_line_count": result.suspicious_line_count,
                            "longest_line_length": result.longest_line_length,
                            "risk_level": result.risk_level,
                            "analyzer": "entropy_scorer",
                        },
                    ))

            except Exception as exc:
                logger.warning("EntropyScorer error on %s: %s", php_file, exc)

        logger.info(
            "EntropyScorer scan complete: %s — %d threats found",
            site_path, len(threats),
        )
        return threats

    # ── Internal methods ─────────────────────────────────────────────

    def _shannon_entropy(self, data):
        # type: (bytes) -> float
        """
        Calculate Shannon entropy of a byte string.

        Returns entropy in bits per byte (0.0–8.0).  An empty input
        returns 0.0.
        """
        length = len(data)
        if length == 0:
            return 0.0

        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _analyze_lines(self, content):
        # type: (bytes) -> Dict[str, Any]
        """
        Perform per-line entropy analysis.

        Returns a dict with:
          - ``suspicious_count``: lines exceeding both length and
            entropy thresholds
          - ``max_entropy``: highest per-line entropy observed
          - ``longest_line``: length of the longest line
        """
        lines = content.split(b"\n")
        suspicious = 0
        max_ent = 0.0
        longest = 0

        for line in lines:
            line_len = len(line)
            if line_len > longest:
                longest = line_len

            if line_len < 10:
                # Skip trivially short lines
                continue

            ent = self._shannon_entropy(line)
            if ent > max_ent:
                max_ent = ent

            if line_len >= self.min_line_length and ent > self.entropy_threshold:
                suspicious += 1

        return {
            "suspicious_count": suspicious,
            "max_entropy": max_ent,
            "longest_line": longest,
        }

    def _determine_risk_level(self, overall, suspicious_count, max_entropy, longest_line):
        # type: (float, int, float, int) -> str
        """
        Determine the risk level string from entropy metrics.

        Returns one of 'low', 'medium', 'high', 'critical'.
        """
        # Critical: overall entropy very high
        if overall > 6.0:
            return "critical"

        # Critical: single packed/obfuscated mega-line
        if longest_line > 5000 and max_entropy > 5.5:
            return "critical"

        # High: multiple suspicious lines
        if suspicious_count >= self.min_suspicious_lines:
            return "high"

        # Medium: some entropy anomalies but below main thresholds
        if suspicious_count >= 1 or (overall > 5.5 and longest_line > 500):
            return "medium"

        return "low"

    def _is_likely_data_file(self, filepath):
        # type: (str) -> bool
        """
        Return True if the file is likely minified JS/CSS, an image,
        or another non-PHP data file that would produce misleading
        entropy readings.
        """
        try:
            name = os.path.basename(filepath).lower()
        except Exception:
            return False

        # Minified JS/CSS — entropy is naturally high
        if name.endswith((".min.js", ".min.css")):
            return True

        # Non-PHP extensions that are data or binary
        data_exts = (
            ".js", ".css", ".map", ".json",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
            ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".zip", ".gz", ".tar", ".rar",
            ".pdf", ".doc", ".docx",
            ".mp3", ".mp4", ".wav", ".avi",
        )
        for ext in data_exts:
            if name.endswith(ext):
                return True

        return False
