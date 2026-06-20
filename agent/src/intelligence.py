"""
CleanShift Intelligence Loader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Loads and queries the IoC database and remediation playbooks from the
intelligence directory. Provides fast matching functions used by the
scanning engine.

The intelligence directory structure:
    intelligence/
        indicators/ioc-database.yaml    — IoC database
        playbooks/*.yaml                — Remediation playbooks
        attack-chains/*.md              — Attack documentation
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Threat

import yaml

# Try importing the encrypted bundle module (available in production builds)
try:
    from .intel_bundle import load_bundle as _load_intel_bundle
except ImportError:
    _load_intel_bundle = None  # type: ignore[assignment]

logger = logging.getLogger("cleanshift.intelligence")

# Default intelligence directory — sibling of the agent/ directory
_DEFAULT_INTEL_DIR = Path(__file__).resolve().parent.parent.parent / "intelligence"


# ─── IoC Data Structures ───────────────────────────────────────────

@dataclass
class MalwareDomain:
    """A known malicious domain used for script injection."""
    domain: str
    type: str = ""
    payload: str = ""
    first_seen: str = ""
    found_in: str = ""
    cve: str = ""
    source: str = ""


@dataclass
class RogueAdminPattern:
    """Pattern for attacker-created WordPress admin accounts."""
    username_pattern: str = ""
    email_pattern: str = ""
    email_example: str = ""
    role: str = "administrator"
    registration_date: str = ""
    cve: str = ""
    behavior: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class DbMarker:
    """Database option planted by malware for persistence or tracking."""
    table: str = "wp_options"
    option_name: str = ""
    option_value: Optional[str] = None
    value_contains: Optional[str] = None
    purpose: str = ""
    prevalence: str = ""
    cve: str = ""
    source: str = ""


@dataclass
class BackdoorFilename:
    """Known malicious file name/pattern and its expected location."""
    name: str = ""
    location: str = ""
    size: str = "variable"
    note: str = ""
    risk: str = "high"
    source: str = ""


@dataclass
class AdminScramblePattern:
    """How attackers modify existing admin accounts."""
    original_username: str = ""
    scrambled_to: str = ""
    pattern: str = ""
    email_changed_to: str = ""
    note: str = ""


@dataclass
class VulnerablePlugin:
    """A plugin with known exploitable vulnerabilities."""
    name: str = ""
    slug: str = ""
    vulnerable_versions: str = ""
    cve: str = ""
    exploit_type: str = ""
    disclosed: str = ""
    patched_version: str = ""
    severity: str = "high"
    note: str = ""
    db_footprint: str = ""
    detection: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class DetectionQuery:
    """A pre-built SQL query for detecting compromise indicators."""
    name: str = ""
    description: str = ""
    sql: str = ""


@dataclass
class PlaybookStep:
    """A single step within a remediation playbook phase."""
    step: str = ""
    description: str = ""
    command: Optional[str] = None
    commands: Optional[List[str]] = None
    fallback_sql: Optional[str] = None
    manual_steps: Optional[List[str]] = None
    requires_approval: bool = False
    automated: bool = True
    check: Optional[str] = None
    expected: Optional[str] = None
    requires_manual_review: bool = False
    # Hardening-specific fields
    htaccess_rules: Optional[str] = None
    wp_config: Optional[str] = None
    manual: bool = False
    notes: Optional[str] = None
    prerequisite: Optional[str] = None


@dataclass
class Playbook:
    """A complete remediation playbook with multiple phases."""
    name: str = ""
    description: str = ""
    severity: str = "high"
    estimated_time: str = ""
    automated: str = "partially"
    phases: Dict[str, List[PlaybookStep]] = field(default_factory=dict)
    server_wide: Dict[str, Any] = field(default_factory=dict)


# ─── IoC Match Result ──────────────────────────────────────────────

@dataclass
class IoC:
    """
    Result of an IoC match — provides context about what was matched
    and what threat category it falls into.
    """
    indicator_type: str      # "malware_domain", "backdoor_file", etc.
    matched_value: str       # What was found
    severity: str = "high"
    cve: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


# ─── Intelligence Database ─────────────────────────────────────────

class IntelligenceDB:
    """
    Loads the IoC database and playbooks from disk and provides
    fast lookup functions for the scanning engine.

    Usage:
        intel = IntelligenceDB()
        intel.load()
        ioc = intel.match_filename("defaults.php")
    """

    def __init__(self, intel_dir: Optional[Path] = None) -> None:
        self.intel_dir = Path(intel_dir) if intel_dir else _DEFAULT_INTEL_DIR

        # Security: resolve the path to canonical form
        # This neutralises any '..' components while allowing relative paths
        self.intel_dir = Path(self.intel_dir).resolve()

        self.malware_domains: List[MalwareDomain] = []
        self.rogue_admin_patterns: List[RogueAdminPattern] = []
        self.db_markers: List[DbMarker] = []
        self.backdoor_filenames: List[BackdoorFilename] = []
        self.admin_scramble_patterns: List[AdminScramblePattern] = []
        self.vulnerable_plugins: List[VulnerablePlugin] = []
        self.detection_queries: List[DetectionQuery] = []
        self.playbooks: Dict[str, Playbook] = {}
        self._loaded = False

    def load(self) -> None:
        """Load all intelligence data.

        Tries the encrypted bundle first (production).  Falls back to
        raw YAML files on disk (development mode).
        """
        loaded_from_bundle = False

        # ── Try encrypted bundle first ──────────────────────────
        if _load_intel_bundle is not None:
            try:
                bundle = _load_intel_bundle()
                if bundle:
                    self._load_from_bundle(bundle)
                    loaded_from_bundle = True
                    logger.info(
                        "Loaded intelligence from encrypted bundle (v%s)",
                        bundle.get("version", "unknown"),
                    )
            except Exception as exc:
                logger.warning(
                    "Encrypted bundle load failed, falling back to YAML: %s", exc
                )

        # ── Fall back to raw YAML files ─────────────────────────
        if not loaded_from_bundle:
            self._load_ioc_database()
            self._load_playbooks()
            logger.info("Loaded intelligence from YAML files (development mode)")

        self._loaded = True
        logger.info(
            "Intelligence ready: %d domains, %d backdoor patterns, "
            "%d vuln plugins, %d detection queries, %d playbooks",
            len(self.malware_domains),
            len(self.backdoor_filenames),
            len(self.vulnerable_plugins),
            len(self.detection_queries),
            len(self.playbooks),
        )

    def _ensure_loaded(self) -> None:
        """Lazy-load if not already loaded."""
        if not self._loaded:
            self.load()

    # ── Bundle Loading ──────────────────────────────────────────

    def _load_from_bundle(self, bundle: Dict[str, Any]) -> None:
        """Hydrate data structures from a decrypted intelligence bundle."""
        # Indicators (same structure as the YAML IoC database)
        indicators = bundle.get("indicators", {})
        if indicators:
            self._hydrate_indicators(indicators)

        # Playbooks (list of raw dicts, same structure as YAML files)
        for pb_data in bundle.get("playbooks", []):
            try:
                pb = self._hydrate_playbook(pb_data)
                if pb:
                    self.playbooks[pb.name] = pb
            except Exception as e:
                logger.error("Failed to hydrate bundled playbook: %s", e)

    def _hydrate_indicators(self, data: Dict[str, Any]) -> None:
        """Populate indicator lists from a parsed dict (bundle or YAML)."""
        for entry in data.get("malware_domains", []):
            self.malware_domains.append(MalwareDomain(
                domain=entry.get("domain", ""),
                type=entry.get("type", ""),
                payload=entry.get("payload", ""),
                first_seen=str(entry.get("first_seen", "")),
                found_in=entry.get("found_in", ""),
                cve=entry.get("cve", ""),
                source=entry.get("source", ""),
            ))
        for entry in data.get("rogue_admin_patterns", []):
            self.rogue_admin_patterns.append(RogueAdminPattern(
                username_pattern=entry.get("username_pattern", ""),
                email_pattern=entry.get("email_pattern", ""),
                email_example=entry.get("email_example", ""),
                role=entry.get("role", "administrator"),
                registration_date=str(entry.get("registration_date", "")),
                cve=entry.get("cve", ""),
                behavior=entry.get("behavior", []),
                source=entry.get("source", ""),
            ))
        for entry in data.get("db_markers", []):
            self.db_markers.append(DbMarker(
                table=entry.get("table", "wp_options"),
                option_name=entry.get("option_name", ""),
                option_value=entry.get("option_value"),
                value_contains=entry.get("value_contains"),
                purpose=entry.get("purpose", ""),
                prevalence=entry.get("prevalence", ""),
                cve=entry.get("cve", ""),
                source=entry.get("source", ""),
            ))
        for entry in data.get("backdoor_filenames", []):
            self.backdoor_filenames.append(BackdoorFilename(
                name=entry.get("name", ""),
                location=entry.get("location", ""),
                size=str(entry.get("size", "variable")),
                note=entry.get("note", ""),
                risk=entry.get("risk", "high"),
                source=entry.get("source", ""),
            ))
        for entry in data.get("admin_scramble_patterns", []):
            self.admin_scramble_patterns.append(AdminScramblePattern(
                original_username=entry.get("original_username", ""),
                scrambled_to=entry.get("scrambled_to", ""),
                pattern=entry.get("pattern", ""),
                email_changed_to=entry.get("email_changed_to", ""),
                note=entry.get("note", ""),
            ))
        for entry in data.get("vulnerable_plugins", []):
            self.vulnerable_plugins.append(VulnerablePlugin(
                name=entry.get("name", ""),
                slug=entry.get("slug", ""),
                vulnerable_versions=entry.get("vulnerable_versions", ""),
                cve=entry.get("cve", ""),
                exploit_type=entry.get("exploit_type", ""),
                disclosed=str(entry.get("disclosed", "")),
                patched_version=entry.get("patched_version", ""),
                severity=entry.get("severity", "high"),
                note=entry.get("note", ""),
                db_footprint=entry.get("db_footprint", ""),
                detection=entry.get("detection", []),
                source=entry.get("source", ""),
            ))
        for entry in data.get("detection_queries", []):
            self.detection_queries.append(DetectionQuery(
                name=entry.get("name", ""),
                description=entry.get("description", ""),
                sql=entry.get("sql", ""),
            ))

    def _hydrate_playbook(self, data: Dict[str, Any]) -> Optional[Playbook]:
        """Parse a playbook from a dict (bundle or YAML)."""
        if not data:
            return None

        pb = Playbook(
            name=data.get("name", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "high"),
            estimated_time=data.get("estimated_time", ""),
            automated=str(data.get("automated", "partially")),
        )

        phase_keys = [
            k for k in data.keys()
            if k.startswith("phase_") and isinstance(data[k], list)
        ]
        for phase_key in sorted(phase_keys):
            steps: List[PlaybookStep] = []
            for step_data in data[phase_key]:
                command = step_data.get("command")
                if command and not self._validate_playbook_command(command):
                    logger.warning('Blocked dangerous playbook command: %s', command[:80])
                    command = None

                commands = step_data.get("commands")
                if commands:
                    safe_commands = []
                    for cmd in commands:
                        if cmd and not self._validate_playbook_command(cmd):
                            logger.warning('Blocked dangerous playbook command: %s', cmd[:80])
                        else:
                            safe_commands.append(cmd)
                    commands = safe_commands if safe_commands else None

                step = PlaybookStep(
                    step=step_data.get("step", ""),
                    description=step_data.get("description", ""),
                    command=command,
                    commands=commands,
                    fallback_sql=step_data.get("fallback_sql"),
                    manual_steps=step_data.get("manual_steps"),
                    requires_approval=step_data.get("requires_approval", False),
                    automated=step_data.get("automated", True),
                    check=step_data.get("check"),
                    expected=step_data.get("expected"),
                    requires_manual_review=step_data.get("requires_manual_review", False),
                    htaccess_rules=step_data.get("htaccess_rules"),
                    wp_config=step_data.get("wp_config"),
                    manual=step_data.get("manual", False),
                    notes=step_data.get("notes"),
                    prerequisite=step_data.get("prerequisite"),
                )
                steps.append(step)
            pb.phases[phase_key] = steps

        if "server_wide" in data and isinstance(data["server_wide"], dict):
            pb.server_wide = data["server_wide"]

        return pb

    # ── IoC Database Loading ────────────────────────────────────

    def _load_ioc_database(self) -> None:
        """Parse ioc-database.yaml into typed data structures."""
        ioc_path = self.intel_dir / "indicators" / "ioc-database.yaml"
        if not ioc_path.exists():
            logger.warning("IoC database not found at %s", ioc_path)
            return

        try:
            with open(ioc_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error("Failed to parse IoC database: %s", e)
            return

        if not data:
            logger.warning("IoC database is empty")
            return

        self._hydrate_indicators(data)
        logger.debug("IoC database loaded from %s", ioc_path)

    # ── Playbook Loading ────────────────────────────────────────

    def _load_playbooks(self) -> None:
        """Load all playbook YAML files from the playbooks directory."""
        playbooks_dir = self.intel_dir / "playbooks"
        if not playbooks_dir.exists():
            logger.warning("Playbooks directory not found at %s", playbooks_dir)
            return

        for yaml_file in playbooks_dir.glob("*.yaml"):
            try:
                pb = self._parse_playbook(yaml_file)
                if pb:
                    self.playbooks[pb.name] = pb
                    logger.debug("Loaded playbook: %s", pb.name)
            except Exception as e:
                logger.error("Failed to load playbook %s: %s", yaml_file, e)

    # Defense-in-depth: basic blocklist for playbook commands.
    # NOTE: This is NOT a security boundary — a determined attacker can trivially
    # bypass it (e.g. /bin/rm, bash -c, find -delete). The real protection is:
    #   1. Playbook YAML files should be read-only, owned by root
    #   2. The intel_dir path is resolved to prevent traversal
    #   3. shlex.quote() is applied to all substituted variables
    _BLOCKED_COMMAND_PREFIXES = (
        'rm -rf /', 'dd if=', 'mkfs', ':(){', 'chmod 777 /',
        'curl|', 'wget|',
    )

    @staticmethod
    def _validate_playbook_command(cmd: str) -> bool:
        """Reject obviously dangerous playbook commands (defense-in-depth)."""
        cmd_lower = cmd.strip().lower()
        for prefix in IntelligenceDB._BLOCKED_COMMAND_PREFIXES:
            if cmd_lower.startswith(prefix):
                return False
        return True

    def _parse_playbook(self, path: Path) -> Optional[Playbook]:
        """Parse a single playbook YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return None

        # Use path.stem as fallback name if the YAML doesn't have one
        if "name" not in data:
            data["name"] = path.stem

        return self._hydrate_playbook(data)

    # ── Matching Functions ──────────────────────────────────────

    def match_filename(self, filepath: str) -> Optional[IoC]:
        """
        Check if a filename matches any known backdoor pattern.

        Args:
            filepath: Relative or absolute path to the file.

        Returns:
            IoC if matched, None otherwise.
        """
        self._ensure_loaded()
        filename = Path(filepath).name
        parent = str(Path(filepath).parent)

        for bd in self.backdoor_filenames:
            # Match the filename pattern (supports glob via fnmatch)
            if fnmatch.fnmatch(filename, bd.name):
                # If location is specified, do a loose location check
                if bd.location and bd.location not in ("any",):
                    # Normalize location for comparison
                    loc = bd.location.split("(")[0].strip().rstrip("/")
                    if loc and loc not in parent:
                        continue

                return IoC(
                    indicator_type="backdoor_file",
                    matched_value=filepath,
                    severity=bd.risk if bd.risk else "high",
                    details={
                        "pattern": bd.name,
                        "expected_location": bd.location,
                        "note": bd.note,
                        "source": bd.source,
                        "size_hint": bd.size,
                    },
                )

        return None

    def match_domain(self, url: str) -> Optional[IoC]:
        """
        Check if a URL or domain string matches any known malware domain.

        Args:
            url: URL, domain, or text that may contain a malicious domain.

        Returns:
            IoC if matched, None otherwise.
        """
        self._ensure_loaded()
        url_lower = url.lower()

        for md in self.malware_domains:
            if md.domain.lower() in url_lower:
                return IoC(
                    indicator_type="malware_domain",
                    matched_value=md.domain,
                    severity="critical",
                    cve=md.cve,
                    details={
                        "type": md.type,
                        "payload": md.payload,
                        "first_seen": md.first_seen,
                        "source": md.source,
                    },
                )

        return None

    def match_db_option(self, option_name: str, option_value: str = "") -> Optional[IoC]:
        """
        Check if a database option matches known malware markers.

        Args:
            option_name: The wp_options option_name.
            option_value: The option_value (if available).

        Returns:
            IoC if matched, None otherwise.
        """
        self._ensure_loaded()

        for marker in self.db_markers:
            # Exact option_name match
            if marker.option_name and marker.option_name == option_name:
                # If marker has a specific value, check it
                if marker.option_value is not None:
                    if str(marker.option_value) == str(option_value):
                        return IoC(
                            indicator_type="db_marker",
                            matched_value=option_name,
                            severity="critical",
                            cve=marker.cve,
                            details={
                                "table": marker.table,
                                "option_value": option_value,
                                "purpose": marker.purpose,
                                "source": marker.source,
                            },
                        )
                # If marker uses value_contains, do a substring check
                elif marker.value_contains:
                    if marker.value_contains in option_value:
                        return IoC(
                            indicator_type="db_marker",
                            matched_value=option_name,
                            severity="critical",
                            cve=marker.cve,
                            details={
                                "table": marker.table,
                                "value_contains": marker.value_contains,
                                "purpose": marker.purpose,
                                "source": marker.source,
                            },
                        )
                else:
                    # Just matching on option_name is enough
                    return IoC(
                        indicator_type="db_marker",
                        matched_value=option_name,
                        severity="high",
                        cve=marker.cve,
                        details={
                            "table": marker.table,
                            "purpose": marker.purpose,
                            "source": marker.source,
                        },
                    )

        # Also check if the value contains any known malware domains
        if option_value:
            domain_match = self.match_domain(option_value)
            if domain_match:
                return IoC(
                    indicator_type="script_injection",
                    matched_value=option_name,
                    severity="critical",
                    cve=domain_match.cve,
                    details={
                        "injected_domain": domain_match.matched_value,
                        **domain_match.details,
                    },
                )

        return None

    def match_plugin(self, slug: str, version: str = "") -> Optional[IoC]:
        """
        Check if an installed plugin is known-vulnerable.

        Uses version comparison when possible; falls back to flagging
        any installation of the plugin if version parsing fails.

        Args:
            slug: Plugin slug (e.g. "litespeed-cache").
            version: Currently installed version string.

        Returns:
            IoC if the plugin is vulnerable, None otherwise.
        """
        self._ensure_loaded()

        for vp in self.vulnerable_plugins:
            if vp.slug.lower() != slug.lower():
                continue

            is_vulnerable = False

            if version and vp.patched_version:
                is_vulnerable = self._version_lt(version, vp.patched_version)
            elif version and vp.vulnerable_versions:
                is_vulnerable = self._version_in_range(version, vp.vulnerable_versions)
            else:
                # Can't determine version — flag it for review
                is_vulnerable = True

            if is_vulnerable:
                return IoC(
                    indicator_type="vulnerable_plugin",
                    matched_value=f"{vp.slug}@{version or 'unknown'}",
                    severity=vp.severity,
                    cve=vp.cve,
                    details={
                        "plugin_name": vp.name,
                        "slug": vp.slug,
                        "installed_version": version,
                        "vulnerable_versions": vp.vulnerable_versions,
                        "patched_version": vp.patched_version,
                        "exploit_type": vp.exploit_type,
                        "note": vp.note,
                        "db_footprint": vp.db_footprint,
                    },
                )

        return None

    def get_detection_queries(self) -> List[DetectionQuery]:
        """Return all detection queries from the IoC database."""
        self._ensure_loaded()
        return list(self.detection_queries)

    def get_rogue_admin_patterns(self) -> List[RogueAdminPattern]:
        """Return all known rogue admin patterns."""
        self._ensure_loaded()
        return list(self.rogue_admin_patterns)

    def get_admin_scramble_patterns(self) -> List[AdminScramblePattern]:
        """Return all known admin scramble patterns."""
        self._ensure_loaded()
        return list(self.admin_scramble_patterns)

    def get_playbook(self, name: str) -> Optional[Playbook]:
        """
        Get a remediation playbook by name.

        Args:
            name: Playbook name (e.g. "cve-2024-28000-litespeed-cache").

        Returns:
            Playbook if found, None otherwise.
        """
        self._ensure_loaded()
        return self.playbooks.get(name)

    def list_playbooks(self) -> List[str]:
        """Return the names of all loaded playbooks."""
        self._ensure_loaded()
        return list(self.playbooks.keys())

    def match_playbook(self, threats: List[Threat]) -> Optional[Playbook]:
        """Auto-match threats to the best playbook based on CVE/pattern overlap.

        Scores each playbook by counting how many threats reference a CVE
        that appears in the playbook name or description, or whose plugin
        slug appears in the playbook name.

        Args:
            threats: List of detected threats to match against.

        Returns:
            The highest-scoring Playbook, or None if no match is found.
        """
        self._ensure_loaded()

        if not threats or not self.playbooks:
            return None

        best_playbook: Optional[Playbook] = None
        best_score = 0

        for pb_name, pb in self.playbooks.items():
            score = 0
            pb_text = f"{pb_name} {pb.description}".lower()

            for threat in threats:
                # Match by CVE — check if the threat's CVE appears in the
                # playbook name or description
                if threat.cve:
                    cve_lower = threat.cve.lower()
                    if cve_lower in pb_text:
                        score += 2  # Strong signal

                # Match by plugin slug — check if the threat's plugin slug
                # appears in the playbook name
                plugin_slug = threat.details.get("plugin_slug", "") or threat.details.get("slug", "")
                if plugin_slug:
                    slug_lower = plugin_slug.lower()
                    if slug_lower in pb_text:
                        score += 1

            if score > best_score:
                best_score = score
                best_playbook = pb

        return best_playbook

    # ── Version Comparison Helpers ──────────────────────────────

    @staticmethod
    def _parse_version(version: str) -> List[int]:
        """Parse a dotted version string into a list of integers."""
        parts = []
        for part in version.strip().split("."):
            # Extract leading digits only (handle things like "6.4.1-beta")
            match = re.match(r"(\d+)", part)
            if match:
                parts.append(int(match.group(1)))
        return parts

    @classmethod
    def _version_lt(cls, v1: str, v2: str) -> bool:
        """Check if version v1 is less than v2."""
        p1 = cls._parse_version(v1)
        p2 = cls._parse_version(v2)
        # Pad to equal length
        max_len = max(len(p1), len(p2))
        p1.extend([0] * (max_len - len(p1)))
        p2.extend([0] * (max_len - len(p2)))
        return p1 < p2

    @classmethod
    def _version_in_range(cls, version: str, range_spec: str) -> bool:
        """
        Check if a version matches a range specifier like '<6.4.1'.

        Supports: <X.Y.Z, <=X.Y.Z, >X.Y.Z, >=X.Y.Z
        """
        range_spec = range_spec.strip()

        if range_spec.startswith("<="):
            target = range_spec[2:].strip()
            return not cls._version_lt(target, version)
        elif range_spec.startswith("<"):
            target = range_spec[1:].strip()
            return cls._version_lt(version, target)
        elif range_spec.startswith(">="):
            target = range_spec[2:].strip()
            return not cls._version_lt(version, target)
        elif range_spec.startswith(">"):
            target = range_spec[1:].strip()
            return cls._version_lt(target, version)
        else:
            # Exact match
            return version.strip() == range_spec

        return False
