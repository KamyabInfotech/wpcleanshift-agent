"""
CleanShift Vulnerability Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checks installed WordPress plugins, themes, and core against the
WPScan vulnerability database API.  Returns structured vulnerability
findings with CVE IDs, CVSS scores, and fixed version info.

Features:
    - Plugin/theme metadata parsing from PHP headers and readme.txt
    - WPScan API v3 integration with rate-limit awareness
    - Response caching (24h) in ~/.cleanshift/cache/vuln/
    - Semantic version comparison for fix-version matching
    - Graceful degradation when API key is missing or API unreachable

Configuration:
    Set ``wpscan_api_key`` in ``~/.cleanshift/config.yml`` or pass
    directly to the constructor.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from rich.console import Console

logger = logging.getLogger("cleanshift.vuln_scanner")
console = Console(stderr=True)

# ─── Configuration ─────────────────────────────────────────────────

_WPSCAN_API_BASE = "https://wpscan.com/api/v3"
_HTTP_TIMEOUT = 15  # seconds

# Cache settings
_CACHE_DIR = Path.home() / ".cleanshift" / "cache" / "vuln"
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours

# Rate limiting — free WPScan tier allows 25 requests/day
_RATE_LIMIT_FILE = _CACHE_DIR / ".rate_limit_state.json"
_MAX_REQUESTS_PER_DAY = 25

# Config file location
_CONFIG_FILE = Path.home() / ".cleanshift" / "config.yml"

# PHP header patterns for metadata extraction
_PLUGIN_HEADER_PATTERNS = {
    "name": re.compile(r"Plugin\s*Name\s*:\s*(.+)", re.IGNORECASE),
    "version": re.compile(r"Version\s*:\s*([^\s]+)", re.IGNORECASE),
    "author": re.compile(r"Author\s*:\s*(.+)", re.IGNORECASE),
    "slug": re.compile(r"Text\s*Domain\s*:\s*(\S+)", re.IGNORECASE),
}

_THEME_HEADER_PATTERNS = {
    "name": re.compile(r"Theme\s*Name\s*:\s*(.+)", re.IGNORECASE),
    "version": re.compile(r"Version\s*:\s*([^\s]+)", re.IGNORECASE),
    "author": re.compile(r"Author\s*:\s*(.+)", re.IGNORECASE),
    "slug": re.compile(r"Text\s*Domain\s*:\s*(\S+)", re.IGNORECASE),
}

# readme.txt version pattern
_README_VERSION_PATTERN = re.compile(
    r"Stable\s+tag\s*:\s*([^\s]+)", re.IGNORECASE
)


# ─── Data Models ───────────────────────────────────────────────────

@dataclass
class VulnFinding:
    """A single vulnerability finding for a plugin, theme, or core.

    Attributes:
        plugin_slug:        Plugin/theme slug or 'wordpress' for core.
        installed_version:  Currently installed version string.
        fixed_version:      Version that fixes the vulnerability (if known).
        cve_ids:            List of associated CVE identifiers.
        cvss_score:         CVSS v3 score (0.0–10.0), None if unavailable.
        severity:           Severity level: critical, high, medium, low.
        title:              Human-readable vulnerability title.
        references:         List of reference URLs.
        component_type:     'plugin', 'theme', or 'core'.
        vuln_type:          Vulnerability type (e.g. 'SQLi', 'XSS', 'RCE').
    """
    plugin_slug: str = ""
    installed_version: str = ""
    fixed_version: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    severity: str = "medium"
    title: str = ""
    references: List[str] = field(default_factory=list)
    component_type: str = "plugin"  # plugin, theme, or core
    vuln_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return asdict(self)


@dataclass
class ComponentInfo:
    """Metadata for a WordPress plugin or theme."""
    slug: str
    name: str = ""
    version: str = ""
    path: str = ""
    component_type: str = "plugin"  # plugin or theme


# ─── Version Comparison ────────────────────────────────────────────

def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison.

    Handles common WordPress version formats:
        '5.9.3' -> (5, 9, 3)
        '1.2.3.4' -> (1, 2, 3, 4)
        '2.0-beta1' -> (2, 0)  (strips non-numeric suffixes)
        'trunk' -> (0,)  (unparseable defaults to 0)

    Args:
        version_str: Version string to parse.

    Returns:
        Tuple of integers representing version components.
    """
    if not version_str:
        return (0,)

    # Strip common suffixes
    cleaned = re.sub(r"[-+].+$", "", version_str.strip())

    parts: List[int] = []
    for segment in cleaned.split("."):
        # Extract leading digits from each segment
        match = re.match(r"(\d+)", segment)
        if match:
            parts.append(int(match.group(1)))

    return tuple(parts) if parts else (0,)


def _version_lt(installed: str, fixed: str) -> bool:
    """Check if installed version is less than the fixed version.

    Args:
        installed: Currently installed version string.
        fixed: Version that contains the fix.

    Returns:
        True if installed < fixed (i.e. the vulnerability applies).
    """
    return _parse_version(installed) < _parse_version(fixed)


# ─── Vulnerability Scanner ─────────────────────────────────────────

class VulnScanner:
    """Checks WordPress components against the WPScan vulnerability DB.

    Parameters
    ----------
    api_key : str | None
        WPScan API token.  If not provided, attempts to read from
        ``~/.cleanshift/config.yml``.
    cache_ttl : int
        Cache time-to-live in seconds (default: 24 hours).
    max_requests_per_day : int
        Maximum API requests per day (default: 25 for free WPScan tier).

    Usage
    -----
    >>> scanner = VulnScanner(api_key="my_wpscan_token")
    >>> findings = scanner.check_plugins("/var/www/html")
    >>> for f in findings:
    ...     print(f.title, f.severity, f.cve_ids)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl: int = _CACHE_TTL_SECONDS,
        max_requests_per_day: int = _MAX_REQUESTS_PER_DAY,
    ) -> None:
        self.api_key = api_key or self._load_api_key()
        self.cache_ttl = cache_ttl
        self.max_requests_per_day = max_requests_per_day
        self._request_count = 0
        self._request_day: Optional[str] = None

        # Ensure cache directory exists
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

        # Load rate-limit state
        self._load_rate_state()

        if not self.api_key:
            logger.warning(
                "WPScan API key not configured — vulnerability scanning "
                "will be limited. Set 'wpscan_api_key' in %s",
                _CONFIG_FILE,
            )

        if not _HTTPX_AVAILABLE:
            logger.warning(
                "httpx not installed — vulnerability scanner requires httpx. "
                "Install with: pip install httpx"
            )

    # ── Public API ─────────────────────────────────────────────────

    def check_plugins(self, wp_path: str | Path) -> List[VulnFinding]:
        """Scan all installed plugins for known vulnerabilities.

        Discovers plugins in ``wp-content/plugins/``, extracts version
        metadata from the main PHP file header and/or readme.txt, and
        queries the WPScan API for each plugin.

        Args:
            wp_path: Absolute path to the WordPress installation root.

        Returns:
            List of VulnFinding objects for vulnerable plugins.
        """
        wp_path = Path(wp_path)
        plugins_dir = wp_path / "wp-content" / "plugins"

        if not plugins_dir.is_dir():
            logger.warning("Plugins directory not found: %s", plugins_dir)
            return []

        components = self._discover_plugins(plugins_dir)
        logger.info("Discovered %d plugins in %s", len(components), plugins_dir)

        findings: List[VulnFinding] = []
        for component in components:
            component_findings = self._check_component(component)
            findings.extend(component_findings)

        return findings

    def check_themes(self, wp_path: str | Path) -> List[VulnFinding]:
        """Scan all installed themes for known vulnerabilities.

        Discovers themes in ``wp-content/themes/``, extracts version
        metadata from style.css, and queries the WPScan API.

        Args:
            wp_path: Absolute path to the WordPress installation root.

        Returns:
            List of VulnFinding objects for vulnerable themes.
        """
        wp_path = Path(wp_path)
        themes_dir = wp_path / "wp-content" / "themes"

        if not themes_dir.is_dir():
            logger.warning("Themes directory not found: %s", themes_dir)
            return []

        components = self._discover_themes(themes_dir)
        logger.info("Discovered %d themes in %s", len(components), themes_dir)

        findings: List[VulnFinding] = []
        for component in components:
            component_findings = self._check_component(component)
            findings.extend(component_findings)

        return findings

    def check_core(
        self, wp_path: str | Path, version: Optional[str] = None
    ) -> List[VulnFinding]:
        """Check the WordPress core version for known vulnerabilities.

        Args:
            wp_path: Absolute path to the WordPress installation root.
            version: WordPress version string (e.g. '6.4.2'). If not
                     provided, attempts to detect from version.php.

        Returns:
            List of VulnFinding objects for core vulnerabilities.
        """
        wp_path = Path(wp_path)

        if not version:
            version = self._detect_wp_version(wp_path)

        if not version:
            logger.warning(
                "Could not detect WordPress version in %s", wp_path
            )
            return []

        logger.info("Checking WordPress core %s for vulnerabilities", version)

        component = ComponentInfo(
            slug="wordpress",
            name="WordPress Core",
            version=version,
            path=str(wp_path),
            component_type="core",
        )
        return self._check_component(component)

    # ── Discovery Helpers ──────────────────────────────────────────

    def _discover_plugins(self, plugins_dir: Path) -> List[ComponentInfo]:
        """Discover installed plugins and extract metadata.

        Looks for plugin directories with a main PHP file containing
        a valid ``Plugin Name:`` header.
        """
        components: List[ComponentInfo] = []

        try:
            for entry in sorted(plugins_dir.iterdir()):
                if not entry.is_dir():
                    # Single-file plugin
                    if entry.suffix == ".php":
                        info = self._parse_plugin_file(entry)
                        if info:
                            components.append(info)
                    continue

                # Look for main plugin file (same name as directory)
                slug = entry.name
                main_file = entry / f"{slug}.php"

                if not main_file.exists():
                    # Try any PHP file in the directory root
                    php_files = list(entry.glob("*.php"))
                    if php_files:
                        main_file = php_files[0]
                    else:
                        continue

                info = self._parse_plugin_file(main_file, slug=slug)
                if info:
                    components.append(info)

        except PermissionError as exc:
            logger.warning("Permission denied reading %s: %s", plugins_dir, exc)

        return components

    def _discover_themes(self, themes_dir: Path) -> List[ComponentInfo]:
        """Discover installed themes and extract metadata.

        Reads theme metadata from ``style.css`` in each theme directory.
        """
        components: List[ComponentInfo] = []

        try:
            for entry in sorted(themes_dir.iterdir()):
                if not entry.is_dir():
                    continue

                style_css = entry / "style.css"
                if not style_css.exists():
                    continue

                info = self._parse_theme_style(style_css, slug=entry.name)
                if info:
                    components.append(info)

        except PermissionError as exc:
            logger.warning("Permission denied reading %s: %s", themes_dir, exc)

        return components

    def _parse_plugin_file(
        self, filepath: Path, slug: Optional[str] = None
    ) -> Optional[ComponentInfo]:
        """Extract plugin metadata from a PHP file header."""
        try:
            # Read only first 8KB — headers are always at the top
            content = filepath.read_text(
                encoding="utf-8", errors="replace"
            )[:8192]
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read %s: %s", filepath, exc)
            return None

        name_match = _PLUGIN_HEADER_PATTERNS["name"].search(content)
        if not name_match:
            return None  # Not a valid plugin file

        version = ""
        version_match = _PLUGIN_HEADER_PATTERNS["version"].search(content)
        if version_match:
            version = version_match.group(1).strip()

        # Try readme.txt for more reliable version
        readme = filepath.parent / "readme.txt"
        if readme.exists():
            readme_version = self._parse_readme_version(readme)
            if readme_version:
                version = readme_version

        # Determine slug
        detected_slug = slug or filepath.parent.name
        slug_match = _PLUGIN_HEADER_PATTERNS["slug"].search(content)
        if slug_match:
            detected_slug = slug_match.group(1).strip()

        return ComponentInfo(
            slug=detected_slug,
            name=name_match.group(1).strip(),
            version=version,
            path=str(filepath.parent),
            component_type="plugin",
        )

    def _parse_theme_style(
        self, style_css: Path, slug: Optional[str] = None
    ) -> Optional[ComponentInfo]:
        """Extract theme metadata from style.css header."""
        try:
            content = style_css.read_text(
                encoding="utf-8", errors="replace"
            )[:8192]
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read %s: %s", style_css, exc)
            return None

        name_match = _THEME_HEADER_PATTERNS["name"].search(content)
        if not name_match:
            return None

        version = ""
        version_match = _THEME_HEADER_PATTERNS["version"].search(content)
        if version_match:
            version = version_match.group(1).strip()

        detected_slug = slug or style_css.parent.name
        slug_match = _THEME_HEADER_PATTERNS["slug"].search(content)
        if slug_match:
            detected_slug = slug_match.group(1).strip()

        return ComponentInfo(
            slug=detected_slug,
            name=name_match.group(1).strip(),
            version=version,
            path=str(style_css.parent),
            component_type="theme",
        )

    def _parse_readme_version(self, readme_path: Path) -> Optional[str]:
        """Extract the 'Stable tag' version from a plugin readme.txt."""
        try:
            content = readme_path.read_text(
                encoding="utf-8", errors="replace"
            )[:4096]
            match = _README_VERSION_PATTERN.search(content)
            if match:
                version = match.group(1).strip()
                if version.lower() != "trunk":
                    return version
        except (OSError, PermissionError):
            pass
        return None

    def _detect_wp_version(self, wp_path: Path) -> Optional[str]:
        """Detect WordPress version from wp-includes/version.php."""
        version_file = wp_path / "wp-includes" / "version.php"
        if not version_file.exists():
            return None

        try:
            content = version_file.read_text(
                encoding="utf-8", errors="replace"
            )
            match = re.search(
                r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", content
            )
            if match:
                return match.group(1).strip()
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read version.php: %s", exc)

        return None

    # ── API Integration ────────────────────────────────────────────

    def _check_component(self, component: ComponentInfo) -> List[VulnFinding]:
        """Query WPScan API for vulnerabilities in a single component."""
        if not self.api_key:
            logger.debug(
                "Skipping API check for %s — no API key configured",
                component.slug,
            )
            return []

        if not _HTTPX_AVAILABLE:
            return []

        if not component.version:
            logger.debug(
                "Skipping %s — no version detected", component.slug
            )
            return []

        # Check rate limit
        if not self._check_rate_limit():
            logger.warning(
                "WPScan API rate limit reached (%d/%d requests today). "
                "Skipping %s",
                self._request_count,
                self.max_requests_per_day,
                component.slug,
            )
            return []

        # Try cache first
        cached = self._load_cached_response(component.slug, component.component_type)
        if cached is not None:
            return self._parse_vulnerabilities(
                cached, component
            )

        # Query WPScan API
        data = self._query_api(component)
        if data is None:
            return []

        # Cache the response
        self._save_cached_response(
            component.slug, component.component_type, data
        )

        return self._parse_vulnerabilities(data, component)

    def _query_api(self, component: ComponentInfo) -> Optional[Dict[str, Any]]:
        """Make a single WPScan API request."""
        if component.component_type == "core":
            url = f"{_WPSCAN_API_BASE}/wordpresses/{component.version.replace('.', '')}"
        elif component.component_type == "theme":
            url = f"{_WPSCAN_API_BASE}/themes/{component.slug}"
        else:
            url = f"{_WPSCAN_API_BASE}/plugins/{component.slug}"

        headers = {
            "Authorization": f"Token token={self.api_key}",
            "User-Agent": "CleanShift-Agent/1.0",
        }

        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
                response = client.get(url, headers=headers)

            self._increment_rate_counter()

            if response.status_code == 200:
                return response.json()

            if response.status_code == 404:
                logger.debug(
                    "Component not found in WPScan DB: %s", component.slug
                )
                return None

            if response.status_code == 429:
                logger.warning("WPScan API rate limit exceeded")
                return None

            if response.status_code in (401, 403):
                logger.error(
                    "WPScan API authentication failed — check your API key"
                )
                return None

            logger.warning(
                "WPScan API returned %d for %s",
                response.status_code, component.slug,
            )
            return None

        except httpx.HTTPError as exc:
            logger.warning(
                "WPScan API request failed for %s: %s", component.slug, exc
            )
            return None
        except Exception as exc:
            logger.warning(
                "Unexpected error querying WPScan API for %s: %s",
                component.slug, exc,
            )
            return None

    def _parse_vulnerabilities(
        self,
        data: Dict[str, Any],
        component: ComponentInfo,
    ) -> List[VulnFinding]:
        """Parse WPScan API response into VulnFinding objects."""
        findings: List[VulnFinding] = []

        # WPScan response structure:
        # { "slug": { "vulnerabilities": [...], ... } }
        component_data = data.get(component.slug, data)
        vulns = component_data.get("vulnerabilities", [])

        for vuln in vulns:
            # Check if this vulnerability affects the installed version
            fixed_in = vuln.get("fixed_in")
            if fixed_in and not _version_lt(component.version, fixed_in):
                continue  # Already patched

            # Extract CVE IDs
            cve_ids: List[str] = []
            references = vuln.get("references", {})
            if "cve" in references:
                cve_ids = [f"CVE-{c}" for c in references["cve"]]

            # Extract reference URLs
            ref_urls: List[str] = []
            for ref_type, ref_list in references.items():
                if ref_type == "cve":
                    continue
                if isinstance(ref_list, list):
                    ref_urls.extend(ref_list)

            # Determine severity from CVSS or vuln type
            cvss = vuln.get("cvss", {})
            cvss_score = cvss.get("score")
            severity = self._cvss_to_severity(cvss_score)

            finding = VulnFinding(
                plugin_slug=component.slug,
                installed_version=component.version,
                fixed_version=fixed_in,
                cve_ids=cve_ids,
                cvss_score=cvss_score,
                severity=severity,
                title=vuln.get("title", "Unknown vulnerability"),
                references=ref_urls,
                component_type=component.component_type,
                vuln_type=vuln.get("vuln_type", ""),
            )
            findings.append(finding)

        if findings:
            logger.info(
                "Found %d vulnerabilities in %s %s",
                len(findings), component.slug, component.version,
            )

        return findings

    # ── Caching ────────────────────────────────────────────────────

    def _cache_key(self, slug: str, component_type: str) -> str:
        """Generate a cache filename for a component."""
        safe_slug = re.sub(r"[^\w\-]", "_", slug)
        return f"{component_type}_{safe_slug}.json"

    def _load_cached_response(
        self, slug: str, component_type: str
    ) -> Optional[Dict[str, Any]]:
        """Load a cached API response if it exists and is not expired."""
        cache_file = _CACHE_DIR / self._cache_key(slug, component_type)

        if not cache_file.exists():
            return None

        try:
            raw = cache_file.read_text(encoding="utf-8")
            cached = json.loads(raw)

            # Check expiry
            cached_at = cached.get("_cached_at", 0)
            if time.time() - cached_at > self.cache_ttl:
                cache_file.unlink(missing_ok=True)
                return None

            # Remove internal cache metadata before returning
            data = {k: v for k, v in cached.items() if not k.startswith("_")}
            return data

        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Failed to read cache for %s: %s", slug, exc)
            return None

    def _save_cached_response(
        self, slug: str, component_type: str, data: Dict[str, Any]
    ) -> None:
        """Write an API response to the cache."""
        try:
            cache_data = dict(data)
            cache_data["_cached_at"] = time.time()

            cache_file = _CACHE_DIR / self._cache_key(slug, component_type)
            cache_file.write_text(
                json.dumps(cache_data, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.debug("Failed to write cache for %s: %s", slug, exc)

    # ── Rate Limiting ──────────────────────────────────────────────

    def _check_rate_limit(self) -> bool:
        """Check if we are within the daily rate limit."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        if self._request_day != today:
            # New day — reset counter
            self._request_day = today
            self._request_count = 0
            self._save_rate_state()

        return self._request_count < self.max_requests_per_day

    def _increment_rate_counter(self) -> None:
        """Increment the daily request counter."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._request_day != today:
            self._request_day = today
            self._request_count = 0

        self._request_count += 1
        self._save_rate_state()

    def _load_rate_state(self) -> None:
        """Load rate-limit state from disk."""
        if not _RATE_LIMIT_FILE.exists():
            return

        try:
            raw = _RATE_LIMIT_FILE.read_text(encoding="utf-8")
            state = json.loads(raw)
            self._request_day = state.get("date")
            self._request_count = state.get("count", 0)
        except (json.JSONDecodeError, OSError):
            pass

    def _save_rate_state(self) -> None:
        """Persist rate-limit state to disk."""
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            state = {
                "date": self._request_day,
                "count": self._request_count,
            }
            _RATE_LIMIT_FILE.write_text(
                json.dumps(state), encoding="utf-8"
            )
        except OSError:
            pass

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _cvss_to_severity(score: Optional[float]) -> str:
        """Convert a CVSS v3 score to a severity string."""
        if score is None:
            return "medium"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    @staticmethod
    def _load_api_key() -> Optional[str]:
        """Attempt to load the WPScan API key from config.yml."""
        if not _CONFIG_FILE.exists():
            return None

        if not _YAML_AVAILABLE:
            # Fallback: simple regex extraction
            try:
                content = _CONFIG_FILE.read_text(encoding="utf-8")
                match = re.search(
                    r"wpscan_api_key\s*:\s*['\"]?(\S+)['\"]?", content
                )
                if match:
                    return match.group(1).strip().strip("'\"")
            except OSError:
                pass
            return None

        try:
            content = _CONFIG_FILE.read_text(encoding="utf-8")
            config = yaml.safe_load(content)
            if isinstance(config, dict):
                return config.get("wpscan_api_key")
        except (OSError, yaml.YAMLError) as exc:
            logger.debug("Failed to read config: %s", exc)

        return None
