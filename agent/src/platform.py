"""
CleanShift Platform Detection Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Auto-detects what CMS or PHP framework is installed at a given filesystem
path.  Provides platform-specific metadata including version, config file
location, database prefix, admin path, writable directories, and common
backdoor locations.

Supported platforms:
    - CMS: WordPress, Joomla, Drupal, Magento 1/2, PrestaShop, WHMCS,
            Moodle, OpenCart, MediaWiki
    - Frameworks: Laravel, Symfony, CodeIgniter, CakePHP, Yii
    - Fallback: custom PHP sites, static HTML sites

Architecture:
    PlatformDetector
      ├─ detect()             — identify platform from filesystem signatures
      ├─ detect_version()     — extract version string per platform
      ├─ get_config_secrets() — parse config for DB creds, API keys
      ├─ get_writable_dirs()  — dirs that should be checked for rogue PHP
      └─ get_backdoor_paths() — platform-specific common backdoor locations

All methods are safe to call on any directory; missing files / parse
failures are handled gracefully and logged.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cleanshift.platform")


# ─── Platform Types ─────────────────────────────────────────────────

class PlatformType:
    """
    Enumeration of supported CMS and framework platform types.

    Uses class-level string constants rather than ``enum.Enum`` so the
    values can be serialised directly and compared to JSON payloads
    without ``.value`` noise.
    """
    WORDPRESS = "wordpress"
    JOOMLA = "joomla"
    DRUPAL = "drupal"
    MAGENTO2 = "magento2"
    MAGENTO1 = "magento1"
    PRESTASHOP = "prestashop"
    WHMCS = "whmcs"
    MOODLE = "moodle"
    OPENCART = "opencart"
    MEDIAWIKI = "mediawiki"
    LARAVEL = "laravel"
    SYMFONY = "symfony"
    CODEIGNITER = "codeigniter"
    CAKEPHP = "cakephp"
    YII = "yii"
    CUSTOM_PHP = "custom_php"
    STATIC = "static"

    # Convenience: all known types for iteration
    ALL = [
        WORDPRESS, JOOMLA, DRUPAL, MAGENTO2, MAGENTO1,
        PRESTASHOP, WHMCS, MOODLE, OPENCART, MEDIAWIKI,
        LARAVEL, SYMFONY, CODEIGNITER, CAKEPHP, YII,
        CUSTOM_PHP, STATIC,
    ]  # type: List[str]


# ─── Platform Info ──────────────────────────────────────────────────

@dataclass
class PlatformInfo:
    """
    Result of platform detection for a single site path.

    Attributes:
        platform_type:        One of ``PlatformType`` constants.
        version:              Detected version string, or empty.
        config_file:          Absolute path to the platform's primary
                              configuration file.
        db_prefix:            Database table prefix (e.g. ``wp_``).
        admin_path:           Relative path to the admin/backend area.
        writable_dirs:        Directories that legitimately accept uploads
                              but should be checked for rogue PHP files.
        detection_confidence: 0.0–1.0 score of how sure we are about the
                              detection.
    """
    platform_type: str = ""
    version: str = ""
    config_file: str = ""
    db_prefix: str = ""
    admin_path: str = ""
    writable_dirs: List[str] = field(default_factory=list)
    detection_confidence: float = 0.0

    def to_dict(self):
        # type: () -> Dict[str, Any]
        """Serialise to a JSON-safe dictionary."""
        return {
            "platform_type": self.platform_type,
            "version": self.version,
            "config_file": self.config_file,
            "db_prefix": self.db_prefix,
            "admin_path": self.admin_path,
            "writable_dirs": list(self.writable_dirs or []),
            "detection_confidence": self.detection_confidence,
        }


# ─── Safe I/O Helpers ───────────────────────────────────────────────

def _safe_read_text(filepath, max_bytes=262144):
    # type: (str, int) -> str
    """Read a text file safely, returning empty string on any error."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except (OSError, IOError, PermissionError):
        return ""


def _safe_read_bytes(filepath, max_bytes=262144):
    # type: (str, int) -> bytes
    """Read a binary file safely, returning empty bytes on any error."""
    try:
        with open(filepath, "rb") as fh:
            return fh.read(max_bytes)
    except (OSError, IOError, PermissionError):
        return b""


def _path_exists(path):
    # type: (str) -> bool
    """Check path existence, returning False on permission errors."""
    try:
        return os.path.exists(path)
    except (OSError, PermissionError):
        return False


def _is_dir(path):
    # type: (str) -> bool
    """Check if path is a directory, returning False on errors."""
    try:
        return os.path.isdir(path)
    except (OSError, PermissionError):
        return False


# ─── Platform Detector ──────────────────────────────────────────────

class PlatformDetector:
    """
    Detects what CMS or PHP framework is installed at a filesystem path.

    Detection works by checking for the existence of signature files
    and directories.  Each signature has an associated confidence
    weight; the platform with the highest combined confidence wins.

    Usage::

        detector = PlatformDetector()
        info = detector.detect("/home/user/public_html")
        print(info.platform_type, info.version)
    """

    # Mapping of platform type -> list of (relative_path, confidence_weight).
    # Files and directories are checked with os.path.exists().
    SIGNATURES = {
        PlatformType.WORDPRESS: [
            ("wp-config.php", 0.9),
            ("wp-includes/version.php", 0.95),
            ("wp-admin/admin.php", 0.8),
        ],
        PlatformType.JOOMLA: [
            ("configuration.php", 0.5),
            ("administrator/index.php", 0.7),
            ("libraries/src/Version.php", 0.95),
            ("libraries/cms/version/version.php", 0.9),
        ],
        PlatformType.DRUPAL: [
            ("sites/default/settings.php", 0.95),
            ("core/lib/Drupal.php", 0.95),
            ("includes/bootstrap.inc", 0.8),
        ],
        PlatformType.MAGENTO2: [
            ("bin/magento", 0.95),
            ("app/etc/env.php", 0.9),
            ("pub/index.php", 0.6),
        ],
        PlatformType.MAGENTO1: [
            ("app/Mage.php", 0.95),
            ("app/etc/local.xml", 0.9),
        ],
        PlatformType.PRESTASHOP: [
            ("classes/PrestaShopCollection.php", 0.95),
            ("config/settings.inc.php", 0.8),
            ("controllers/front/IndexController.php", 0.7),
        ],
        PlatformType.WHMCS: [
            ("whmcs.php", 0.8),
            ("modules/addons/", 0.5),
            ("crons/cron.php", 0.6),
        ],
        PlatformType.MOODLE: [
            ("config-dist.php", 0.7),
            ("admin/tool/task/", 0.8),
            ("mod/assign/", 0.8),
            ("lib/moodlelib.php", 0.9),
        ],
        PlatformType.OPENCART: [
            ("system/storage/", 0.7),
            ("catalog/controller/", 0.8),
            ("admin/config.php", 0.6),
        ],
        PlatformType.MEDIAWIKI: [
            ("LocalSettings.php", 0.7),
            ("includes/Defines.php", 0.9),
            ("api.php", 0.4),
        ],
        PlatformType.LARAVEL: [
            ("artisan", 0.9),
            ("app/Http/Kernel.php", 0.95),
            ("bootstrap/app.php", 0.8),
        ],
        PlatformType.SYMFONY: [
            ("bin/console", 0.7),
            ("config/bundles.php", 0.9),
            ("symfony.lock", 0.95),
        ],
        PlatformType.CODEIGNITER: [
            ("system/CodeIgniter.php", 0.95),
            ("spark", 0.7),
            ("app/Config/App.php", 0.8),
        ],
        PlatformType.CAKEPHP: [
            ("bin/cake", 0.9),
            ("webroot/index.php", 0.5),
            ("config/app.php", 0.6),
        ],
        PlatformType.YII: [
            ("yii", 0.8),
            ("config/web.php", 0.7),
            ("protected/config/main.php", 0.9),
        ],
    }  # type: Dict[str, List[Tuple[str, float]]]

    # ── Primary config file for each platform ────────────────────────

    _CONFIG_FILES = {
        PlatformType.WORDPRESS: "wp-config.php",
        PlatformType.JOOMLA: "configuration.php",
        PlatformType.DRUPAL: "sites/default/settings.php",
        PlatformType.MAGENTO2: "app/etc/env.php",
        PlatformType.MAGENTO1: "app/etc/local.xml",
        PlatformType.PRESTASHOP: "config/settings.inc.php",
        PlatformType.WHMCS: "configuration.php",
        PlatformType.MOODLE: "config.php",
        PlatformType.OPENCART: "config.php",
        PlatformType.MEDIAWIKI: "LocalSettings.php",
        PlatformType.LARAVEL: ".env",
        PlatformType.SYMFONY: ".env",
        PlatformType.CODEIGNITER: ".env",
        PlatformType.CAKEPHP: "config/app.php",
        PlatformType.YII: "config/web.php",
    }  # type: Dict[str, str]

    # ── Admin paths ──────────────────────────────────────────────────

    _ADMIN_PATHS = {
        PlatformType.WORDPRESS: "wp-admin",
        PlatformType.JOOMLA: "administrator",
        PlatformType.DRUPAL: "admin",
        PlatformType.MAGENTO2: "admin",
        PlatformType.MAGENTO1: "admin",
        PlatformType.PRESTASHOP: "admin",
        PlatformType.WHMCS: "admin",
        PlatformType.MOODLE: "admin",
        PlatformType.OPENCART: "admin",
        PlatformType.MEDIAWIKI: "Special:UserLogin",
        PlatformType.LARAVEL: "",
        PlatformType.SYMFONY: "",
        PlatformType.CODEIGNITER: "",
        PlatformType.CAKEPHP: "",
        PlatformType.YII: "",
    }  # type: Dict[str, str]

    # ── Default DB prefixes ──────────────────────────────────────────

    _DEFAULT_DB_PREFIXES = {
        PlatformType.WORDPRESS: "wp_",
        PlatformType.JOOMLA: "jos_",
        PlatformType.DRUPAL: "",
        PlatformType.MAGENTO2: "",
        PlatformType.MAGENTO1: "",
        PlatformType.PRESTASHOP: "ps_",
        PlatformType.WHMCS: "tbl",
        PlatformType.MOODLE: "mdl_",
        PlatformType.OPENCART: "oc_",
        PlatformType.MEDIAWIKI: "mw_",
    }  # type: Dict[str, str]

    # ── Version extraction regexes ───────────────────────────────────

    _WP_VERSION_RE = re.compile(
        r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]"
    )
    _JOOMLA_XML_VERSION_RE = re.compile(
        r"<version>\s*([^<]+)\s*</version>", re.IGNORECASE
    )
    _DRUPAL_VERSION_RE = re.compile(
        r"const\s+VERSION\s*=\s*['\"]([^'\"]+)['\"]"
    )
    _DRUPAL7_VERSION_RE = re.compile(
        r"Drupal\s+(\d+\.\d+)"
    )
    _MAGE1_VERSION_RE = re.compile(
        r"function\s+getVersion[^}]*return\s+['\"]([^'\"]+)['\"]",
        re.DOTALL,
    )
    _PRESTASHOP_VERSION_RE = re.compile(
        r"\$_PS_VERSION_\s*=\s*['\"]([^'\"]+)['\"]"
    )
    _WHMCS_VERSION_RE = re.compile(
        r"\$version\s*=\s*['\"]([^'\"]+)['\"]"
    )
    _MOODLE_VERSION_RE = re.compile(
        r"\$release\s*=\s*['\"]([^'\"]+)['\"]"
    )
    _OPENCART_VERSION_RE = re.compile(
        r"define\s*\(\s*['\"]VERSION['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"
    )
    _MEDIAWIKI_VERSION_RE = re.compile(
        r"define\s*\(\s*['\"]MW_VERSION['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"
    )
    _CI_VERSION_RE = re.compile(
        r"const\s+CI_VERSION\s*=\s*['\"]([^'\"]+)['\"]"
    )
    _YII_VERSION_RE = re.compile(
        r"function\s+getVersion[^}]*return\s+['\"]([^'\"]+)['\"]",
        re.DOTALL,
    )

    # ── Detection entry point ────────────────────────────────────────

    def detect(self, path):
        # type: (str) -> PlatformInfo
        """
        Detect the CMS or framework installed at *path*.

        Checks all signature files for every known platform, sums the
        confidence weights of present signatures, and returns the
        platform with the highest combined confidence.  Falls back to
        ``CUSTOM_PHP`` (if ``*.php`` files exist) or ``STATIC``.

        Args:
            path: Absolute filesystem path to scan.

        Returns:
            A ``PlatformInfo`` with the best match.
        """
        path = str(path)
        if not _path_exists(path) or not _is_dir(path):
            logger.warning("Path does not exist or is not a directory: %s", path)
            return PlatformInfo(
                platform_type=PlatformType.STATIC,
                detection_confidence=0.0,
            )

        scores = {}  # type: Dict[str, float]
        match_counts = {}  # type: Dict[str, int]

        for ptype, sigs in self.SIGNATURES.items():
            total_score = 0.0
            matches = 0
            for rel_path, weight in sigs:
                full_path = os.path.join(path, rel_path)
                try:
                    if _path_exists(full_path):
                        total_score += weight
                        matches += 1
                except Exception:
                    continue
            if matches > 0:
                scores[ptype] = total_score
                match_counts[ptype] = matches

        if not scores:
            # Fallback: check if there are any PHP files at all
            fallback = self._detect_fallback(path)
            logger.info("No platform signatures matched at %s, fallback=%s", path, fallback)
            return PlatformInfo(
                platform_type=fallback,
                detection_confidence=0.1 if fallback == PlatformType.CUSTOM_PHP else 0.0,
            )

        # Pick the platform with the highest score
        best_platform = max(scores, key=lambda k: scores[k])
        best_score = scores[best_platform]

        # Normalise confidence: divide by sum of all possible weights
        max_possible = sum(w for _, w in self.SIGNATURES.get(best_platform, []))
        confidence = min(best_score / max_possible, 1.0) if max_possible > 0 else 0.0

        logger.info(
            "Detected platform: %s (confidence=%.2f, score=%.2f/%d sigs) at %s",
            best_platform, confidence, best_score, match_counts.get(best_platform, 0), path,
        )

        # Build full PlatformInfo
        config_rel = self._CONFIG_FILES.get(best_platform, "")
        config_abs = os.path.join(path, config_rel) if config_rel else ""

        info = PlatformInfo()
        info.platform_type = best_platform
        info.detection_confidence = round(confidence, 3)
        info.config_file = config_abs if _path_exists(config_abs) else ""
        info.admin_path = self._ADMIN_PATHS.get(best_platform, "")
        info.db_prefix = self._DEFAULT_DB_PREFIXES.get(best_platform, "")
        info.writable_dirs = self.get_writable_dirs(info)

        # Attempt version detection
        try:
            info.version = self.detect_version(path, best_platform)
        except Exception as exc:
            logger.debug("Version detection failed for %s: %s", best_platform, exc)
            info.version = ""

        # Attempt DB prefix extraction from config
        try:
            extracted_prefix = self._extract_db_prefix(path, best_platform)
            if extracted_prefix:
                info.db_prefix = extracted_prefix
        except Exception:
            pass

        return info

    # ── Fallback detection ───────────────────────────────────────────

    def _detect_fallback(self, path):
        # type: (str) -> str
        """Determine if a path contains a custom PHP site or is static."""
        try:
            for entry in os.listdir(path):
                if entry.lower().endswith(".php"):
                    return PlatformType.CUSTOM_PHP
        except (OSError, PermissionError):
            pass
        return PlatformType.STATIC

    # ── Version Detection ────────────────────────────────────────────

    def detect_version(self, path, platform_type):
        # type: (str, str) -> str
        """
        Extract the installed version for *platform_type* at *path*.

        Each platform has a different file and format for its version
        string.  Returns an empty string if detection fails.

        Args:
            path:          Root directory of the installation.
            platform_type: One of ``PlatformType`` constants.

        Returns:
            Version string, e.g. ``"6.5.2"`` or ``""``.
        """
        dispatch = {
            PlatformType.WORDPRESS: self._version_wordpress,
            PlatformType.JOOMLA: self._version_joomla,
            PlatformType.DRUPAL: self._version_drupal,
            PlatformType.MAGENTO2: self._version_magento2,
            PlatformType.MAGENTO1: self._version_magento1,
            PlatformType.PRESTASHOP: self._version_prestashop,
            PlatformType.WHMCS: self._version_whmcs,
            PlatformType.MOODLE: self._version_moodle,
            PlatformType.OPENCART: self._version_opencart,
            PlatformType.MEDIAWIKI: self._version_mediawiki,
            PlatformType.LARAVEL: self._version_laravel,
            PlatformType.SYMFONY: self._version_symfony,
            PlatformType.CODEIGNITER: self._version_codeigniter,
            PlatformType.CAKEPHP: self._version_cakephp,
            PlatformType.YII: self._version_yii,
        }  # type: Dict[str, Any]

        handler = dispatch.get(platform_type)
        if handler is None:
            return ""

        try:
            version = handler(path)
            if version:
                logger.debug("Detected %s version: %s", platform_type, version)
            return version or ""
        except Exception as exc:
            logger.debug("Version detection error for %s: %s", platform_type, exc)
            return ""

    def _version_wordpress(self, path):
        # type: (str) -> str
        """Parse wp-includes/version.php for $wp_version."""
        content = _safe_read_text(os.path.join(path, "wp-includes", "version.php"))
        m = self._WP_VERSION_RE.search(content)
        return m.group(1) if m else ""

    def _version_joomla(self, path):
        # type: (str) -> str
        """Parse administrator/manifests/files/joomla.xml for <version>."""
        # Joomla 4+
        xml_path = os.path.join(path, "administrator", "manifests", "files", "joomla.xml")
        content = _safe_read_text(xml_path)
        if content:
            m = self._JOOMLA_XML_VERSION_RE.search(content)
            if m:
                return m.group(1).strip()

        # Joomla 3: libraries/cms/version/version.php
        ver_path = os.path.join(path, "libraries", "cms", "version", "version.php")
        content = _safe_read_text(ver_path)
        if content:
            # Look for RELEASE and DEV_LEVEL
            release_re = re.search(r"RELEASE\s*=\s*['\"]([^'\"]+)['\"]", content)
            dev_re = re.search(r"DEV_LEVEL\s*=\s*['\"]([^'\"]+)['\"]", content)
            if release_re:
                version = release_re.group(1)
                if dev_re:
                    version += "." + dev_re.group(1)
                return version

        # Joomla 4+: libraries/src/Version.php
        ver4_path = os.path.join(path, "libraries", "src", "Version.php")
        content = _safe_read_text(ver4_path)
        if content:
            major_re = re.search(r"MAJOR_VERSION\s*=\s*(\d+)", content)
            minor_re = re.search(r"MINOR_VERSION\s*=\s*(\d+)", content)
            patch_re = re.search(r"PATCH_VERSION\s*=\s*(\d+)", content)
            if major_re and minor_re and patch_re:
                return "%s.%s.%s" % (major_re.group(1), minor_re.group(1), patch_re.group(1))

        return ""

    def _version_drupal(self, path):
        # type: (str) -> str
        """Drupal 8+: core/lib/Drupal.php; Drupal 7: CHANGELOG.txt."""
        # Drupal 8+
        drupal_php = os.path.join(path, "core", "lib", "Drupal.php")
        content = _safe_read_text(drupal_php)
        if content:
            m = self._DRUPAL_VERSION_RE.search(content)
            if m:
                return m.group(1)

        # Drupal 7
        changelog = os.path.join(path, "CHANGELOG.txt")
        content = _safe_read_text(changelog, max_bytes=4096)
        if content:
            m = self._DRUPAL7_VERSION_RE.search(content)
            if m:
                return m.group(1)

        return ""

    def _version_magento2(self, path):
        # type: (str) -> str
        """Parse composer.json for magento/product-* version."""
        composer_json = os.path.join(path, "composer.json")
        content = _safe_read_text(composer_json)
        if not content:
            return ""
        try:
            data = json.loads(content)
            # Check require section for magento/product-*
            require = data.get("require", {})
            for pkg, ver in require.items():
                if pkg.startswith("magento/product-"):
                    # Strip composer constraint chars
                    clean = re.sub(r"[^0-9.]", "", ver)
                    return clean
            # Also check name
            name = data.get("name", "")
            version = data.get("version", "")
            if "magento" in name.lower() and version:
                return version
        except (ValueError, KeyError, TypeError):
            pass
        return ""

    def _version_magento1(self, path):
        # type: (str) -> str
        """Parse app/Mage.php for getVersion."""
        content = _safe_read_text(os.path.join(path, "app", "Mage.php"))
        m = self._MAGE1_VERSION_RE.search(content)
        return m.group(1) if m else ""

    def _version_prestashop(self, path):
        # type: (str) -> str
        """Parse config/settings.inc.php for _PS_VERSION_."""
        content = _safe_read_text(os.path.join(path, "config", "settings.inc.php"))
        m = self._PRESTASHOP_VERSION_RE.search(content)
        return m.group(1) if m else ""

    def _version_whmcs(self, path):
        # type: (str) -> str
        """Look for version in init.php or vendor files."""
        # Try init.php
        for candidate in ["init.php", "includes/classes/WHMCSConnect.php"]:
            content = _safe_read_text(os.path.join(path, candidate))
            if content:
                m = self._WHMCS_VERSION_RE.search(content)
                if m:
                    return m.group(1)
        return ""

    def _version_moodle(self, path):
        # type: (str) -> str
        """Parse version.php for $release."""
        content = _safe_read_text(os.path.join(path, "version.php"))
        m = self._MOODLE_VERSION_RE.search(content)
        if m:
            # $release typically looks like "4.3.2 (Build: 20240101)"
            release = m.group(1)
            # Extract just the version number
            ver_match = re.match(r"([\d.]+)", release)
            return ver_match.group(1) if ver_match else release
        return ""

    def _version_opencart(self, path):
        # type: (str) -> str
        """Parse index.php or system startup for VERSION constant."""
        for candidate in ["index.php", "system/startup.php"]:
            content = _safe_read_text(os.path.join(path, candidate))
            if content:
                m = self._OPENCART_VERSION_RE.search(content)
                if m:
                    return m.group(1)
        return ""

    def _version_mediawiki(self, path):
        # type: (str) -> str
        """Parse includes/Defines.php or includes/DefaultSettings.php."""
        for candidate in ["includes/Defines.php", "includes/DefaultSettings.php"]:
            content = _safe_read_text(os.path.join(path, candidate))
            if content:
                m = self._MEDIAWIKI_VERSION_RE.search(content)
                if m:
                    return m.group(1)
        return ""

    def _version_laravel(self, path):
        # type: (str) -> str
        """Parse composer.lock for laravel/framework version."""
        return self._version_from_composer_lock(path, "laravel/framework")

    def _version_symfony(self, path):
        # type: (str) -> str
        """Parse composer.lock for symfony/framework-bundle version."""
        return self._version_from_composer_lock(path, "symfony/framework-bundle")

    def _version_codeigniter(self, path):
        # type: (str) -> str
        """Parse system/CodeIgniter.php for CI_VERSION."""
        ci3_path = os.path.join(path, "system", "CodeIgniter.php")
        content = _safe_read_text(ci3_path)
        if content:
            m = self._CI_VERSION_RE.search(content)
            if m:
                return m.group(1)

        # CI4: check composer.lock
        return self._version_from_composer_lock(path, "codeigniter4/framework")

    def _version_cakephp(self, path):
        # type: (str) -> str
        """Parse composer.lock for cakephp/cakephp version."""
        return self._version_from_composer_lock(path, "cakephp/cakephp")

    def _version_yii(self, path):
        # type: (str) -> str
        """Parse framework/YiiBase.php or composer.lock."""
        for candidate in [
            os.path.join("framework", "YiiBase.php"),
            os.path.join("vendor", "yiisoft", "yii2", "BaseYii.php"),
        ]:
            content = _safe_read_text(os.path.join(path, candidate))
            if content:
                m = self._YII_VERSION_RE.search(content)
                if m:
                    return m.group(1)

        return self._version_from_composer_lock(path, "yiisoft/yii2")

    def _version_from_composer_lock(self, path, package_name):
        # type: (str, str) -> str
        """
        Extract a package version from composer.lock.

        Args:
            path:         Site root directory.
            package_name: Composer package name, e.g. ``"laravel/framework"``.

        Returns:
            Version string or empty.
        """
        lock_path = os.path.join(path, "composer.lock")
        content = _safe_read_text(lock_path)
        if not content:
            return ""
        try:
            data = json.loads(content)
            packages = data.get("packages", [])
            for pkg in packages:
                if pkg.get("name", "").lower() == package_name.lower():
                    version = pkg.get("version", "")
                    # Strip leading 'v'
                    if version.startswith("v"):
                        version = version[1:]
                    return version
        except (ValueError, KeyError, TypeError):
            pass
        return ""

    # ── DB Prefix Extraction ─────────────────────────────────────────

    def _extract_db_prefix(self, path, platform_type):
        # type: (str, str) -> str
        """Extract DB table prefix from config file if possible."""
        if platform_type == PlatformType.WORDPRESS:
            content = _safe_read_text(os.path.join(path, "wp-config.php"))
            m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]*)['\"]", content)
            return m.group(1) if m else ""

        if platform_type == PlatformType.JOOMLA:
            content = _safe_read_text(os.path.join(path, "configuration.php"))
            m = re.search(r"\$dbprefix\s*=\s*['\"]([^'\"]*)['\"]", content)
            return m.group(1) if m else ""

        if platform_type == PlatformType.PRESTASHOP:
            content = _safe_read_text(os.path.join(path, "config", "settings.inc.php"))
            m = re.search(r"define\s*\(\s*['\"]_DB_PREFIX_['\"]\s*,\s*['\"]([^'\"]*)['\"]", content)
            return m.group(1) if m else ""

        return ""

    # ── Config Secrets Extraction ────────────────────────────────────

    def get_config_secrets(self, path, platform_info):
        # type: (str, PlatformInfo) -> Dict[str, Any]
        """
        Extract database credentials and secret keys from the
        platform's config file.  Used for audit, NOT stored in
        scan reports — only metadata (e.g. "password is empty" or
        "default key detected") is reported.

        Args:
            path:          Site root directory.
            platform_info: Previously detected ``PlatformInfo``.

        Returns:
            Dictionary with keys like ``db_host``, ``db_name``,
            ``db_user``, ``db_pass``, ``secret_keys``, etc.
        """
        secrets = {
            "db_host": "",
            "db_name": "",
            "db_user": "",
            "db_pass": "",
            "secret_keys": {},
            "issues": [],
        }  # type: Dict[str, Any]

        dispatch = {
            PlatformType.WORDPRESS: self._secrets_wordpress,
            PlatformType.JOOMLA: self._secrets_joomla,
            PlatformType.DRUPAL: self._secrets_drupal,
            PlatformType.LARAVEL: self._secrets_dotenv,
            PlatformType.SYMFONY: self._secrets_dotenv,
            PlatformType.CODEIGNITER: self._secrets_dotenv,
            PlatformType.MAGENTO2: self._secrets_magento2,
            PlatformType.MOODLE: self._secrets_moodle,
        }  # type: Dict[str, Any]

        handler = dispatch.get(platform_info.platform_type)
        if handler is None:
            return secrets

        try:
            return handler(path, secrets)
        except Exception as exc:
            logger.debug("Config secrets extraction error: %s", exc)
            secrets["issues"].append("Failed to parse config: %s" % str(exc))
            return secrets

    def _secrets_wordpress(self, path, secrets):
        # type: (str, Dict[str, Any]) -> Dict[str, Any]
        content = _safe_read_text(os.path.join(path, "wp-config.php"))
        if not content:
            secrets["issues"].append("wp-config.php not readable")
            return secrets

        defines = {
            "DB_HOST": "db_host",
            "DB_NAME": "db_name",
            "DB_USER": "db_user",
            "DB_PASSWORD": "db_pass",
        }
        for const, key in defines.items():
            m = re.search(
                r"define\s*\(\s*['\"]%s['\"]\s*,\s*['\"]([^'\"]*)['\"]" % re.escape(const),
                content,
            )
            if m:
                secrets[key] = m.group(1)

        # Check secret keys
        key_names = [
            "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
            "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT",
        ]
        for key_name in key_names:
            m = re.search(
                r"define\s*\(\s*['\"]%s['\"]\s*,\s*['\"]([^'\"]*)['\"]" % re.escape(key_name),
                content,
            )
            if m:
                val = m.group(1)
                secrets["secret_keys"][key_name] = val
                if not val or val == "put your unique phrase here":
                    secrets["issues"].append("Default or empty %s" % key_name)

        if not secrets["db_pass"]:
            secrets["issues"].append("Empty database password")

        return secrets

    def _secrets_joomla(self, path, secrets):
        # type: (str, Dict[str, Any]) -> Dict[str, Any]
        content = _safe_read_text(os.path.join(path, "configuration.php"))
        if not content:
            secrets["issues"].append("configuration.php not readable")
            return secrets

        mappings = {
            r"\$host\s*=\s*['\"]([^'\"]*)['\"]": "db_host",
            r"\$db\s*=\s*['\"]([^'\"]*)['\"]": "db_name",
            r"\$user\s*=\s*['\"]([^'\"]*)['\"]": "db_user",
            r"\$password\s*=\s*['\"]([^'\"]*)['\"]": "db_pass",
            r"\$secret\s*=\s*['\"]([^'\"]*)['\"]": None,
        }
        for pattern, key in mappings.items():
            m = re.search(pattern, content)
            if m:
                val = m.group(1)
                if key:
                    secrets[key] = val
                else:
                    secrets["secret_keys"]["secret"] = val
                    if not val:
                        secrets["issues"].append("Empty Joomla secret key")

        if not secrets["db_pass"]:
            secrets["issues"].append("Empty database password")

        return secrets

    def _secrets_drupal(self, path, secrets):
        # type: (str, Dict[str, Any]) -> Dict[str, Any]
        content = _safe_read_text(os.path.join(path, "sites", "default", "settings.php"))
        if not content:
            secrets["issues"].append("settings.php not readable")
            return secrets

        # Drupal 7/8 use $databases array
        db_match = re.search(
            r"'database'\s*=>\s*'([^']*)'", content
        )
        if db_match:
            secrets["db_name"] = db_match.group(1)

        user_match = re.search(r"'username'\s*=>\s*'([^']*)'", content)
        if user_match:
            secrets["db_user"] = user_match.group(1)

        pass_match = re.search(r"'password'\s*=>\s*'([^']*)'", content)
        if pass_match:
            secrets["db_pass"] = pass_match.group(1)

        host_match = re.search(r"'host'\s*=>\s*'([^']*)'", content)
        if host_match:
            secrets["db_host"] = host_match.group(1)

        # Hash salt
        salt_match = re.search(r"\$settings\['hash_salt'\]\s*=\s*'([^']*)'", content)
        if salt_match:
            val = salt_match.group(1)
            secrets["secret_keys"]["hash_salt"] = val
            if not val:
                secrets["issues"].append("Empty Drupal hash_salt")

        if not secrets["db_pass"]:
            secrets["issues"].append("Empty database password")

        return secrets

    def _secrets_dotenv(self, path, secrets):
        # type: (str, Dict[str, Any]) -> Dict[str, Any]
        """Parse .env file (Laravel, Symfony, CodeIgniter 4)."""
        content = _safe_read_text(os.path.join(path, ".env"))
        if not content:
            secrets["issues"].append(".env file not readable")
            return secrets

        env_vars = {}  # type: Dict[str, str]
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'\"")
                env_vars[key] = val

        secrets["db_host"] = env_vars.get("DB_HOST", "")
        secrets["db_name"] = env_vars.get("DB_DATABASE", env_vars.get("DB_NAME", ""))
        secrets["db_user"] = env_vars.get("DB_USERNAME", env_vars.get("DB_USER", ""))
        secrets["db_pass"] = env_vars.get("DB_PASSWORD", "")

        # Check secret / API keys
        secret_keys = [
            "APP_KEY", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET",
            "MAIL_PASSWORD", "REDIS_PASSWORD",
        ]
        for sk in secret_keys:
            if sk in env_vars:
                secrets["secret_keys"][sk] = env_vars[sk]
                if not env_vars[sk]:
                    secrets["issues"].append("Empty %s" % sk)

        if not secrets["db_pass"]:
            secrets["issues"].append("Empty database password")

        return secrets

    def _secrets_magento2(self, path, secrets):
        # type: (str, Dict[str, Any]) -> Dict[str, Any]
        """Parse app/etc/env.php for Magento 2 config."""
        content = _safe_read_text(os.path.join(path, "app", "etc", "env.php"))
        if not content:
            secrets["issues"].append("env.php not readable")
            return secrets

        # PHP array format — use regex
        host_m = re.search(r"'host'\s*=>\s*'([^']*)'", content)
        if host_m:
            secrets["db_host"] = host_m.group(1)

        dbname_m = re.search(r"'dbname'\s*=>\s*'([^']*)'", content)
        if dbname_m:
            secrets["db_name"] = dbname_m.group(1)

        user_m = re.search(r"'username'\s*=>\s*'([^']*)'", content)
        if user_m:
            secrets["db_user"] = user_m.group(1)

        pass_m = re.search(r"'password'\s*=>\s*'([^']*)'", content)
        if pass_m:
            secrets["db_pass"] = pass_m.group(1)

        # Crypt key
        key_m = re.search(r"'key'\s*=>\s*'([^']*)'", content)
        if key_m:
            secrets["secret_keys"]["crypt_key"] = key_m.group(1)

        if not secrets["db_pass"]:
            secrets["issues"].append("Empty database password")

        return secrets

    def _secrets_moodle(self, path, secrets):
        # type: (str, Dict[str, Any]) -> Dict[str, Any]
        """Parse config.php for Moodle config."""
        content = _safe_read_text(os.path.join(path, "config.php"))
        if not content:
            secrets["issues"].append("config.php not readable")
            return secrets

        mappings = {
            r"\$CFG->dbhost\s*=\s*['\"]([^'\"]*)['\"]": "db_host",
            r"\$CFG->dbname\s*=\s*['\"]([^'\"]*)['\"]": "db_name",
            r"\$CFG->dbuser\s*=\s*['\"]([^'\"]*)['\"]": "db_user",
            r"\$CFG->dbpass\s*=\s*['\"]([^'\"]*)['\"]": "db_pass",
            r"\$CFG->passwordsaltmain\s*=\s*['\"]([^'\"]*)['\"]": None,
        }
        for pattern, key in mappings.items():
            m = re.search(pattern, content)
            if m:
                val = m.group(1)
                if key:
                    secrets[key] = val
                else:
                    secrets["secret_keys"]["passwordsaltmain"] = val

        if not secrets["db_pass"]:
            secrets["issues"].append("Empty database password")

        return secrets

    # ── Writable Directories ─────────────────────────────────────────

    def get_writable_dirs(self, platform_info):
        # type: (PlatformInfo) -> List[str]
        """
        Return platform-specific directories that accept uploads or
        caches and should be checked for rogue PHP files.

        Args:
            platform_info: Detected ``PlatformInfo``.

        Returns:
            List of relative directory paths.
        """
        dirs_map = {
            PlatformType.WORDPRESS: [
                "wp-content/uploads",
                "wp-content/cache",
                "wp-content/upgrade",
                "wp-content/wflogs",
                "wp-content/mu-plugins",
            ],
            PlatformType.JOOMLA: [
                "images",
                "media",
                "tmp",
                "cache",
                "administrator/cache",
                "logs",
            ],
            PlatformType.DRUPAL: [
                "sites/default/files",
                "sites/default/files/private",
                "sites/default/files/tmp",
            ],
            PlatformType.MAGENTO2: [
                "pub/media",
                "pub/static",
                "var",
                "var/cache",
                "var/log",
                "generated",
            ],
            PlatformType.MAGENTO1: [
                "media",
                "var",
                "var/cache",
                "var/log",
            ],
            PlatformType.PRESTASHOP: [
                "img",
                "upload",
                "download",
                "cache",
                "var/cache",
                "var/logs",
            ],
            PlatformType.WHMCS: [
                "attachments",
                "downloads",
                "templates_c",
            ],
            PlatformType.MOODLE: [
                "moodledata",
                "filedir",
            ],
            PlatformType.OPENCART: [
                "image",
                "system/storage",
                "system/storage/cache",
                "system/storage/logs",
            ],
            PlatformType.MEDIAWIKI: [
                "images",
                "images/thumb",
            ],
            PlatformType.LARAVEL: [
                "storage",
                "storage/app/public",
                "storage/framework/cache",
                "storage/logs",
                "public/storage",
            ],
            PlatformType.SYMFONY: [
                "var",
                "var/cache",
                "var/log",
                "public/uploads",
            ],
            PlatformType.CODEIGNITER: [
                "writable",
                "writable/cache",
                "writable/logs",
                "writable/uploads",
            ],
            PlatformType.CAKEPHP: [
                "tmp",
                "tmp/cache",
                "logs",
                "webroot/uploads",
            ],
            PlatformType.YII: [
                "runtime",
                "runtime/cache",
                "web/assets",
                "web/uploads",
            ],
        }  # type: Dict[str, List[str]]

        return dirs_map.get(platform_info.platform_type, [])

    # ── Backdoor Paths ───────────────────────────────────────────────

    def get_backdoor_paths(self, platform_info):
        # type: (PlatformInfo) -> List[str]
        """
        Return platform-specific filesystem paths where backdoors are
        commonly planted.

        Args:
            platform_info: Detected ``PlatformInfo``.

        Returns:
            List of relative file/directory paths to inspect.
        """
        paths_map = {
            PlatformType.WORDPRESS: [
                "wp-content/mu-plugins/",
                "wp-content/uploads/",
                "wp-includes/wp-tmp.php",
                "wp-includes/wp-vcd.php",
                "wp-admin/includes/class-wp-tmp.php",
                "wp-content/themes/index.php",
                "wp-content/plugins/index.php",
                ".wp-config.php.swp",
                "wp-config.php.bak",
            ],
            PlatformType.JOOMLA: [
                "images/stories/",
                "media/",
                "tmp/",
                "administrator/components/com_admin/sql/",
                "libraries/joomla/cache/",
                "configuration.php.bak",
            ],
            PlatformType.DRUPAL: [
                "sites/default/files/.htaccess",
                "sites/default/files/php/",
                "sites/all/modules/",
                "misc/",
            ],
            PlatformType.MAGENTO2: [
                "pub/media/.htaccess",
                "var/",
                "generated/code/",
                "app/etc/env.php.bak",
            ],
            PlatformType.MAGENTO1: [
                "media/",
                "skin/",
                "downloader/",
                "var/",
                "app/etc/local.xml.bak",
            ],
            PlatformType.PRESTASHOP: [
                "upload/",
                "img/",
                "cache/",
                "config/settings.inc.php.bak",
            ],
            PlatformType.WHMCS: [
                "attachments/",
                "downloads/",
                "templates_c/",
                "configuration.php.bak",
            ],
            PlatformType.MOODLE: [
                "moodledata/",
                "lib/editor/",
            ],
            PlatformType.OPENCART: [
                "image/",
                "system/storage/",
            ],
            PlatformType.MEDIAWIKI: [
                "images/",
                "maintenance/",
            ],
            PlatformType.LARAVEL: [
                "storage/app/",
                "public/",
                ".env.backup",
                ".env.old",
            ],
            PlatformType.SYMFONY: [
                "var/",
                "public/",
                ".env.local",
            ],
            PlatformType.CODEIGNITER: [
                "writable/",
                "public/",
            ],
            PlatformType.CAKEPHP: [
                "tmp/",
                "webroot/",
            ],
            PlatformType.YII: [
                "runtime/",
                "web/",
            ],
        }  # type: Dict[str, List[str]]

        return paths_map.get(platform_info.platform_type, [])

    # ── Config File Permission Check ─────────────────────────────────

    def check_config_permissions(self, path, platform_info):
        # type: (str, PlatformInfo) -> List[Dict[str, Any]]
        """
        Check config file permissions and detect backup copies.

        Args:
            path:          Site root directory.
            platform_info: Detected ``PlatformInfo``.

        Returns:
            List of issue dictionaries with ``severity``, ``title``,
            and ``detail`` keys.
        """
        issues = []  # type: List[Dict[str, Any]]
        config_rel = self._CONFIG_FILES.get(platform_info.platform_type, "")
        if not config_rel:
            return issues

        config_path = os.path.join(path, config_rel)

        # Check permissions
        try:
            if os.path.exists(config_path):
                st = os.stat(config_path)
                mode = st.st_mode
                # World-readable check
                if mode & stat.S_IROTH:
                    issues.append({
                        "severity": "high",
                        "title": "Config file is world-readable: %s" % config_rel,
                        "detail": "Permissions: %s (should be 640 or stricter)" % oct(mode)[-3:],
                    })
                # World-writable check
                if mode & stat.S_IWOTH:
                    issues.append({
                        "severity": "critical",
                        "title": "Config file is world-writable: %s" % config_rel,
                        "detail": "Permissions: %s" % oct(mode)[-3:],
                    })
        except (OSError, PermissionError) as exc:
            logger.debug("Permission check error for %s: %s", config_path, exc)

        # Check for backup copies
        backup_exts = [".bak", ".old", ".save", ".orig", ".copy", ".swp", "~"]
        for ext in backup_exts:
            backup_path = config_path + ext
            try:
                if os.path.exists(backup_path):
                    issues.append({
                        "severity": "high",
                        "title": "Config backup file found: %s%s" % (config_rel, ext),
                        "detail": "Backup config file may expose credentials if web-accessible",
                    })
            except (OSError, PermissionError):
                pass

        return issues
