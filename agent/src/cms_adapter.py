"""
CMS Adapter — abstraction layer for multi-CMS scanning support.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Provides a pluggable adapter pattern so the scanning engine can work
with different CMS platforms (WordPress, Joomla, Drupal, …) or fall
back to a generic filesystem-only scan.

Architecture::

    CMSAdapter (ABC)
      ├─ WordPressAdapter   — delegates to wp.py discovery & parsing
      └─ GenericAdapter      — filesystem-only fallback (no DB, no core check)

Usage::

    from .cms_adapter import get_adapter

    adapter = get_adapter(site_path)
    if adapter.detect(site_path):
        sites  = adapter.get_sites(base_path)
        creds  = adapter.get_db_credentials(site_path)
        core   = adapter.get_core_files(site_path)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("cleanshift.cms_adapter")


# ── Abstract Base Class ─────────────────────────────────────────────────


class CMSAdapter(ABC):
    """Abstract interface for CMS-specific operations.

    Each concrete adapter encapsulates:
    - Detection  (is this CMS present at a given path?)
    - Discovery  (find all CMS installations under a base directory)
    - Credential extraction  (parse database credentials from config files)
    - Core file enumeration  (list files eligible for integrity checking)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the CMS (e.g. 'WordPress', 'Generic')."""
        ...

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """Return ``True`` if this CMS is detected at *path*.

        Args:
            path: Absolute path to a potential CMS installation root.
        """
        ...

    @abstractmethod
    def get_sites(self, base_path: Path) -> List[Path]:
        """Discover all CMS installations under *base_path*.

        Args:
            base_path: Root directory to search (e.g. ``/home``).

        Returns:
            List of absolute paths to CMS installation roots.
        """
        ...

    @abstractmethod
    def get_db_credentials(self, site_path: Path) -> Dict[str, str]:
        """Extract database credentials from the CMS configuration.

        Args:
            site_path: Absolute path to a CMS installation root.

        Returns:
            Dictionary with keys like ``DB_NAME``, ``DB_USER``, etc.
            Returns an empty dict when DB scanning is not applicable.
        """
        ...

    @abstractmethod
    def get_core_files(self, site_path: Path) -> List[Path]:
        """Return a list of core CMS files suitable for integrity checking.

        Args:
            site_path: Absolute path to a CMS installation root.

        Returns:
            List of file paths.  Empty if integrity checking is not
            supported for this CMS type.
        """
        ...


# ── WordPress Adapter ──────────────────────────────────────────────────


class WordPressAdapter(CMSAdapter):
    """Concrete adapter for WordPress installations.

    Delegates to the existing ``wp.py`` module which already handles
    WordPress discovery, wp-config.php parsing, and WP-CLI interaction.
    This adapter provides a clean interface that the scanner can use
    without being tightly coupled to WordPress-specific code.
    """

    @property
    def name(self) -> str:
        return "WordPress"

    def detect(self, path: Path) -> bool:
        """Detect WordPress by checking for ``wp-config.php``.

        Also verifies the presence of ``wp-includes/`` or ``wp-admin/``
        to avoid false positives from standalone wp-config.php files.
        """
        wp_config = path / "wp-config.php"
        if not wp_config.exists():
            return False
        # Require at least one core directory to confirm it's actually WP
        return (path / "wp-includes").is_dir() or (path / "wp-admin").is_dir()

    def get_sites(self, base_path: Path) -> List[Path]:
        """Discover WordPress installations using ``wp.discover_wp_sites()``.

        Delegates entirely to the battle-tested discovery logic in
        ``wp.py`` which handles cPanel, Plesk, and fallback directory
        traversal.
        """
        from .wp import discover_wp_sites

        return discover_wp_sites(str(base_path))

    def get_db_credentials(self, site_path: Path) -> Dict[str, str]:
        """Parse ``wp-config.php`` to extract database credentials.

        Delegates to ``wp.parse_wp_config()`` which uses regex-based
        extraction of ``define()`` constants and ``$table_prefix``.

        Returns:
            Dict with keys: ``DB_NAME``, ``DB_USER``, ``DB_PASSWORD``,
            ``DB_HOST``, ``DB_CHARSET``, ``DB_COLLATE``, ``table_prefix``.
        """
        from .wp import parse_wp_config

        wp_config = site_path / "wp-config.php"
        if not wp_config.exists():
            logger.warning("wp-config.php not found at %s", site_path)
            return {}

        try:
            return parse_wp_config(wp_config)
        except (FileNotFoundError, PermissionError) as exc:
            logger.error("Failed to parse wp-config.php at %s: %s", site_path, exc)
            return {}

    def get_core_files(self, site_path: Path) -> List[Path]:
        """Return WordPress core files for integrity checking.

        Enumerates PHP files in ``wp-includes/`` and ``wp-admin/``
        directories, which are the primary targets for core file
        tampering detection.
        """
        core_files: List[Path] = []
        core_dirs = ["wp-includes", "wp-admin"]

        for dirname in core_dirs:
            core_dir = site_path / dirname
            if not core_dir.is_dir():
                continue
            try:
                for php_file in core_dir.rglob("*.php"):
                    if php_file.is_file():
                        core_files.append(php_file)
            except PermissionError:
                logger.warning("Permission denied reading %s", core_dir)

        logger.debug(
            "WordPress core files at %s: %d files in %s",
            site_path,
            len(core_files),
            core_dirs,
        )
        return core_files


# ── Generic Adapter ────────────────────────────────────────────────────


class GenericAdapter(CMSAdapter):
    """Fallback adapter for non-CMS or unrecognized sites.

    Performs file-system-only scanning — no database credentials are
    extracted and no core file integrity checking is performed.  This
    allows CleanShift to still scan for malware in arbitrary directory
    trees (e.g. static sites, custom PHP apps) using YARA and pattern
    matching.
    """

    @property
    def name(self) -> str:
        return "Generic"

    def detect(self, path: Path) -> bool:
        """Always returns ``True`` — this is the universal fallback."""
        return True

    def get_sites(self, base_path: Path) -> List[Path]:
        """Return the base path itself as the only 'site'.

        For non-CMS directories we treat the entire directory as a
        single scan target.
        """
        if base_path.is_dir():
            return [base_path]
        return []

    def get_db_credentials(self, site_path: Path) -> Dict[str, str]:
        """Return an empty dict — no database scanning for generic sites."""
        return {}

    def get_core_files(self, site_path: Path) -> List[Path]:
        """Return an empty list — no core integrity checking for generic sites."""
        return []


# ── Factory ────────────────────────────────────────────────────────────


# Registry of adapters in priority order.  First match wins.
_ADAPTERS: List[CMSAdapter] = [
    WordPressAdapter(),
    # Future: JoomlaAdapter(), DrupalAdapter(), …
    GenericAdapter(),  # Must be last — always matches
]


def get_adapter(site_path: Path) -> CMSAdapter:
    """Select the appropriate CMS adapter for *site_path*.

    Iterates through registered adapters in priority order and returns
    the first one whose ``detect()`` method returns ``True``.  The
    ``GenericAdapter`` always matches, so this function never returns
    ``None``.

    Args:
        site_path: Absolute path to a potential site installation.

    Returns:
        A concrete ``CMSAdapter`` instance.
    """
    for adapter in _ADAPTERS:
        if adapter.detect(site_path):
            logger.info(
                "Selected %s adapter for %s",
                adapter.name,
                site_path,
            )
            return adapter

    # Should never reach here — GenericAdapter.detect() always returns True
    fallback = GenericAdapter()
    logger.warning("No adapter matched %s — using Generic fallback", site_path)
    return fallback
