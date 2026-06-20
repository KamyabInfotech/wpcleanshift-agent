"""
CleanShift Hosting Panel Detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Auto-detects the hosting control panel (cPanel, Plesk, or custom) and
provides panel-agnostic helpers for site discovery, user resolution,
and path mapping.

This module centralizes all hosting-panel-specific logic so that the
rest of the codebase can work uniformly regardless of whether the
server runs cPanel or Plesk.

Usage::

    from .hosting import HostingDetector, HostingPanel

    panel = HostingDetector.detect()
    base_paths = HostingDetector.get_base_paths()
    owner = HostingDetector.get_user_from_path("/var/www/vhosts/example.com/httpdocs")
    home = HostingDetector.get_user_home(owner)
"""


from __future__ import annotations

import logging
import os
import threading
from enum import Enum
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("cleanshift.hosting")


class HostingPanel(str, Enum):
    """Supported hosting control panels."""
    CPANEL = "cpanel"
    PLESK = "plesk"
    CUSTOM = "custom"


class HostingDetector:
    """
    Auto-detects the hosting panel and provides panel-agnostic helpers.

    Detection is cached per-process (thread-safe singleton). All methods
    are safe to call on any server — missing files and permission errors
    are handled gracefully.
    """

    _panel: Optional[HostingPanel] = None
    _lock = threading.Lock()

    # ── Filesystem signatures ────────────────────────────────────────

    _CPANEL_SIGNATURES = [
        "/usr/local/cpanel/cpanel",
        "/var/cpanel/",
        "/etc/trueuserdomains",
        "/usr/local/cpanel/version",
    ]

    _PLESK_SIGNATURES = [
        "/usr/local/psa/version",
        "/usr/local/psa/",
        "/var/www/vhosts/",
        "/opt/psa/",
    ]

    # ── Common MySQL socket paths, ordered by likelihood ─────────────

    _MYSQL_SOCKETS = [
        "/var/lib/mysql/mysql.sock",         # RHEL/CentOS/Plesk
        "/run/mysqld/mysqld.sock",           # Debian/Ubuntu
        "/var/run/mysqld/mysqld.sock",       # Debian older
        "/tmp/mysql.sock",                   # macOS / fallback
        "/var/lib/mysql/mysqld.sock",        # some RHEL variants
    ]

    # ── Panel Detection ──────────────────────────────────────────────

    @classmethod
    def detect(cls) -> HostingPanel:
        """
        Auto-detect the hosting panel from filesystem signatures.

        Returns:
            HostingPanel enum value.
        """
        if cls._panel is not None:
            return cls._panel

        with cls._lock:
            if cls._panel is not None:
                return cls._panel

            panel = cls._detect_impl()
            cls._panel = panel
            logger.info("Hosting panel detected: %s", panel.value)
            return panel

    @classmethod
    def _detect_impl(cls) -> HostingPanel:
        """Internal detection logic."""
        cpanel_score = sum(1 for p in cls._CPANEL_SIGNATURES if _path_exists(p))
        plesk_score = sum(1 for p in cls._PLESK_SIGNATURES if _path_exists(p))

        if cpanel_score >= 2:
            return HostingPanel.CPANEL
        if plesk_score >= 2:
            return HostingPanel.PLESK

        # Single-signal fallbacks
        if cpanel_score == 1:
            return HostingPanel.CPANEL
        if plesk_score == 1:
            return HostingPanel.PLESK

        return HostingPanel.CUSTOM

    @classmethod
    def reset_cache(cls) -> None:
        """Reset the cached detection (useful for testing)."""
        cls._panel = None

    # ── Path Helpers ─────────────────────────────────────────────────

    @classmethod
    def get_base_paths(cls) -> List[str]:
        """
        Return site discovery base paths for the detected panel.

        Returns:
            List of absolute paths to scan for sites.
        """
        panel = cls.detect()
        if panel == HostingPanel.CPANEL:
            return ["/home"]
        elif panel == HostingPanel.PLESK:
            return ["/var/www/vhosts"]
        else:
            # Custom: check what exists
            paths = []
            if _path_exists("/var/www/vhosts"):
                paths.append("/var/www/vhosts")
            if _path_exists("/home"):
                paths.append("/home")
            return paths or ["/home"]

    @classmethod
    def get_docroot_names(cls) -> List[str]:
        """
        Return document root directory names for the detected panel.

        Returns:
            List of directory names that may contain WordPress installs.
        """
        panel = cls.detect()
        if panel == HostingPanel.CPANEL:
            return ["public_html"]
        elif panel == HostingPanel.PLESK:
            return ["httpdocs", "public_html"]
        else:
            return ["httpdocs", "public_html", "www", "html"]

    @classmethod
    def get_exclude_paths(cls) -> List[str]:
        """
        Return panel-specific paths to exclude from scanning.

        Returns:
            List of absolute paths or directory names to skip.
        """
        panel = cls.detect()
        excludes = []

        if panel == HostingPanel.CPANEL:
            excludes.extend([
                "/home/virtfs",
                "/home/cPanelInstall",
                "/home/cpeasyapache",
            ])
        elif panel == HostingPanel.PLESK:
            excludes.extend([
                "/var/www/vhosts/.skel",
                "/var/www/vhosts/default",
                "/var/www/vhosts/fs",
                "/var/www/vhosts/chroot",
            ])

        return excludes

    @classmethod
    def get_exclude_dir_names(cls) -> set:
        """
        Return directory names to skip during site enumeration.

        Returns:
            Set of directory basenames to exclude.
        """
        panel = cls.detect()
        names = set()

        if panel == HostingPanel.CPANEL:
            names.update({"cPanelInstall", "cpeasyapache", "virtfs"})
        elif panel == HostingPanel.PLESK:
            names.update({".skel", "default", "fs", "chroot"})

        # Common excludes regardless of panel
        names.update({".trash", ".quarantine", "logs", "tmp"})
        return names

    # ── User Resolution ──────────────────────────────────────────────

    @classmethod
    def get_user_from_path(cls, site_path: str) -> str:
        """
        Determine the Unix system user owning files at a site path.

        Uses ``os.stat()`` to get the actual file owner — works on
        both cPanel and Plesk regardless of path structure.

        Args:
            site_path: Absolute path to a WordPress site root.

        Returns:
            Unix username, or empty string on failure.
        """
        try:
            import pwd
            st = os.stat(site_path)
            return pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, OSError, ImportError):
            # Fallback: try to infer from path
            return cls._infer_user_from_path(site_path)

    @classmethod
    def _infer_user_from_path(cls, site_path: str) -> str:
        """
        Fallback: infer user/domain from path structure.

        cPanel: /home/{username}/public_html → username
        Plesk:  /var/www/vhosts/{domain}/httpdocs → domain (not a unix user)
        """
        parts = Path(site_path).parts
        if "home" in parts:
            idx = parts.index("home")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        if "vhosts" in parts:
            idx = parts.index("vhosts")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return ""

    @classmethod
    def get_user_home(cls, username: str) -> str:
        """
        Resolve the actual home directory for a Unix user.

        Uses ``pwd.getpwnam()`` to get the real home directory, avoiding
        hardcoded assumptions like ``/home/{user}``.

        Args:
            username: Unix username (e.g. ``"astrocrat"``).

        Returns:
            Absolute path to user's home directory, or empty string.
        """
        if not username:
            return ""
        try:
            import pwd
            return pwd.getpwnam(username).pw_dir
        except (KeyError, ImportError):
            # Fallback: try common locations
            for base in ["/home", "/var/www/vhosts"]:
                candidate = os.path.join(base, username)
                if _path_exists(candidate):
                    return candidate
            return ""

    @classmethod
    def get_site_home_boundary(cls, site_path: str) -> str:
        """
        Return the boundary directory for symlink escape detection.

        On cPanel: /home/{user}
        On Plesk:  /var/www/vhosts/{domain}

        Args:
            site_path: Absolute path to a site root.

        Returns:
            The parent boundary path, or empty string.
        """
        parts = Path(site_path).parts

        # Plesk: /var/www/vhosts/{domain}/httpdocs
        if "vhosts" in parts:
            idx = parts.index("vhosts")
            if idx + 1 < len(parts):
                return str(Path(*parts[:idx + 2]))

        # cPanel: /home/{user}/public_html
        if "home" in parts:
            idx = parts.index("home")
            if idx + 1 < len(parts):
                return str(Path(*parts[:idx + 2]))

        # macOS/dev: /Users/{user}
        if "Users" in parts:
            idx = parts.index("Users")
            if idx + 1 < len(parts):
                return str(Path(*parts[:idx + 2]))

        return ""

    # ── MySQL Socket ─────────────────────────────────────────────────

    _mysql_socket: Optional[str] = None

    @classmethod
    def get_mysql_socket(cls) -> Optional[str]:
        """
        Find the MySQL/MariaDB Unix socket path.

        Caches the result. Returns None if no socket is found
        (indicating TCP should be used instead).
        """
        if cls._mysql_socket is not None:
            return cls._mysql_socket if cls._mysql_socket != "" else None

        for sock_path in cls._MYSQL_SOCKETS:
            if _path_exists(sock_path):
                cls._mysql_socket = sock_path
                logger.info("MySQL socket found: %s", sock_path)
                return sock_path

        cls._mysql_socket = ""  # Sentinel: checked but not found
        logger.info("No MySQL socket found, will use TCP")
        return None


# ─── Private Helpers ────────────────────────────────────────────────

def _path_exists(path: str) -> bool:
    """Check path existence, returning False on permission errors."""
    try:
        return os.path.exists(path)
    except (OSError, PermissionError):
        return False
