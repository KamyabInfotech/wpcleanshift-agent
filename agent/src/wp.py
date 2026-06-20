"""
CleanShift WordPress Helpers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Utilities for discovering WordPress installations on cPanel and Plesk
servers, parsing wp-config.php, and running wp-cli commands. All
file-system operations use pathlib; all subprocesses use safe shell-out
patterns.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import PluginInfo, ThemeInfo, WordPressSite

logger = logging.getLogger("wpcleanshift.wp")

# Patterns for extracting define() calls from wp-config.php
_DEFINE_PATTERN = re.compile(
    r"""define\s*\(\s*['"](\w+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""",
    re.IGNORECASE,
)

# Pattern for extracting $table_prefix
_TABLE_PREFIX_PATTERN = re.compile(
    r"""\$table_prefix\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def parse_wp_config(wp_config_path: Path) -> Dict[str, str]:
    """
    Parse wp-config.php to extract database credentials and settings.

    Uses regex to extract define() constants and $table_prefix. This
    avoids executing PHP and handles the vast majority of wp-config
    formats in the wild.

    Args:
        wp_config_path: Absolute path to wp-config.php.

    Returns:
        Dictionary with keys: DB_NAME, DB_USER, DB_PASSWORD, DB_HOST,
        DB_CHARSET, DB_COLLATE, table_prefix. Missing values default
        to sensible WordPress defaults.

    Raises:
        FileNotFoundError: If wp-config.php doesn't exist.
        PermissionError: If the file can't be read.
    """
    config: Dict[str, str] = {
        "DB_NAME": "",
        "DB_USER": "",
        "DB_PASSWORD": "",
        "DB_HOST": "localhost",
        "DB_CHARSET": "utf8",
        "DB_COLLATE": "",
        "table_prefix": "wp_",
    }

    path = Path(wp_config_path)
    if not path.exists():
        raise FileNotFoundError(f"wp-config.php not found: {path}")

    content = path.read_text(encoding="utf-8", errors="replace")

    # Extract all define() constants
    for match in _DEFINE_PATTERN.finditer(content):
        key, value = match.group(1), match.group(2)
        if key in config:
            config[key] = value

    # Extract $table_prefix
    prefix_match = _TABLE_PREFIX_PATTERN.search(content)
    if prefix_match:
        raw_prefix = prefix_match.group(1)
        # Validate prefix to prevent SQL injection — only allow safe characters
        if re.match(r'^[a-zA-Z0-9_]{1,64}$', raw_prefix):
            config["table_prefix"] = raw_prefix
        else:
            logger.warning(
                "Unsafe table_prefix in %s: %r — using default 'wp_'",
                path, raw_prefix,
            )

    logger.debug(
        "Parsed wp-config at %s: db=%s, user=%s, host=%s, prefix=%s",
        path, config["DB_NAME"], config["DB_USER"],
        config["DB_HOST"], config["table_prefix"],
    )
    return config


def discover_wp_sites(base_path: str = "") -> List[Path]:
    """
    Find all WordPress installations under a base directory.

    Searches for wp-config.php files, which is the definitive marker
    of a WordPress installation. Skips common false-positive locations
    like plugin/theme directories that bundle wp-config examples.

    Auto-detects the base path from the hosting panel if not specified.

    Args:
        base_path: Root directory to search. If empty, auto-detects
                   from the hosting panel (cPanel: /home, Plesk: /var/www/vhosts).

    Returns:
        List of Paths to WordPress root directories (parent of wp-config.php).
    """
    if not base_path:
        try:
            from .hosting import HostingDetector
            base_paths = HostingDetector.get_base_paths()
            base_path = base_paths[0] if base_paths else "/home"
        except ImportError:
            base_path = "/home"
    base = Path(base_path)
    if not base.exists():
        logger.warning("Base path does not exist: %s", base)
        return []

    wp_roots: List[Path] = []
    exclude_patterns = {
        "node_modules",
        ".git",
        "vendor",
        "cache",
        "backup",
        "backups",
        ".trash",
        "tmp",
    }

    logger.info("Discovering WordPress sites under %s ...", base)

    try:
        fast_found: set = set()

        # ── Fast path 1: cPanel user-based discovery ──────────────────
        # Instead of globbing /home/*/public_html/* (which chokes on
        # I/O-saturated servers), enumerate cPanel users and check each
        # user's home directory directly. This is O(users) not O(files).
        cpanel_users: List[str] = []
        trueuserdomains = Path("/etc/trueuserdomains")
        if trueuserdomains.exists():
            try:
                for line in trueuserdomains.read_text().strip().split("\n"):
                    if ":" in line:
                        user = line.split(":")[-1].strip()
                        if user and user not in cpanel_users:
                            cpanel_users.append(user)
                logger.info("Found %d cPanel users from trueuserdomains", len(cpanel_users))
            except Exception as e:
                logger.debug("Could not read trueuserdomains: %s", e)

        if not cpanel_users:
            # Fallback: list base directories, excluding panel-specific dirs
            try:
                from .hosting import HostingDetector
                exclude_names = HostingDetector.get_exclude_dir_names()
            except ImportError:
                exclude_names = {"cPanelInstall", "cpeasyapache", "virtfs"}
            try:
                cpanel_users = [
                    d.name for d in base.iterdir()
                    if d.is_dir() and not d.name.startswith(".")
                    and d.name not in exclude_names
                ]
            except Exception as e:
                logger.debug("Could not list %s: %s", base, e)

        # Check each user's directories for wp-config.php
        for user in cpanel_users:
            user_home = base / user
            if not user_home.is_dir():
                continue

            # Candidate directories: public_html + any subdirectories (addon domains)
            # Also check userdata for cPanel addon/subdomain document roots
            candidates: List[Path] = []

            public_html = user_home / "public_html"
            if public_html.is_dir():
                candidates.append(public_html)
                # Check immediate subdirectories (addon domains live here)
                try:
                    for sub in public_html.iterdir():
                        if sub.is_dir() and sub.name not in exclude_patterns and not sub.name.startswith("."):
                            candidates.append(sub)
                except PermissionError:
                    pass

            # Also check cPanel userdata for additional document roots
            userdata_main = Path(f"/var/cpanel/userdata/{user}/main")
            if userdata_main.exists():
                try:
                    content = userdata_main.read_text(errors="replace")
                    for line in content.split("\n"):
                        if "documentroot:" in line.lower():
                            docroot = line.split(":", 1)[-1].strip()
                            if docroot:
                                dr_path = Path(docroot)
                                if dr_path.is_dir() and dr_path not in candidates:
                                    candidates.append(dr_path)
                except Exception:
                    pass

            # Check each candidate for wp-config.php
            for cdir in candidates:
                wp_config = cdir / "wp-config.php"
                if wp_config.exists():
                    wp_root = cdir
                    if wp_root not in fast_found:
                        if (wp_root / "wp-includes").is_dir() or (wp_root / "wp-admin").is_dir():
                            wp_roots.append(wp_root)
                            fast_found.add(wp_root)
                            logger.debug("Found WordPress at %s (cPanel fast path)", wp_root)

        # ── Fast path 2: Plesk vhosts ────────────────────────────────
        plesk_base = Path("/var/www/vhosts")
        if plesk_base.is_dir():
            try:
                for vhost in plesk_base.iterdir():
                    if not vhost.is_dir() or vhost.name.startswith("."):
                        continue
                    for docroot_name in ("httpdocs", "public_html"):
                        httpdocs = vhost / docroot_name
                        if httpdocs.is_dir():
                            # Check root
                            if (httpdocs / "wp-config.php").exists():
                                if httpdocs not in fast_found:
                                    if (httpdocs / "wp-includes").is_dir() or (httpdocs / "wp-admin").is_dir():
                                        wp_roots.append(httpdocs)
                                        fast_found.add(httpdocs)
                                        logger.debug("Found WordPress at %s (Plesk)", httpdocs)
                            # Check subdirs
                            try:
                                for sub in httpdocs.iterdir():
                                    if sub.is_dir() and sub.name not in exclude_patterns:
                                        if (sub / "wp-config.php").exists():
                                            if sub not in fast_found:
                                                if (sub / "wp-includes").is_dir() or (sub / "wp-admin").is_dir():
                                                    wp_roots.append(sub)
                                                    fast_found.add(sub)
                                                    logger.debug("Found WordPress at %s (Plesk sub)", sub)
                            except PermissionError:
                                pass
            except PermissionError:
                pass

        if wp_roots:
            logger.info("Fast discovery found %d site(s), skipping deep scan", len(wp_roots))
        else:
            # Slow path: deep find for non-standard layouts
            # Use -xdev to avoid crossing filesystem boundaries (prevents
            # traversing into CageFS virtfs or NFS mounts)
            logger.info("Fast path found nothing, trying deep find (max 600s)...")
            result = subprocess.run(
                [
                    "find", str(base),
                    "-xdev",
                    "-name", "wp-config.php",
                    "-not", "-path", "*/node_modules/*",
                    "-not", "-path", "*/.git/*",
                    "-not", "-path", "*/vendor/*",
                    "-not", "-path", "*/cache/*",
                    "-not", "-path", "*/backup*/*",
                    "-not", "-path", "*/.trash/*",
                    "-not", "-path", "*/virtfs/*",
                    "-not", "-path", "*/mail/*",
                    "-maxdepth", "6",
                    "-type", "f",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                wp_config = Path(line)
                wp_root = wp_config.parent

                if wp_root in fast_found:
                    continue

                # Validate: must also contain wp-includes/ or wp-admin/
                if (wp_root / "wp-includes").is_dir() or (wp_root / "wp-admin").is_dir():
                    wp_roots.append(wp_root)
                    fast_found.add(wp_root)
                    logger.debug("Found WordPress at %s (deep find)", wp_root)
                else:
                    logger.debug("Skipping %s — no wp-includes or wp-admin", wp_root)

    except subprocess.TimeoutExpired:
        logger.error("Site discovery timed out after 600 seconds")
    except FileNotFoundError:
        # `find` not available — fall back to Python walk
        logger.info("'find' not available, falling back to os.walk")
        wp_roots = _discover_wp_sites_python(base, exclude_patterns)

    logger.info("Discovered %d WordPress installation(s)", len(wp_roots))
    return sorted(wp_roots)


def _discover_wp_sites_python(
    base: Path, exclude_dirs: set, max_depth: int = 6
) -> List[Path]:
    """Pure-Python fallback for site discovery."""
    wp_roots: List[Path] = []
    base_depth = len(base.parts)

    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        # Enforce max depth limit
        current_depth = len(Path(dirpath).parts) - base_depth
        if current_depth >= max_depth:
            dirnames.clear()
            continue

        # Prune excluded directories
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in exclude_dirs
        ]

        if "wp-config.php" in filenames:
            root = Path(dirpath)
            if (root / "wp-includes").is_dir() or (root / "wp-admin").is_dir():
                wp_roots.append(root)

    return wp_roots


def run_wp_cli(
    site_path: Path,
    command: str,
    args: Optional[List[str]] = None,
    allow_root: bool = True,
    timeout: int = 60,
    as_user: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Execute a wp-cli command for a specific WordPress site.

    Args:
        site_path: Path to the WordPress root directory.
        command: WP-CLI command (e.g. "user list", "core version").
        args: Additional arguments to pass.
        allow_root: Add --allow-root flag (needed when running as root).
        timeout: Command timeout in seconds.
        as_user: Run as this system user (via sudo -u).

    Returns:
        Tuple of (success: bool, output: str).
    """
    cmd_parts: List[str] = []

    if as_user:
        cmd_parts.extend(["sudo", "-u", as_user])

    cmd_parts.append("wp")
    try:
        cmd_parts.extend(shlex.split(command))
    except ValueError:
        # Fallback for commands with unterminated quotes (e.g. apostrophes)
        logger.debug("shlex.split() failed for %r, falling back to str.split()", command)
        cmd_parts.extend(command.split())

    if args:
        cmd_parts.extend(args)

    cmd_parts.extend(["--path=" + str(site_path)])

    if allow_root and not as_user and os.geteuid() == 0:
        cmd_parts.append("--allow-root")

    logger.debug("Running wp-cli: %s", " ".join(cmd_parts))

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(site_path),
        )

        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            stderr = result.stderr.strip()
            logger.warning(
                "wp-cli command failed (rc=%d): %s\nstderr: %s",
                result.returncode, " ".join(cmd_parts), stderr,
            )
            return False, stderr

    except subprocess.TimeoutExpired:
        logger.error("wp-cli command timed out after %ds: %s", timeout, " ".join(cmd_parts))
        return False, f"Command timed out after {timeout}s"
    except FileNotFoundError:
        logger.error("wp-cli not found — is it installed and in PATH?")
        return False, "wp-cli not found"


def get_wp_version(site_path: Path) -> str:
    """
    Get the WordPress core version for a site.

    Falls back to parsing wp-includes/version.php if wp-cli fails.

    Args:
        site_path: Path to the WordPress root directory.

    Returns:
        Version string (e.g. "6.5.2") or "unknown".
    """
    # Try wp-cli first
    success, output = run_wp_cli(site_path, "core version")
    if success and output:
        return output.strip()

    # Fallback: parse version.php
    version_file = site_path / "wp-includes" / "version.php"
    if version_file.exists():
        try:
            content = version_file.read_text(encoding="utf-8", errors="replace")
            match = re.search(
                r"\$wp_version\s*=\s*'([^']+)'",
                content,
            )
            if match:
                return match.group(1)
        except Exception as e:
            logger.debug("Failed to parse version.php: %s", e)

    return "unknown"


def get_installed_plugins(site_path: Path) -> List[PluginInfo]:
    """
    Get all installed plugins for a WordPress site.

    Args:
        site_path: Path to the WordPress root directory.

    Returns:
        List of PluginInfo objects.
    """
    success, output = run_wp_cli(
        site_path,
        "plugin list",
        args=["--format=json"],
    )

    plugins: List[PluginInfo] = []

    if success and output:
        try:
            data = json.loads(output)
            for item in data:
                plugins.append(PluginInfo(
                    slug=item.get("name", ""),
                    name=item.get("title", item.get("name", "")),
                    version=item.get("version", ""),
                    status=item.get("status", "inactive"),
                    update_available=item.get("update", None),
                ))
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse plugin list JSON: %s", e)
    else:
        # Fallback: scan the plugins directory
        plugins_dir = site_path / "wp-content" / "plugins"
        if plugins_dir.is_dir():
            for entry in plugins_dir.iterdir():
                if entry.is_dir() and not entry.name.startswith("."):
                    plugins.append(PluginInfo(
                        slug=entry.name,
                        name=entry.name,
                        version=_read_plugin_version(entry),
                        status="unknown",
                    ))

    return plugins


def get_installed_themes(site_path: Path) -> List[ThemeInfo]:
    """
    Get all installed themes for a WordPress site.

    Args:
        site_path: Path to the WordPress root directory.

    Returns:
        List of ThemeInfo objects.
    """
    success, output = run_wp_cli(
        site_path,
        "theme list",
        args=["--format=json"],
    )

    themes: List[ThemeInfo] = []

    if success and output:
        try:
            data = json.loads(output)
            for item in data:
                themes.append(ThemeInfo(
                    slug=item.get("name", ""),
                    name=item.get("title", item.get("name", "")),
                    version=item.get("version", ""),
                    status=item.get("status", "inactive"),
                    update_available=item.get("update", None),
                ))
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse theme list JSON: %s", e)
    else:
        # Fallback: scan the themes directory
        themes_dir = site_path / "wp-content" / "themes"
        if themes_dir.is_dir():
            for entry in themes_dir.iterdir():
                if entry.is_dir() and not entry.name.startswith("."):
                    themes.append(ThemeInfo(
                        slug=entry.name,
                        name=entry.name,
                        version="unknown",
                        status="unknown",
                    ))

    return themes


def build_site_info(site_path: Path) -> WordPressSite:
    """
    Build a complete WordPressSite object by parsing config and
    introspecting with wp-cli.

    Args:
        site_path: Path to the WordPress root directory.

    Returns:
        Populated WordPressSite instance.
    """
    wp_config_path = site_path / "wp-config.php"
    config = parse_wp_config(wp_config_path)

    # Determine domain via wp-cli
    domain = ""
    success, output = run_wp_cli(site_path, "option get", args=["siteurl"])
    if success and output:
        domain = output.strip()

    # Determine site owner from filesystem ownership
    # Uses os.stat() for accuracy on both cPanel and Plesk
    site_owner = ""
    hosting_panel = ""
    try:
        from .hosting import HostingDetector, HostingPanel
        site_owner = HostingDetector.get_user_from_path(str(site_path))
        hosting_panel = HostingDetector.detect().value
    except ImportError:
        # Fallback: infer from path
        parts = site_path.parts
        if len(parts) >= 3 and parts[1] == "home":
            site_owner = parts[2]
        elif len(parts) >= 5 and parts[1] == "var" and parts[2] == "www" and parts[3] == "vhosts":
            site_owner = parts[4]

    site = WordPressSite(
        path=str(site_path),
        domain=domain,
        wp_version=get_wp_version(site_path),
        db_host=config["DB_HOST"],
        db_name=config["DB_NAME"],
        db_user=config["DB_USER"],
        db_pass=config["DB_PASSWORD"],
        db_prefix=config["table_prefix"],
        plugins=get_installed_plugins(site_path),
        themes=get_installed_themes(site_path),
        site_owner=site_owner,
        hosting_panel=hosting_panel,
    )

    logger.info(
        "Built site info: %s (WP %s, db=%s, %d plugins, %d themes)",
        site.path, site.wp_version, site.db_name,
        len(site.plugins), len(site.themes),
    )
    return site


def _read_plugin_version(plugin_dir: Path) -> str:
    """
    Read the Version header from a plugin's main PHP file.

    Looks for the standard WordPress plugin header:
        Version: X.Y.Z
    """
    for php_file in plugin_dir.glob("*.php"):
        try:
            # Only read first 8KB — header is always near the top
            content = php_file.read_bytes()[:8192].decode("utf-8", errors="replace")
            match = re.search(
                r"^\s*\*?\s*Version:\s*(.+)$",
                content,
                re.MULTILINE | re.IGNORECASE,
            )
            if match:
                return match.group(1).strip()
        except Exception:
            continue
    return "unknown"
