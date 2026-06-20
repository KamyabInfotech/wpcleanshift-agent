"""
CleanShift File Watcher Daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Lightweight file watcher that monitors critical WordPress paths for changes
and triggers instant scans when suspicious modifications are detected.

Monitored paths per WordPress site:
  - mu-plugins/          (must-use plugins — auto-loaded by WordPress)
  - .htaccess            (server config — redirects, PHP settings)
  - .user.ini            (PHP config override)
  - wp-config.php        (database credentials, salts)
  - uploads/*.php        (PHP in uploads = always malicious)

Implementation:
  - Uses Linux inotify via ctypes (no external dependencies)
  - Falls back to polling if inotify is unavailable (e.g. macOS, old kernels)
  - Respects existing security stack (Imunify360, CPGuard)
  - Runs as systemd service with graceful SIGTERM shutdown
  - Auto-discovers WordPress sites under /home/*/public_html/ and /var/www/vhosts/*/httpdocs/

Python 3.6+ compatible.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import glob
import logging
import os
import signal
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("wpcleanshift.watcher")

# inotify event flags
IN_CREATE = 0x00000100
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_DELETE = 0x00000200
IN_ISDIR = 0x40000000

# Combined mask for file creation/modification
WATCH_MASK = IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO


# ─── Security Stack Detection ──────────────────────────────────────

def _is_imunify_watcher_running():
    # type: () -> bool
    """Check if Imunify360's inotify watcher is already running."""
    try:
        for pid_dir in glob.glob("/proc/[0-9]*"):
            try:
                cmdline_path = os.path.join(pid_dir, "cmdline")
                with open(cmdline_path, "r") as f:
                    cmdline = f.read()
                if "imunify" in cmdline.lower() and "inotif" in cmdline.lower():
                    return True
            except (IOError, OSError):
                continue
    except Exception:
        pass
    return False


def _detect_existing_security():
    # type: () -> Dict[str, bool]
    """Detect existing security systems on the server."""
    security = {
        "imunify360": False,
        "cpguard": False,
        "csf": False,
        "modsecurity": False,
        "fail2ban": False,
        "plesk": False,
    }

    checks = [
        ("imunify360", ["/usr/bin/imunify360-agent", "/etc/sysconfig/imunify360"]),
        ("cpguard", ["/usr/local/cpguard", "/etc/cpguard"]),
        ("csf", ["/etc/csf/csf.conf", "/usr/sbin/csf"]),
        ("modsecurity", ["/etc/modsecurity", "/usr/lib/apache2/modules/mod_security2.so"]),
        ("fail2ban", ["/etc/fail2ban/fail2ban.conf", "/usr/bin/fail2ban-client"]),
        ("plesk", ["/usr/local/psa/version", "/opt/psa/version", "/etc/psa/.psa.shadow"]),
    ]

    for name, paths in checks:
        for path in paths:
            if os.path.exists(path):
                security[name] = True
                break

    return security


# ─── inotify Wrapper (ctypes) ──────────────────────────────────────

class InotifyWatcher(object):
    """Linux inotify wrapper using ctypes — no external dependencies."""

    def __init__(self):
        # type: () -> None
        self._fd = -1
        self._wd_map = {}  # type: Dict[int, str]
        self._libc = None  # type: Optional[ctypes.CDLL]
        self._available = False
        self._init_inotify()

    def _init_inotify(self):
        # type: () -> None
        """Initialize inotify file descriptor."""
        try:
            libc_name = ctypes.util.find_library("c")
            if not libc_name:
                logger.debug("libc not found — inotify unavailable")
                return
            self._libc = ctypes.CDLL(libc_name, use_errno=True)
            self._fd = self._libc.inotify_init()
            if self._fd < 0:
                err = ctypes.get_errno()
                logger.debug("inotify_init failed: errno=%d", err)
                self._fd = -1
                return
            self._available = True
            logger.info("inotify initialized (fd=%d)", self._fd)
        except (OSError, AttributeError) as e:
            logger.debug("inotify not available: %s", e)

    @property
    def available(self):
        # type: () -> bool
        return self._available

    def add_watch(self, path):
        # type: (str) -> int
        """Add a watch on a path. Returns watch descriptor or -1."""
        if not self._available or self._libc is None:
            return -1
        path_bytes = path.encode("utf-8")
        wd = self._libc.inotify_add_watch(self._fd, path_bytes, WATCH_MASK)
        if wd >= 0:
            self._wd_map[wd] = path
            logger.debug("Watching: %s (wd=%d)", path, wd)
        else:
            err = ctypes.get_errno()
            logger.warning("Failed to watch %s: errno=%d", path, err)
        return wd

    def read_events(self, timeout_ms=1000):
        # type: (int) -> List[Tuple[str, str, int]]
        """Read inotify events. Returns list of (directory, filename, mask)."""
        if not self._available:
            return []

        import select
        events = []  # type: List[Tuple[str, str, int]]
        readable, _, _ = select.select([self._fd], [], [], timeout_ms / 1000.0)
        if not readable:
            return events

        try:
            buf = os.read(self._fd, 4096)
        except OSError:
            return events

        offset = 0
        while offset < len(buf):
            # inotify_event struct: wd (int), mask (uint32), cookie (uint32), len (uint32)
            if offset + 16 > len(buf):
                break
            wd, mask, cookie, name_len = struct.unpack_from("iIII", buf, offset)
            offset += 16
            if offset + name_len > len(buf):
                break
            name_raw = buf[offset:offset + name_len]
            offset += name_len
            # Strip null bytes from name
            name = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
            directory = self._wd_map.get(wd, "unknown")
            if name:
                events.append((directory, name, mask))

        return events

    def close(self):
        # type: () -> None
        """Close the inotify file descriptor."""
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
            self._available = False


# ─── Polling Fallback ──────────────────────────────────────────────

class PollingWatcher(object):
    """Polling-based file watcher fallback when inotify is unavailable."""

    def __init__(self, poll_interval=5.0):
        # type: (float) -> None
        self.poll_interval = poll_interval
        self._watch_paths = []  # type: List[str]
        self._last_mtimes = {}  # type: Dict[str, float]

    @property
    def available(self):
        # type: () -> bool
        return True  # Polling always works

    def add_watch(self, path):
        # type: (str) -> int
        """Register a path for polling."""
        self._watch_paths.append(path)
        # Snapshot current mtimes
        self._snapshot_path(path)
        return len(self._watch_paths) - 1

    def _snapshot_path(self, path):
        # type: (str) -> None
        """Record modification times for all files under path."""
        p = Path(path)
        if p.is_file():
            try:
                self._last_mtimes[path] = p.stat().st_mtime
            except OSError:
                pass
        elif p.is_dir():
            try:
                for child in p.iterdir():
                    child_path = str(child)
                    try:
                        self._last_mtimes[child_path] = child.stat().st_mtime
                    except OSError:
                        pass
            except OSError:
                pass

    def read_events(self, timeout_ms=1000):
        # type: (int) -> List[Tuple[str, str, int]]
        """Poll for file changes. Returns list of (directory, filename, mask)."""
        time.sleep(min(timeout_ms / 1000.0, self.poll_interval))
        events = []  # type: List[Tuple[str, str, int]]

        for watch_path in self._watch_paths:
            p = Path(watch_path)
            if p.is_file():
                try:
                    mtime = p.stat().st_mtime
                    old_mtime = self._last_mtimes.get(watch_path, 0)
                    if mtime != old_mtime:
                        events.append((str(p.parent), p.name, IN_MODIFY))
                        self._last_mtimes[watch_path] = mtime
                except OSError:
                    pass
            elif p.is_dir():
                try:
                    for child in p.iterdir():
                        child_path = str(child)
                        try:
                            mtime = child.stat().st_mtime
                        except OSError:
                            continue
                        old_mtime = self._last_mtimes.get(child_path, 0)
                        if old_mtime == 0:
                            # New file
                            events.append((watch_path, child.name, IN_CREATE))
                            self._last_mtimes[child_path] = mtime
                        elif mtime != old_mtime:
                            events.append((watch_path, child.name, IN_MODIFY))
                            self._last_mtimes[child_path] = mtime
                except OSError:
                    pass

        return events

    def close(self):
        # type: () -> None
        """Nothing to close for polling watcher."""
        pass


# ─── WP Site Discovery ─────────────────────────────────────────────

def discover_wp_sites(base_path="/home"):
    # type: (str) -> List[str]
    """Auto-discover WordPress sites under cPanel and Plesk paths.

    Searches:
      - {base_path}/*/public_html/wp-config.php  (cPanel)
      - /var/www/vhosts/*/httpdocs/wp-config.php  (Plesk)
    """
    sites = []  # type: List[str]
    seen = set()  # type: Set[str]

    # cPanel: /home/*/public_html/
    patterns = [
        os.path.join(base_path, "*", "public_html", "wp-config.php"),
        os.path.join(base_path, "*", "public_html", "*", "wp-config.php"),
    ]

    # Plesk: /var/www/vhosts/*/httpdocs/
    if os.path.isdir("/var/www/vhosts"):
        patterns.append("/var/www/vhosts/*/httpdocs/wp-config.php")
        patterns.append("/var/www/vhosts/*/httpdocs/*/wp-config.php")

    for pattern in patterns:
        for wp_config in glob.glob(pattern):
            site_root = os.path.dirname(wp_config)
            if site_root not in seen:
                sites.append(site_root)
                seen.add(site_root)

    return sites


# ─── Quick File Scanner ────────────────────────────────────────────

def quick_scan_file(filepath):
    # type: (str) -> Optional[str]
    """
    Perform a quick threat assessment on a single file.
    Returns threat description or None if clean.
    """
    p = Path(filepath)
    if not p.exists():
        return None

    name = p.name.lower()
    threat = None  # type: Optional[str]

    # PHP in uploads directory is always suspicious
    path_str = str(p)
    if "uploads" in path_str and name.endswith(".php"):
        threat = "PHP file in uploads directory: %s" % filepath

    # PHP in mu-plugins that looks suspicious
    elif "mu-plugins" in path_str and name.endswith(".php"):
        try:
            content = p.read_bytes()[:4096]
            suspicious_patterns = [
                b"base64_decode", b"eval(", b"gzinflate(",
                b"str_rot13(", b"shell_exec(", b"system(",
            ]
            matches = sum(1 for pat in suspicious_patterns if pat in content)
            if matches >= 2:
                threat = "Suspicious mu-plugin: %s (%d malware patterns)" % (name, matches)
        except (OSError, IOError):
            pass

    # .htaccess modifications
    elif name == ".htaccess":
        try:
            content = p.read_text(errors="replace")
            htaccess_threats = [
                "auto_prepend_file", "SetHandler application/x-httpd-php",
                "AddType application/x-httpd-php", "php_flag engine",
            ]
            for pattern in htaccess_threats:
                if pattern.lower() in content.lower():
                    threat = ".htaccess contains suspicious directive: %s in %s" % (pattern, filepath)
                    break
        except (OSError, IOError):
            pass

    # wp-config.php modification
    elif name == "wp-config.php":
        threat = "wp-config.php was modified: %s" % filepath

    # .user.ini modification
    elif name == ".user.ini":
        try:
            content = p.read_text(errors="replace")
            if "auto_prepend_file" in content.lower():
                threat = ".user.ini contains auto_prepend_file: %s" % filepath
        except (OSError, IOError):
            pass

    return threat


# ─── Telegram Alert (minimal) ──────────────────────────────────────

def send_telegram_alert(message, bot_token="", chat_id=""):
    # type: (str, str, str) -> bool
    """Send a Telegram alert. Returns True on success."""
    if not bot_token or not chat_id:
        logger.debug("Telegram not configured — skipping alert")
        return False

    try:
        import json
        from urllib.request import Request, urlopen

        url = "https://api.telegram.org/bot%s/sendMessage" % bot_token
        data = json.dumps({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        }).encode("utf-8")
        req = Request(url, data=data, headers={"Content-Type": "application/json"})
        resp = urlopen(req, timeout=10)
        resp.read()
        return True
    except Exception as e:
        logger.error("Failed to send Telegram alert: %s", e)
        return False


# ─── Main Watcher Daemon ──────────────────────────────────────────

class WatcherDaemon(object):
    """
    File watcher daemon that monitors critical WordPress paths.

    Uses inotify when available, falls back to polling.
    Respects existing security stack (reduces polling if Imunify360 present).
    """

    # Critical paths to watch (relative to WP site root)
    WATCH_PATHS = [
        "wp-content/mu-plugins",
        ".htaccess",
        ".user.ini",
        "wp-config.php",
        "wp-content/uploads",
    ]

    def __init__(
        self,
        base_path="/home",
        bot_token="",
        chat_id="",
        poll_interval=5.0,
    ):
        # type: (str, str, str, float) -> None
        self.base_path = base_path
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.poll_interval = poll_interval
        self._running = False
        self._watcher = None  # type: Optional[object]
        self._sites = []  # type: List[str]

    def _setup_signal_handlers(self):
        # type: () -> None
        """Install SIGTERM/SIGINT handlers for graceful shutdown."""
        def _handle_signal(signum, frame):
            logger.info("Received signal %d — shutting down gracefully", signum)
            self._running = False

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

    def _setup_watcher(self):
        # type: () -> None
        """Initialize the appropriate file watcher."""
        # Check for existing security stack
        security = _detect_existing_security()
        for name, active in security.items():
            if active:
                logger.info("Detected existing security system: %s", name)

        # If Imunify360's inotify watcher is running, reduce our frequency
        imunify_watching = _is_imunify_watcher_running()
        if imunify_watching:
            logger.info(
                "Imunify360 inotify watcher detected — reducing poll frequency"
            )
            self.poll_interval = max(self.poll_interval * 3, 15.0)

        # Try inotify first, fall back to polling
        inotify = InotifyWatcher()
        if inotify.available:
            logger.info("Using inotify for file watching")
            self._watcher = inotify
            # P2: Check inotify watch limits
            self._check_inotify_limits()
        else:
            logger.info("inotify unavailable — using polling (interval=%.1fs)", self.poll_interval)
            self._watcher = PollingWatcher(poll_interval=self.poll_interval)

    def _check_inotify_limits(self):
        # type: () -> None
        """Check if the kernel inotify watch limit is sufficient."""
        try:
            with open("/proc/sys/fs/inotify/max_user_watches", "r") as f:
                max_watches = int(f.read().strip())
            # Estimate our needs: ~6 paths per site
            estimated = len(getattr(self, '_sites', [])) * len(self.WATCH_PATHS)
            if not estimated:
                estimated = 1200  # Assume ~200 sites as default
            if max_watches < estimated * 2:
                logger.warning(
                    "inotify max_user_watches=%d may be too low (we need ~%d). "
                    "Run: sysctl -w fs.inotify.max_user_watches=65536",
                    max_watches, estimated,
                )
            else:
                logger.debug("inotify limit OK: %d (need ~%d)", max_watches, estimated)
        except (OSError, ValueError):
            # Not on Linux or can't read — skip check
            pass

    def _discover_and_watch(self):
        # type: () -> None
        """Discover WordPress sites and set up watches.

        Tracks watched paths and removes stale watches for paths
        that no longer exist (H4 — prevents inotify FD leaks).
        """
        self._sites = discover_wp_sites(self.base_path)
        logger.info("Discovered %d WordPress site(s)", len(self._sites))

        # Build the set of paths that should be watched now
        desired_paths = set()  # type: set
        for site_root in self._sites:
            for rel_path in self.WATCH_PATHS:
                full_path = os.path.join(site_root, rel_path)
                if os.path.exists(full_path):
                    desired_paths.add(full_path)
                elif os.path.isdir(os.path.dirname(full_path)):
                    parent = os.path.dirname(full_path)
                    if os.path.exists(parent):
                        desired_paths.add(parent)

        # Remove stale watches (paths we previously watched but no longer need)
        if not hasattr(self, '_watched_paths'):
            self._watched_paths = set()  # type: set

        stale_paths = self._watched_paths - desired_paths
        for stale in stale_paths:
            try:
                self._watcher.remove_watch(stale)
                logger.debug("Removed stale watch: %s", stale)
            except Exception as exc:
                logger.debug("Could not remove stale watch %s: %s", stale, exc)

        # Add watches for new paths
        new_paths = desired_paths - self._watched_paths
        for path in new_paths:
            self._watcher.add_watch(path)

        self._watched_paths = desired_paths
        logger.info("Watches: %d active, %d added, %d removed across %d sites",
                    len(desired_paths), len(new_paths), len(stale_paths), len(self._sites))

    def _handle_event(self, directory, filename, mask):
        # type: (str, str, int) -> None
        """Handle a file system event."""
        filepath = os.path.join(directory, filename)
        event_type = "MODIFY" if (mask & IN_MODIFY) else "CREATE"
        logger.info("File %s: %s", event_type, filepath)

        # Only scan PHP files, .htaccess, .user.ini, wp-config.php
        name_lower = filename.lower()
        should_scan = (
            name_lower.endswith(".php") or
            name_lower == ".htaccess" or
            name_lower == ".user.ini" or
            name_lower == "wp-config.php"
        )

        if not should_scan:
            return

        # Quick scan the file
        threat = quick_scan_file(filepath)
        if threat:
            logger.warning("THREAT DETECTED: %s", threat)
            alert_msg = (
                "<b>\xf0\x9f\x9a\xa8 CleanShift Watcher Alert</b>\n\n"
                "<b>Event:</b> %s\n"
                "<b>File:</b> <code>%s</code>\n"
                "<b>Threat:</b> %s\n"
                "<b>Time:</b> %s"
            ) % (event_type, filepath, threat, time.strftime("%Y-%m-%d %H:%M:%S"))
            send_telegram_alert(alert_msg, self.bot_token, self.chat_id)

    def run(self):
        # type: () -> None
        """Main daemon loop."""
        logger.info("CleanShift Watcher starting (base_path=%s)", self.base_path)

        self._setup_signal_handlers()
        self._setup_watcher()
        self._discover_and_watch()

        self._running = True
        logger.info("Watcher daemon running — monitoring for changes")

        # Re-discover sites periodically (every 30 minutes)
        last_rediscover = time.monotonic()
        rediscover_interval = 1800  # 30 minutes

        while self._running:
            try:
                events = self._watcher.read_events(timeout_ms=1000)
                for directory, filename, mask in events:
                    try:
                        self._handle_event(directory, filename, mask)
                    except Exception as e:
                        logger.error(
                            "Error handling event for %s/%s: %s",
                            directory, filename, e,
                        )

                # Periodic re-discovery
                elapsed = time.monotonic() - last_rediscover
                if elapsed > rediscover_interval:
                    logger.info("Re-discovering WordPress sites...")
                    self._discover_and_watch()
                    last_rediscover = time.monotonic()

            except Exception as e:
                logger.error("Watcher loop error: %s", e)
                time.sleep(1)  # Prevent tight error loops

        # Cleanup
        logger.info("Watcher daemon shutting down")
        if self._watcher is not None:
            self._watcher.close()


# ─── CLI Entry Point ──────────────────────────────────────────────

def main():
    # type: () -> None
    """CLI entry point for the watcher daemon."""
    import argparse

    parser = argparse.ArgumentParser(
        description="CleanShift File Watcher Daemon"
    )
    parser.add_argument(
        "--base-path", default="/home",
        help="Base path to scan for WordPress sites (default: /home)",
    )
    parser.add_argument(
        "--poll-interval", type=float, default=5.0,
        help="Polling interval in seconds if inotify unavailable (default: 5.0)",
    )
    parser.add_argument(
        "--bot-token-env", default="TELEGRAM_BOT_TOKEN",
        help="Environment variable name containing the Telegram bot token (default: TELEGRAM_BOT_TOKEN)",
    )
    parser.add_argument(
        "--chat-id", default=os.environ.get("TELEGRAM_CHAT_ID", ""),
        help="Telegram chat ID for alerts",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    bot_token = os.environ.get(args.bot_token_env, "")
    daemon = WatcherDaemon(
        base_path=args.base_path,
        bot_token=bot_token,
        chat_id=args.chat_id,
        poll_interval=args.poll_interval,
    )
    daemon.run()


if __name__ == "__main__":
    main()
