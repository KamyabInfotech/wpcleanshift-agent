"""
CleanShift File Integrity Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Verifies WordPress core and plugin files against official checksums
from the wordpress.org API, and provides an SQLite-based file hash
cache for incremental scanning.

Components:
    VerifyResult       — Enumeration of verification outcomes
    ChecksumVerifier   — Validates files against official wordpress.org checksums
    HashCache          — SQLite-backed file state cache for incremental scanning

Production hardening:
    - All HTTP calls use 5-second timeout
    - API responses cached to disk (JSON, 24h TTL)
    - Thread-safe file cache access via threading.Lock
    - SQLite in WAL mode for concurrent reads
    - Graceful failure on all operations (never blocks scanning)
    - Corrupt DB detection and auto-recovery
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    # Should never happen on Python 3.6+, but guard anyway
    urlopen = None  # type: ignore
    Request = None  # type: ignore
    HTTPError = Exception  # type: ignore
    URLError = Exception  # type: ignore

from .models import (
    Severity,
    Threat,
    ThreatType,
    WordPressSite,
)

logger = logging.getLogger("wpcleanshift.verifier")


# ─── Verify Result Enum ────────────────────────────────────────────

class VerifyResult(str, Enum):
    """
    Outcome of verifying a file against official wordpress.org checksums.

    Values:
        OFFICIAL — File matches the official checksum.  Safe to skip
                   pattern matching.
        MODIFIED — File exists in official checksums but the hash differs.
                   Indicates possible tampering.
        CUSTOM   — File is not listed in official checksums (theme file,
                   custom plugin, etc.).  Pattern matching should run.
        UNKNOWN  — Verification could not be performed (API error, no
                   cache, etc.).  Pattern matching should run.
    """
    OFFICIAL = "official"
    MODIFIED = "modified"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


# ─── Checksum Verifier ─────────────────────────────────────────────

class ChecksumVerifier:
    """
    Validates file integrity against official WordPress.org checksums.

    For core files:
      GET https://api.wordpress.org/core/checksums/1.0/?version={ver}&locale=en_US
      Returns {"checksums": {"wp-includes/load.php": "md5hash", ...}}

    For plugins (if available):
      GET https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
      Returns {"files": {"path": {"md5": "hash", "sha256": "hash"}, ...}}

    Usage::

        verifier = ChecksumVerifier(cache_dir='/opt/cleanshift/cache')
        result = verifier.verify_file(site, 'wp-includes/load.php')
        # Returns: VerifyResult.OFFICIAL | .MODIFIED | .CUSTOM | .UNKNOWN
    """

    _CORE_API_URL = "https://api.wordpress.org/core/checksums/1.0/"
    _PLUGIN_API_URL = "https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json"
    _HTTP_TIMEOUT = 5  # seconds
    _VERSION_RE = re.compile(
        rb"\$wp_version\s*=\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]"
    )

    def __init__(self, cache_dir=None, cache_ttl=86400):
        # type: (Optional[str], int) -> None
        """
        Initialise the checksum verifier.

        Args:
            cache_dir: Directory to cache API responses as JSON files.
                       If None, a temporary directory under /tmp is used.
            cache_ttl: Cache time-to-live in seconds (default 24 hours).
        """
        if cache_dir is None:
            cache_dir = os.path.join("/tmp", "cleanshift_checksum_cache")
        self._cache_dir = cache_dir
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        # In-memory cache for the current process lifetime
        self._mem_cache = {}  # type: Dict[str, Dict[str, str]]

        try:
            os.makedirs(self._cache_dir, exist_ok=True)
        except OSError as exc:
            logger.warning("Cannot create cache dir %s: %s", self._cache_dir, exc)

    # ── Public API ──────────────────────────────────────────────────

    def fetch_core_checksums(self, wp_version):
        # type: (str) -> Dict[str, str]
        """
        Fetch core file checksums from the WordPress.org API.

        Args:
            wp_version: WordPress version string, e.g. '6.5.2'.

        Returns:
            Dict mapping relative file paths to MD5 hex digests.
            Empty dict on failure.
        """
        cache_key = "core_%s" % wp_version
        cached = self._load_cache(cache_key)
        if cached is not None:
            logger.debug("Core checksums cache hit: %s", cache_key)
            return cached

        logger.debug("Core checksums cache miss: %s — fetching from API", cache_key)
        url = "%s?version=%s&locale=en_US" % (self._CORE_API_URL, wp_version)

        try:
            data = self._http_get_json(url)
        except Exception as exc:
            logger.error("Failed to fetch core checksums for v%s: %s", wp_version, exc)
            return {}

        if not isinstance(data, dict):
            logger.error("Unexpected API response type: %s", type(data).__name__)
            return {}

        checksums = data.get("checksums", {})
        if not isinstance(checksums, dict):
            logger.error("Invalid checksums field in API response")
            return {}

        self._save_cache(cache_key, checksums)
        return checksums

    def fetch_plugin_checksums(self, slug, version):
        # type: (str, str) -> Dict[str, Dict[str, str]]
        """
        Fetch plugin file checksums from the WordPress.org API.

        Args:
            slug:    Plugin slug, e.g. 'akismet'.
            version: Plugin version string, e.g. '5.3.1'.

        Returns:
            Dict mapping relative file paths to dicts of
            ``{"md5": "...", "sha256": "..."}``.  Empty dict on failure.
        """
        cache_key = "plugin_%s_%s" % (slug, version)
        cached = self._load_cache(cache_key)
        if cached is not None:
            logger.debug("Plugin checksums cache hit: %s", cache_key)
            return cached

        logger.debug("Plugin checksums cache miss: %s — fetching", cache_key)
        url = self._PLUGIN_API_URL.format(slug=slug, version=version)

        try:
            data = self._http_get_json(url)
        except Exception as exc:
            logger.warning("Failed to fetch plugin checksums for %s v%s: %s", slug, version, exc)
            return {}

        if not isinstance(data, dict):
            return {}

        files = data.get("files", {})
        if not isinstance(files, dict):
            return {}

        self._save_cache(cache_key, files)
        return files

    def verify_file(self, site, rel_path):
        # type: (WordPressSite, str) -> VerifyResult
        """
        Verify a single file against official checksums.

        Args:
            site:     WordPressSite instance (needs path and wp_version).
            rel_path: Path relative to the WP root, e.g. 'wp-includes/load.php'.

        Returns:
            VerifyResult indicating file integrity status.
        """
        wp_version = site.wp_version
        if not wp_version:
            wp_version = self._detect_wp_version(site.path)

        if not wp_version:
            logger.debug("Cannot determine WP version for %s", site.path)
            return VerifyResult.UNKNOWN

        # Normalise path separators
        norm_path = rel_path.replace("\\", "/")

        # Try core checksums first
        core_checksums = self.fetch_core_checksums(wp_version)
        if not core_checksums:
            return VerifyResult.UNKNOWN

        if norm_path in core_checksums:
            expected_md5 = core_checksums[norm_path]
            abs_path = os.path.join(site.path, rel_path)
            actual_md5 = self._compute_md5(abs_path)
            if not actual_md5:
                return VerifyResult.UNKNOWN
            if actual_md5 == expected_md5:
                return VerifyResult.OFFICIAL
            else:
                logger.info(
                    "Core file MODIFIED: %s (expected=%s, actual=%s)",
                    rel_path, expected_md5, actual_md5,
                )
                return VerifyResult.MODIFIED

        # File not in core checksums — it's a custom file
        return VerifyResult.CUSTOM

    def verify_core(self, site):
        # type: (WordPressSite) -> List[Threat]
        """
        Verify all core files for a WordPress site.

        Walks the core directories (wp-admin/, wp-includes/, root *.php)
        and checks each file against official checksums.

        Args:
            site: WordPressSite to verify.

        Returns:
            List of Threat objects for modified core files.
        """
        threats = []  # type: List[Threat]
        wp_version = site.wp_version
        if not wp_version:
            wp_version = self._detect_wp_version(site.path)

        if not wp_version:
            logger.warning("Cannot verify core — WP version unknown for %s", site.path)
            return threats

        core_checksums = self.fetch_core_checksums(wp_version)
        if not core_checksums:
            logger.warning("Cannot verify core — no checksums for WP %s", wp_version)
            return threats

        site_path = Path(site.path)
        checked = 0
        modified = 0

        for rel_path, expected_md5 in core_checksums.items():
            abs_path = site_path / rel_path
            if not abs_path.is_file():
                continue

            checked += 1
            actual_md5 = self._compute_md5(str(abs_path))
            if not actual_md5:
                continue

            if actual_md5 != expected_md5:
                modified += 1
                threats.append(Threat(
                    threat_type=ThreatType.CORE_MODIFIED,
                    severity=Severity.HIGH,
                    title="Modified core file: %s" % rel_path,
                    description=(
                        "Core file does not match the official WordPress %s "
                        "checksum.  This may indicate tampering or a partial "
                        "update." % wp_version
                    ),
                    location=str(abs_path),
                    evidence="expected_md5=%s actual_md5=%s" % (expected_md5, actual_md5),
                    site_path=site.path,
                    details={
                        "rel_path": rel_path,
                        "wp_version": wp_version,
                        "expected_md5": expected_md5,
                        "actual_md5": actual_md5,
                    },
                ))

        logger.info(
            "Core verification: %s — checked=%d modified=%d",
            site.path, checked, modified,
        )
        return threats

    def _detect_wp_version(self, site_path):
        # type: (str) -> Optional[str]
        """
        Detect the WordPress version from wp-includes/version.php.

        Args:
            site_path: Absolute path to the WordPress root.

        Returns:
            Version string like '6.5.2' or None if detection fails.
        """
        version_file = os.path.join(site_path, "wp-includes", "version.php")
        try:
            with open(version_file, "rb") as fh:
                content = fh.read(4096)
            match = self._VERSION_RE.search(content)
            if match:
                version = match.group(1).decode("utf-8", errors="replace")
                logger.debug("Detected WP version %s from %s", version, version_file)
                return version
        except (OSError, IOError) as exc:
            logger.debug("Cannot read version.php: %s", exc)
        return None

    # ── Internal helpers ────────────────────────────────────────────

    def _compute_md5(self, filepath):
        # type: (str) -> str
        """
        Compute the MD5 hex digest of a file.

        Reads in 64 KB chunks to avoid loading large files into memory.

        Args:
            filepath: Absolute path to the file.

        Returns:
            MD5 hex digest string, or empty string on error.
        """
        try:
            h = hashlib.md5()
            with open(filepath, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, IOError, PermissionError) as exc:
            logger.debug("Cannot compute MD5 for %s: %s", filepath, exc)
            return ""

    def _http_get_json(self, url):
        # type: (str) -> Any
        """
        Perform an HTTP GET and parse the JSON response.

        Args:
            url: URL to fetch.

        Returns:
            Parsed JSON object.

        Raises:
            Exception on HTTP or JSON parse error.
        """
        if urlopen is None:
            raise RuntimeError("urllib.request not available")

        req = Request(url)
        req.add_header("User-Agent", "CleanShift/1.0")
        response = urlopen(req, timeout=self._HTTP_TIMEOUT)
        raw = response.read()
        return json.loads(raw.decode("utf-8", errors="replace"))

    def _load_cache(self, cache_key):
        # type: (str) -> Optional[Dict[str, Any]]
        """
        Load a cached API response from disk.

        Args:
            cache_key: Unique identifier for the cached data.

        Returns:
            Cached dict, or None if not cached / expired / corrupt.
        """
        # Check in-memory cache first
        with self._lock:
            if cache_key in self._mem_cache:
                return self._mem_cache[cache_key]

        cache_file = os.path.join(self._cache_dir, "%s.json" % cache_key)
        try:
            file_stat = os.stat(cache_file)
            age = time.time() - file_stat.st_mtime
            if age > self._cache_ttl:
                logger.debug("Cache expired for %s (age=%.0fs)", cache_key, age)
                return None

            with open(cache_file, "r") as fh:
                data = json.load(fh)

            # Populate in-memory cache
            with self._lock:
                self._mem_cache[cache_key] = data

            return data
        except (OSError, IOError):
            return None
        except (ValueError, json.JSONDecodeError):
            logger.warning("Corrupt cache file %s — removing", cache_file)
            try:
                os.remove(cache_file)
            except OSError:
                pass
            return None

    def _save_cache(self, cache_key, data):
        # type: (str, Any) -> None
        """
        Save an API response to the disk cache.

        Args:
            cache_key: Unique identifier for the cached data.
            data:      JSON-serialisable data to cache.
        """
        with self._lock:
            self._mem_cache[cache_key] = data

        cache_file = os.path.join(self._cache_dir, "%s.json" % cache_key)
        try:
            tmp_file = cache_file + ".tmp"
            with open(tmp_file, "w") as fh:
                json.dump(data, fh)
            os.replace(tmp_file, cache_file)
            logger.debug("Saved cache: %s", cache_key)
        except (OSError, IOError) as exc:
            logger.warning("Failed to write cache %s: %s", cache_key, exc)
            try:
                os.remove(tmp_file)
            except OSError:
                pass


# ─── Hash Cache ─────────────────────────────────────────────────────

class HashCache:
    """
    Tracks file states across scans for incremental scanning and
    baseline detection.

    On first scan: records mtime, size, SHA256 for every file.
    On subsequent scans: only re-scans files where mtime or size changed.
    Also detects NEW files that weren't in the previous baseline.

    Storage: SQLite database at ``{cache_dir}/file_cache.db``

    Table schema::

        file_cache(
            site_path TEXT,
            rel_path  TEXT,
            mtime     REAL,
            size      INTEGER,
            sha256    TEXT,
            scan_time REAL,
            status    TEXT,      -- 'clean', 'threat', 'skipped'
            PRIMARY KEY (site_path, rel_path)
        )
    """

    _CREATE_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS file_cache (
            site_path TEXT    NOT NULL,
            rel_path  TEXT    NOT NULL,
            mtime     REAL    NOT NULL,
            size      INTEGER NOT NULL,
            sha256    TEXT    NOT NULL DEFAULT '',
            scan_time REAL    NOT NULL,
            status    TEXT    NOT NULL DEFAULT 'clean',
            PRIMARY KEY (site_path, rel_path)
        )
    """
    _CREATE_INDEX_SQL = """
        CREATE INDEX IF NOT EXISTS idx_file_cache_site
        ON file_cache (site_path, rel_path)
    """

    def __init__(self, cache_dir):
        # type: (str) -> None
        """
        Initialise the hash cache.

        Args:
            cache_dir: Directory where the SQLite database will be stored.

        Raises:
            No exceptions — a corrupt DB is deleted and recreated.
        """
        self._cache_dir = cache_dir
        self._db_path = os.path.join(cache_dir, "file_cache.db")
        self._lock = threading.Lock()
        self._conn = None  # type: Optional[sqlite3.Connection]

        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError as exc:
            logger.warning("Cannot create cache dir %s: %s", cache_dir, exc)

        self._init_db()

    def _init_db(self):
        # type: () -> None
        """
        Create the SQLite database and table if they don't exist.

        Uses WAL journal mode for concurrent reads.  If the existing
        database is corrupt, deletes it and recreates from scratch.
        """
        try:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=10.0,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(self._CREATE_TABLE_SQL)
            self._conn.execute(self._CREATE_INDEX_SQL)
            self._conn.commit()
            logger.debug("HashCache database ready: %s", self._db_path)
        except sqlite3.DatabaseError as exc:
            logger.error("Corrupt database %s: %s — recreating", self._db_path, exc)
            self._recover_db()

    def _recover_db(self):
        # type: () -> None
        """Delete a corrupt database and create a fresh one."""
        try:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

            if os.path.exists(self._db_path):
                os.remove(self._db_path)
            # Also remove WAL and SHM files
            for suffix in ("-wal", "-shm"):
                wal_path = self._db_path + suffix
                if os.path.exists(wal_path):
                    try:
                        os.remove(wal_path)
                    except OSError:
                        pass

            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=10.0,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(self._CREATE_TABLE_SQL)
            self._conn.execute(self._CREATE_INDEX_SQL)
            self._conn.commit()
            logger.info("HashCache database recreated: %s", self._db_path)
        except Exception as exc:
            logger.error("Failed to recover database: %s", exc)

    # ── Public API ──────────────────────────────────────────────────

    def needs_rescan(self, site_path, rel_path, current_mtime, current_size):
        # type: (str, str, float, int) -> bool
        """
        Determine whether a file needs to be re-scanned.

        A file needs re-scanning when:
          - It is not in the cache (new file)
          - Its mtime has changed
          - Its size has changed

        Args:
            site_path:    Absolute path to the WordPress root.
            rel_path:     Path relative to site root.
            current_mtime: Current file modification time.
            current_size:  Current file size in bytes.

        Returns:
            True if the file should be re-scanned.
        """
        if self._conn is None:
            return True

        try:
            with self._lock:
                cursor = self._conn.execute(
                    "SELECT mtime, size FROM file_cache "
                    "WHERE site_path = ? AND rel_path = ?",
                    (site_path, rel_path),
                )
                row = cursor.fetchone()
        except sqlite3.Error as exc:
            logger.debug("DB read error in needs_rescan: %s", exc)
            return True

        if row is None:
            return True

        cached_mtime, cached_size = row
        if cached_mtime != current_mtime or cached_size != current_size:
            return True

        return False

    def update(self, site_path, rel_path, mtime, size, sha256, status="clean"):
        # type: (str, str, float, int, str, str) -> None
        """
        Insert or update a file entry in the cache.

        Args:
            site_path: Absolute path to the WordPress root.
            rel_path:  Path relative to site root.
            mtime:     File modification time.
            size:      File size in bytes.
            sha256:    SHA256 hex digest of the file.
            status:    Scan result — 'clean', 'threat', or 'skipped'.
        """
        if self._conn is None:
            return

        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO file_cache "
                    "(site_path, rel_path, mtime, size, sha256, scan_time, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (site_path, rel_path, mtime, size, sha256, time.time(), status),
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            logger.error("DB write error in update: %s", exc)

    def bulk_update(self, entries):
        # type: (List[Tuple[str, str, float, int, str, str]]) -> None
        """
        Batch-insert or update multiple file entries in a single transaction.

        Each entry is a tuple of:
            (site_path, rel_path, mtime, size, sha256, status)

        Args:
            entries: List of entry tuples.
        """
        if self._conn is None or not entries:
            return

        now = time.time()
        try:
            with self._lock:
                self._conn.execute("BEGIN")
                for site_path, rel_path, mtime, size, sha256, status in entries:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO file_cache "
                        "(site_path, rel_path, mtime, size, sha256, scan_time, status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (site_path, rel_path, mtime, size, sha256, now, status),
                    )
                self._conn.commit()
        except sqlite3.Error as exc:
            logger.error("DB write error in bulk_update: %s", exc)
            try:
                self._conn.rollback()
            except Exception:
                pass

    def get_new_files(self, site_path, current_files):
        # type: (str, Set[str]) -> Set[str]
        """
        Identify files present on disk but not in the cache.

        Args:
            site_path:     Absolute path to the WordPress root.
            current_files: Set of relative paths currently on disk.

        Returns:
            Set of relative paths that are new since the last scan.
        """
        cached_files = self._get_cached_paths(site_path)
        return current_files - cached_files

    def get_deleted_files(self, site_path, current_files):
        # type: (str, Set[str]) -> Set[str]
        """
        Identify files in the cache that are no longer on disk.

        Args:
            site_path:     Absolute path to the WordPress root.
            current_files: Set of relative paths currently on disk.

        Returns:
            Set of relative paths that were deleted since the last scan.
        """
        cached_files = self._get_cached_paths(site_path)
        return cached_files - current_files

    def get_stats(self, site_path):
        # type: (str) -> Dict[str, int]
        """
        Get summary statistics for a site's cached file entries.

        Args:
            site_path: Absolute path to the WordPress root.

        Returns:
            Dict with keys: total, clean, threat, skipped.
        """
        stats = {"total": 0, "clean": 0, "threat": 0, "skipped": 0}

        if self._conn is None:
            return stats

        try:
            with self._lock:
                cursor = self._conn.execute(
                    "SELECT status, COUNT(*) FROM file_cache "
                    "WHERE site_path = ? GROUP BY status",
                    (site_path,),
                )
                for status, count in cursor.fetchall():
                    stats["total"] += count
                    if status in stats:
                        stats[status] = count
        except sqlite3.Error as exc:
            logger.debug("DB read error in get_stats: %s", exc)

        return stats

    def cleanup_old(self, max_age_days=30):
        # type: (int) -> int
        """
        Remove cache entries older than the specified age.

        Args:
            max_age_days: Maximum age in days for cache entries.

        Returns:
            Number of entries removed.
        """
        if self._conn is None:
            return 0

        cutoff = time.time() - (max_age_days * 86400)
        try:
            with self._lock:
                cursor = self._conn.execute(
                    "DELETE FROM file_cache WHERE scan_time < ?",
                    (cutoff,),
                )
                self._conn.commit()
                removed = cursor.rowcount
                logger.info("HashCache cleanup: removed %d entries older than %d days", removed, max_age_days)
                return removed
        except sqlite3.Error as exc:
            logger.error("DB error in cleanup_old: %s", exc)
            return 0

    def close(self):
        # type: () -> None
        """Close the database connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ── Internal helpers ────────────────────────────────────────────

    def _get_cached_paths(self, site_path):
        # type: (str) -> Set[str]
        """
        Get all cached relative paths for a site.

        Args:
            site_path: Absolute path to the WordPress root.

        Returns:
            Set of cached relative paths.
        """
        cached = set()  # type: Set[str]
        if self._conn is None:
            return cached

        try:
            with self._lock:
                cursor = self._conn.execute(
                    "SELECT rel_path FROM file_cache WHERE site_path = ?",
                    (site_path,),
                )
                for row in cursor.fetchall():
                    cached.add(row[0])
        except sqlite3.Error as exc:
            logger.debug("DB read error in _get_cached_paths: %s", exc)

        return cached
