"""
CleanShift Test Suite — File Integrity Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tests for:
- VerifyResult enum values
- ChecksumVerifier (core checksums, plugin checksums, caching, MD5,
  WP version detection, API failure handling)
- HashCache (SQLite lifecycle, incremental scanning, new/deleted file
  detection, corrupt DB recovery, cleanup)

Uses pytest fixtures, tmp_path, and unittest.mock for HTTP mocking.
Python 3.6+ compatible.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from agent.src.models import (
    Severity,
    ThreatType,
    WordPressSite,
)
from agent.src.verifier import (
    ChecksumVerifier,
    HashCache,
    VerifyResult,
)


# ─── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def cache_dir(tmp_path):
    """Provide a temporary cache directory."""
    d = tmp_path / "cache"
    d.mkdir()
    return str(d)


@pytest.fixture
def wp_site(tmp_path):
    """Create a minimal WordPress site structure with version.php."""
    site_path = tmp_path / "public_html"
    site_path.mkdir()
    (site_path / "wp-admin").mkdir()
    wp_includes = site_path / "wp-includes"
    wp_includes.mkdir()
    (site_path / "wp-content").mkdir()

    # version.php for WP version detection
    (wp_includes / "version.php").write_text(
        "<?php\n"
        "$wp_version = '6.5.2';\n"
        "$wp_db_version = 57155;\n"
    )

    # A core file to verify
    (wp_includes / "load.php").write_text("<?php // WordPress core loader\n")

    return WordPressSite(
        path=str(site_path),
        domain="example.com",
        wp_version="6.5.2",
        db_name="testdb",
    )


# ─── VerifyResult Tests ────────────────────────────────────────────

class TestVerifyResult:
    """Tests for the VerifyResult enum."""

    def test_enum_values(self):
        """VerifyResult should have all expected values."""
        assert VerifyResult.OFFICIAL == "official"
        assert VerifyResult.MODIFIED == "modified"
        assert VerifyResult.CUSTOM == "custom"
        assert VerifyResult.UNKNOWN == "unknown"

    def test_enum_membership(self):
        """String values should be usable for comparison."""
        assert VerifyResult("official") == VerifyResult.OFFICIAL
        assert VerifyResult("modified") == VerifyResult.MODIFIED


# ─── ChecksumVerifier Tests ────────────────────────────────────────

class TestChecksumVerifier:
    """Tests for the ChecksumVerifier class."""

    def test_compute_md5_correct(self, tmp_path):
        """_compute_md5 should return the correct MD5 hex digest."""
        test_file = tmp_path / "test.txt"
        content = b"Hello, WordPress!\n"
        test_file.write_bytes(content)

        expected_md5 = hashlib.md5(content).hexdigest()

        verifier = ChecksumVerifier(cache_dir=str(tmp_path / "cache"))
        result = verifier._compute_md5(str(test_file))

        assert result == expected_md5

    def test_compute_md5_missing_file(self, cache_dir):
        """_compute_md5 should return empty string for missing files."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)
        result = verifier._compute_md5("/nonexistent/path/file.php")
        assert result == ""

    def test_verify_file_official(self, wp_site, cache_dir):
        """verify_file should return OFFICIAL when checksum matches."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        # Compute the actual MD5 of the test file
        load_php_path = os.path.join(wp_site.path, "wp-includes", "load.php")
        actual_md5 = hashlib.md5(open(load_php_path, "rb").read()).hexdigest()

        # Mock API response with the correct checksum
        mock_checksums = {"wp-includes/load.php": actual_md5}

        with patch.object(verifier, "fetch_core_checksums", return_value=mock_checksums):
            result = verifier.verify_file(wp_site, "wp-includes/load.php")

        assert result == VerifyResult.OFFICIAL

    def test_verify_file_modified(self, wp_site, cache_dir):
        """verify_file should return MODIFIED when checksum differs."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        # Mock API response with a different checksum
        mock_checksums = {"wp-includes/load.php": "deadbeef" * 4}

        with patch.object(verifier, "fetch_core_checksums", return_value=mock_checksums):
            result = verifier.verify_file(wp_site, "wp-includes/load.php")

        assert result == VerifyResult.MODIFIED

    def test_verify_file_custom(self, wp_site, cache_dir):
        """verify_file should return CUSTOM for files not in checksums."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        # Mock API response without our custom file
        mock_checksums = {"wp-includes/load.php": "abc123"}

        with patch.object(verifier, "fetch_core_checksums", return_value=mock_checksums):
            result = verifier.verify_file(wp_site, "wp-content/plugins/myplugin/myplugin.php")

        assert result == VerifyResult.CUSTOM

    def test_api_failure_returns_unknown(self, wp_site, cache_dir):
        """verify_file should return UNKNOWN when API fetch fails."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        with patch.object(verifier, "fetch_core_checksums", return_value={}):
            result = verifier.verify_file(wp_site, "wp-includes/load.php")

        assert result == VerifyResult.UNKNOWN

    def test_cache_saves_and_loads(self, cache_dir):
        """Cached data should persist to disk and reload correctly."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        test_data = {"wp-includes/load.php": "abc123def456"}
        verifier._save_cache("core_6.5.2", test_data)

        # Clear in-memory cache to force disk read
        verifier._mem_cache.clear()

        loaded = verifier._load_cache("core_6.5.2")
        assert loaded == test_data

    def test_cache_expiry(self, cache_dir):
        """Expired cache entries should return None."""
        verifier = ChecksumVerifier(cache_dir=cache_dir, cache_ttl=1)

        test_data = {"file.php": "hash123"}
        verifier._save_cache("test_key", test_data)

        # Clear in-memory cache
        verifier._mem_cache.clear()

        # Backdate the cache file
        cache_file = os.path.join(cache_dir, "test_key.json")
        old_time = time.time() - 100
        os.utime(cache_file, (old_time, old_time))

        loaded = verifier._load_cache("test_key")
        assert loaded is None

    def test_detect_wp_version(self, wp_site, cache_dir):
        """_detect_wp_version should parse version from version.php."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)
        version = verifier._detect_wp_version(wp_site.path)
        assert version == "6.5.2"

    def test_detect_wp_version_missing(self, tmp_path, cache_dir):
        """_detect_wp_version should return None if version.php is missing."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)
        version = verifier._detect_wp_version(str(tmp_path))
        assert version is None

    def test_plugin_checksum_fetch(self, cache_dir):
        """fetch_plugin_checksums should parse API response correctly."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        mock_response = {
            "files": {
                "akismet.php": {"md5": "abc123", "sha256": "def456"},
                "class.akismet.php": {"md5": "789ghi", "sha256": "jkl012"},
            }
        }

        with patch.object(verifier, "_http_get_json", return_value=mock_response):
            result = verifier.fetch_plugin_checksums("akismet", "5.3.1")

        assert "akismet.php" in result
        assert result["akismet.php"]["md5"] == "abc123"
        assert result["class.akismet.php"]["sha256"] == "jkl012"

    def test_verify_core_detects_modified(self, wp_site, cache_dir):
        """verify_core should return threats for modified core files."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        # Mock checksums where load.php has a different hash
        mock_checksums = {"wp-includes/load.php": "0" * 32}

        with patch.object(verifier, "fetch_core_checksums", return_value=mock_checksums):
            threats = verifier.verify_core(wp_site)

        assert len(threats) == 1
        assert threats[0].threat_type == ThreatType.CORE_MODIFIED
        assert threats[0].severity == Severity.HIGH
        assert "load.php" in threats[0].title

    def test_fetch_core_checksums_caches(self, cache_dir):
        """fetch_core_checksums should cache results and use them."""
        verifier = ChecksumVerifier(cache_dir=cache_dir)

        mock_response = {"checksums": {"wp-login.php": "abc123"}}

        with patch.object(verifier, "_http_get_json", return_value=mock_response) as mock_http:
            # First call — should hit API
            result1 = verifier.fetch_core_checksums("6.5.2")
            assert mock_http.call_count == 1
            assert result1 == {"wp-login.php": "abc123"}

            # Second call — should use cache
            result2 = verifier.fetch_core_checksums("6.5.2")
            assert mock_http.call_count == 1  # No additional API call
            assert result2 == result1


# ─── HashCache Tests ───────────────────────────────────────────────

class TestHashCache:
    """Tests for the HashCache class."""

    def test_needs_rescan_new_file(self, cache_dir):
        """needs_rescan should return True for files not in cache."""
        cache = HashCache(cache_dir)
        try:
            result = cache.needs_rescan("/site", "new_file.php", 1000.0, 512)
            assert result is True
        finally:
            cache.close()

    def test_needs_rescan_unchanged(self, cache_dir):
        """needs_rescan should return False for unchanged files."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "file.php", 1000.0, 512, "abc123", "clean")
            result = cache.needs_rescan("/site", "file.php", 1000.0, 512)
            assert result is False
        finally:
            cache.close()

    def test_needs_rescan_changed_mtime(self, cache_dir):
        """needs_rescan should return True when mtime changes."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "file.php", 1000.0, 512, "abc123", "clean")
            result = cache.needs_rescan("/site", "file.php", 2000.0, 512)
            assert result is True
        finally:
            cache.close()

    def test_needs_rescan_changed_size(self, cache_dir):
        """needs_rescan should return True when file size changes."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "file.php", 1000.0, 512, "abc123", "clean")
            result = cache.needs_rescan("/site", "file.php", 1000.0, 1024)
            assert result is True
        finally:
            cache.close()

    def test_get_new_files(self, cache_dir):
        """get_new_files should find files on disk but not in cache."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "existing.php", 1000.0, 100, "hash1", "clean")
            cache.update("/site", "also_known.php", 1000.0, 200, "hash2", "clean")

            current = {"existing.php", "also_known.php", "brand_new.php"}
            new_files = cache.get_new_files("/site", current)

            assert new_files == {"brand_new.php"}
        finally:
            cache.close()

    def test_get_deleted_files(self, cache_dir):
        """get_deleted_files should find files in cache but not on disk."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "still_here.php", 1000.0, 100, "hash1", "clean")
            cache.update("/site", "deleted.php", 1000.0, 200, "hash2", "clean")
            cache.update("/site", "also_gone.php", 1000.0, 300, "hash3", "clean")

            current = {"still_here.php"}
            deleted = cache.get_deleted_files("/site", current)

            assert deleted == {"deleted.php", "also_gone.php"}
        finally:
            cache.close()

    def test_update_and_retrieve(self, cache_dir):
        """update should store data retrievable by needs_rescan."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "test.php", 12345.0, 1024, "sha256hash", "threat")

            # Should not need rescan with same mtime+size
            assert cache.needs_rescan("/site", "test.php", 12345.0, 1024) is False

            # Different site should still need rescan
            assert cache.needs_rescan("/other_site", "test.php", 12345.0, 1024) is True
        finally:
            cache.close()

    def test_get_stats(self, cache_dir):
        """get_stats should return correct counts per status."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site", "a.php", 1.0, 10, "h1", "clean")
            cache.update("/site", "b.php", 2.0, 20, "h2", "clean")
            cache.update("/site", "c.php", 3.0, 30, "h3", "threat")
            cache.update("/site", "d.php", 4.0, 40, "h4", "skipped")

            stats = cache.get_stats("/site")

            assert stats["total"] == 4
            assert stats["clean"] == 2
            assert stats["threat"] == 1
            assert stats["skipped"] == 1
        finally:
            cache.close()

    def test_corrupt_db_recovery(self, cache_dir):
        """HashCache should recover from a corrupt database file."""
        db_path = os.path.join(cache_dir, "file_cache.db")

        # Write garbage to the DB file
        with open(db_path, "wb") as f:
            f.write(b"THIS IS NOT A VALID SQLITE DATABASE FILE\x00" * 100)

        # Should not raise — should recover automatically
        cache = HashCache(cache_dir)
        try:
            # Should work after recovery
            cache.update("/site", "file.php", 1000.0, 512, "hash", "clean")
            assert cache.needs_rescan("/site", "file.php", 1000.0, 512) is False
        finally:
            cache.close()

    def test_bulk_update(self, cache_dir):
        """bulk_update should insert multiple entries efficiently."""
        cache = HashCache(cache_dir)
        try:
            entries = [
                ("/site", "a.php", 1.0, 10, "h1", "clean"),
                ("/site", "b.php", 2.0, 20, "h2", "clean"),
                ("/site", "c.php", 3.0, 30, "h3", "threat"),
            ]
            cache.bulk_update(entries)

            assert cache.needs_rescan("/site", "a.php", 1.0, 10) is False
            assert cache.needs_rescan("/site", "b.php", 2.0, 20) is False
            assert cache.needs_rescan("/site", "c.php", 3.0, 30) is False
        finally:
            cache.close()

    def test_cleanup_old(self, cache_dir):
        """cleanup_old should remove entries older than the threshold."""
        cache = HashCache(cache_dir)
        try:
            # Insert an entry and manually backdate its scan_time
            cache.update("/site", "old.php", 1.0, 10, "h1", "clean")
            with cache._lock:
                cache._conn.execute(
                    "UPDATE file_cache SET scan_time = ? WHERE rel_path = ?",
                    (time.time() - 40 * 86400, "old.php"),
                )
                cache._conn.commit()

            cache.update("/site", "recent.php", 2.0, 20, "h2", "clean")

            removed = cache.cleanup_old(max_age_days=30)
            assert removed == 1

            # Old file should be gone, recent should remain
            assert cache.needs_rescan("/site", "old.php", 1.0, 10) is True
            assert cache.needs_rescan("/site", "recent.php", 2.0, 20) is False
        finally:
            cache.close()

    def test_separate_sites(self, cache_dir):
        """Cache should isolate entries per site_path."""
        cache = HashCache(cache_dir)
        try:
            cache.update("/site_a", "file.php", 1.0, 100, "hash_a", "clean")
            cache.update("/site_b", "file.php", 2.0, 200, "hash_b", "threat")

            # Same filename but different sites
            assert cache.needs_rescan("/site_a", "file.php", 1.0, 100) is False
            assert cache.needs_rescan("/site_b", "file.php", 2.0, 200) is False

            stats_a = cache.get_stats("/site_a")
            stats_b = cache.get_stats("/site_b")
            assert stats_a["clean"] == 1
            assert stats_b["threat"] == 1
        finally:
            cache.close()
