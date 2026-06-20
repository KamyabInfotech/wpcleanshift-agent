"""
CleanShift YARA Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~

Wraps yara-python for signature-based malware detection.  Loads YARA
rules from the ``intelligence/rules/`` directory and scans PHP/JS
files for known malware patterns, webshells, and obfuscation.

Features:
    - Thread-safe rule compilation with caching (compile once, reuse)
    - Configurable max file size (default 10 MB)
    - Graceful degradation if yara-python is not installed
    - Returns structured YaraFinding objects

Dependencies:
    - yara-python (optional — scanner returns empty results if missing)
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

logger = logging.getLogger("cleanshift.yara_scanner")

# Default rules directory — intelligence/rules/ relative to repo root
_DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "intelligence" / "rules"
)

# Default maximum file size to scan (10 MB)
_DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024

# File extensions to scan
_SCANNABLE_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps",
    ".js", ".html", ".htm", ".svg", ".htaccess", ".inc", ".tpl",
}


# ─── Data Models ───────────────────────────────────────────────────

@dataclass
class YaraFinding:
    """A single YARA rule match against a scanned file.

    Attributes:
        rule_name:        Name of the matched YARA rule.
        matched_strings:  List of (offset, identifier, data) tuples from
                          the matched strings.
        file_path:        Absolute path to the matched file.
        severity:         Severity from rule metadata ('critical', 'high',
                          'medium', 'low'), defaults to 'medium'.
        description:      Human-readable description from rule metadata.
        tags:             YARA rule tags (e.g. ['webshell', 'php']).
        meta:             Full rule metadata dictionary.
    """
    rule_name: str = ""
    matched_strings: List[Dict[str, Any]] = field(default_factory=list)
    file_path: str = ""
    severity: str = "medium"
    description: str = ""
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "rule_name": self.rule_name,
            "matched_strings": self.matched_strings,
            "file_path": self.file_path,
            "severity": self.severity,
            "description": self.description,
            "tags": self.tags,
            "meta": self.meta,
        }


# ─── YARA Scanner ──────────────────────────────────────────────────

class YaraScanner:
    """Thread-safe YARA rule scanner for malware detection.

    Parameters
    ----------
    rules_dir : str | Path | None
        Directory containing .yar/.yara rule files.
        Defaults to ``intelligence/rules/``.
    max_file_size : int
        Maximum file size in bytes to scan (default: 10 MB).
        Files exceeding this limit are skipped with a debug log.

    Usage
    -----
    >>> scanner = YaraScanner()
    >>> scanner.load_rules()
    >>> findings = scanner.scan_file("/var/www/html/suspicious.php")
    >>> for f in findings:
    ...     print(f.rule_name, f.severity)
    """

    def __init__(
        self,
        rules_dir: Optional[str | Path] = None,
        max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
    ) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
        self.max_file_size = max_file_size

        self._compiled_rules: Optional[Any] = None  # yara.Rules
        self._compile_lock = threading.Lock()
        self._rules_loaded = False

        if not _YARA_AVAILABLE:
            logger.warning(
                "yara-python is not installed — YARA scanning disabled. "
                "Install with: pip install yara-python"
            )

    # ── Public API ─────────────────────────────────────────────────

    def load_rules(self, rules_dir: Optional[str | Path] = None) -> bool:
        """Compile and cache YARA rules from the rules directory.

        Thread-safe — only one thread compiles at a time, and the
        compiled rules are reused by all subsequent calls.

        Args:
            rules_dir: Override the rules directory (optional).

        Returns:
            True if rules were loaded successfully, False otherwise.
        """
        if not _YARA_AVAILABLE:
            logger.warning("Cannot load YARA rules — yara-python not installed")
            return False

        if rules_dir:
            self.rules_dir = Path(rules_dir)

        with self._compile_lock:
            return self._compile_rules()

    def scan_file(self, filepath: str | Path) -> List[YaraFinding]:
        """Scan a single file against loaded YARA rules.

        Args:
            filepath: Absolute path to the file to scan.

        Returns:
            List of YaraFinding objects for each rule match.
            Returns empty list if YARA is not available, rules
            aren't loaded, file is too large, or file can't be read.
        """
        if not _YARA_AVAILABLE or not self._rules_loaded:
            return []

        filepath = Path(filepath)

        # Validate file
        if not filepath.exists():
            logger.debug("File not found: %s", filepath)
            return []

        if not filepath.is_file():
            return []

        # Check file size
        try:
            file_size = filepath.stat().st_size
        except OSError as exc:
            logger.debug("Cannot stat file %s: %s", filepath, exc)
            return []

        if file_size > self.max_file_size:
            logger.debug(
                "Skipping %s (%d bytes > %d max)",
                filepath, file_size, self.max_file_size,
            )
            return []

        if file_size == 0:
            return []

        # Scan
        try:
            matches = self._compiled_rules.match(str(filepath), timeout=30)
            return self._process_matches(matches, str(filepath))
        except yara.TimeoutError:
            logger.warning("YARA scan timed out on: %s", filepath)
            return []
        except yara.Error as exc:
            logger.warning("YARA scan error on %s: %s", filepath, exc)
            return []
        except Exception as exc:
            logger.warning("Unexpected error scanning %s: %s", filepath, exc)
            return []

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        extensions: Optional[set] = None,
    ) -> List[YaraFinding]:
        """Scan all files in a directory against loaded YARA rules.

        Args:
            directory: Path to the directory to scan.
            recursive: Whether to scan subdirectories (default: True).
            extensions: Set of file extensions to scan (with leading dot).
                        Defaults to common PHP/web file extensions.

        Returns:
            Combined list of YaraFinding objects from all scanned files.
        """
        if not _YARA_AVAILABLE or not self._rules_loaded:
            return []

        directory = Path(directory)
        if not directory.is_dir():
            logger.warning("Not a directory: %s", directory)
            return []

        scan_extensions = extensions or _SCANNABLE_EXTENSIONS
        findings: List[YaraFinding] = []
        files_scanned = 0

        try:
            iterator = directory.rglob("*") if recursive else directory.glob("*")
            for entry in iterator:
                if not entry.is_file():
                    continue

                # Filter by extension
                if entry.suffix.lower() not in scan_extensions:
                    continue

                file_findings = self.scan_file(entry)
                findings.extend(file_findings)
                files_scanned += 1

        except PermissionError as exc:
            logger.warning("Permission denied scanning %s: %s", directory, exc)
        except Exception as exc:
            logger.warning("Error scanning directory %s: %s", directory, exc)

        logger.info(
            "YARA scan complete: %d files scanned, %d findings in %s",
            files_scanned, len(findings), directory,
        )
        return findings

    @property
    def rules_loaded(self) -> bool:
        """Whether YARA rules have been successfully compiled."""
        return self._rules_loaded

    # ── Private Helpers ────────────────────────────────────────────

    def _compile_rules(self) -> bool:
        """Compile all .yar/.yara files in the rules directory.

        Must be called while holding ``_compile_lock``.
        """
        if not self.rules_dir.is_dir():
            logger.warning("Rules directory not found: %s", self.rules_dir)
            return False

        # Collect rule files (recursively — includes community/ subdirectory)
        rule_files: Dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for rule_path in sorted(self.rules_dir.rglob(ext)):
                # Use relative path as namespace to avoid collisions
                # e.g. community/php_malware instead of just php_malware
                rel = rule_path.relative_to(self.rules_dir)
                namespace = str(rel.with_suffix('')).replace('/', '_').replace('\\', '_')
                rule_files[namespace] = str(rule_path)

        if not rule_files:
            logger.warning("No YARA rule files found in %s", self.rules_dir)
            return False

        try:
            self._compiled_rules = yara.compile(filepaths=rule_files)
            self._rules_loaded = True
            logger.info(
                "YARA rules compiled: %d rule file(s) from %s",
                len(rule_files), self.rules_dir,
            )
            return True
        except yara.SyntaxError as exc:
            logger.error("YARA rule syntax error: %s", exc)
            return False
        except yara.Error as exc:
            logger.error("YARA compilation error: %s", exc)
            return False

    def _process_matches(
        self,
        matches: list,
        filepath: str,
    ) -> List[YaraFinding]:
        """Convert raw yara match objects to YaraFinding instances."""
        findings: List[YaraFinding] = []

        for match in matches:
            meta = dict(match.meta) if match.meta else {}
            severity = meta.get("severity", "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            # Extract matched strings
            matched_strings: List[Dict[str, Any]] = []
            if hasattr(match, "strings"):
                for string_match in match.strings:
                    # yara-python 4.x: StringMatch with .instances
                    if hasattr(string_match, "instances"):
                        for instance in string_match.instances:
                            matched_strings.append({
                                "offset": instance.offset,
                                "identifier": string_match.identifier,
                                "data": instance.matched_data.decode(
                                    "utf-8", errors="replace"
                                )[:200],
                            })
                    else:
                        # yara-python 3.x fallback: (offset, id, data)
                        try:
                            offset, identifier, data = string_match
                            matched_strings.append({
                                "offset": offset,
                                "identifier": identifier,
                                "data": data.decode(
                                    "utf-8", errors="replace"
                                )[:200] if isinstance(data, bytes) else str(data)[:200],
                            })
                        except (ValueError, TypeError):
                            pass

            finding = YaraFinding(
                rule_name=match.rule,
                matched_strings=matched_strings,
                file_path=filepath,
                severity=severity,
                description=meta.get("description", ""),
                tags=list(match.tags) if match.tags else [],
                meta=meta,
            )
            findings.append(finding)

        return findings
