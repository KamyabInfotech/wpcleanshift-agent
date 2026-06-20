"""
CleanShift CMS Adapter — Abstract Base Class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Defines the :class:`CMSAdapter` interface that every CMS-specific
scanning module must implement.  The interface is intentionally thin:
each method corresponds to a single responsibility that the scanning
engine may invoke independently.

Method summary:

    detect()               — probe a filesystem path for CMS signatures
    get_version()          — extract the installed CMS version string
    get_database_config()  — parse the CMS config for DB credentials
    verify_core_integrity()— check core files against known-good checksums
    audit_extensions()     — audit plugins / themes / modules for vulns
    name (property)        — human-readable CMS name
    priority (property)    — detection order; higher values are checked first
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional


class CMSAdapter(ABC):
    """Interface that each CMS-specific scanning module must implement.

    Concrete subclasses are registered with :class:`CMSRegistry` and
    tried in descending ``priority`` order.  The first adapter whose
    :meth:`detect` returns ``True`` wins.
    """

    # ── Detection ────────────────────────────────────────────────────

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """Return ``True`` if this CMS is detected at *path*.

        Implementations should check for the presence of signature
        files or directories that uniquely identify the CMS.  The
        check must be fast (no network I/O, no database queries).

        Args:
            path: Absolute filesystem path to probe.

        Returns:
            ``True`` if the CMS is present, ``False`` otherwise.
        """

    # ── Version ──────────────────────────────────────────────────────

    @abstractmethod
    def get_version(self, path: Path) -> Optional[str]:
        """Return the installed CMS version string, or ``None``.

        Args:
            path: Root directory of the CMS installation.

        Returns:
            Version string (e.g. ``"6.5.2"``) or ``None`` if it
            cannot be determined.
        """

    # ── Database configuration ───────────────────────────────────────

    @abstractmethod
    def get_database_config(self, path: Path) -> Dict[str, Any]:
        """Extract database connection parameters from the CMS config.

        Typical keys: ``db_host``, ``db_name``, ``db_user``,
        ``db_password``, ``db_prefix``, ``db_charset``.

        Args:
            path: Root directory of the CMS installation.

        Returns:
            Dictionary of connection parameters.  Empty dict if the
            config cannot be parsed.
        """

    # ── Core integrity ───────────────────────────────────────────────

    @abstractmethod
    def verify_core_integrity(self, path: Path) -> List[Dict[str, Any]]:
        """Check core files against known-good checksums.

        Each anomaly dict should contain at least:

        * ``file``    — relative path to the modified/missing file
        * ``status``  — one of ``"modified"``, ``"missing"``, ``"unknown"``
        * ``detail``  — human-readable explanation

        Args:
            path: Root directory of the CMS installation.

        Returns:
            List of anomaly dicts.  An empty list means all core
            files are intact (or no checksums are available).
        """

    # ── Extension audit ──────────────────────────────────────────────

    @abstractmethod
    def audit_extensions(self, path: Path) -> List[Dict[str, Any]]:
        """Audit plugins / themes / modules for known vulnerabilities.

        Each threat dict should contain at least:

        * ``name``     — extension name
        * ``version``  — installed version
        * ``status``   — e.g. ``"active"``, ``"inactive"``
        * ``update``   — available update version, or ``"none"``
        * ``vulnerabilities`` — list of known CVE / advisory IDs

        Args:
            path: Root directory of the CMS installation.

        Returns:
            List of extension info dicts.  Empty list if no
            extensions are found or the CMS has no extension concept.
        """

    # ── Identity ─────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable CMS name (e.g. ``'WordPress'``, ``'Drupal'``)."""

    @property
    @abstractmethod
    def priority(self) -> int:
        """Detection priority — higher values are checked first.

        Use 100 for well-known CMS adapters, 0 for the generic
        fallback, and values in between for less-common platforms.
        """

    # ── Dunder helpers ───────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r} priority={self.priority}>"
