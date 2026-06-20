"""
CleanShift CMS Adapter — Generic PHP Fallback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A no-op :class:`CMSAdapter` implementation that acts as the universal
fallback.  Its :meth:`detect` always returns ``True``, so it must be
registered at the lowest priority (0) and will only match if no
specific CMS adapter claims the path first.

This adapter intentionally returns empty / ``None`` results for every
method: the generic scanning engine can still perform file-level
analysis without any CMS-specific context.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import CMSAdapter

logger = logging.getLogger("cleanshift.cms.generic")


class GenericPHPAdapter(CMSAdapter):
    """Fallback adapter for sites with no recognised CMS.

    Always matches, always returns empty results.  Registered at
    ``priority=0`` so every concrete CMS adapter is tried first.
    """

    # ── Identity ─────────────────────────────────────────────────────

    @property
    def name(self) -> str:  # noqa: D401
        """Human-readable CMS name."""
        return "Generic PHP"

    @property
    def priority(self) -> int:  # noqa: D401
        """Detection priority (lowest — this is the fallback)."""
        return 0

    # ── Detection ────────────────────────────────────────────────────

    def detect(self, path: Path) -> bool:
        """Always returns ``True`` — this adapter catches everything.

        Args:
            path: Filesystem path (ignored).
        """
        logger.debug("Generic PHP fallback matched at %s", path)
        return True

    # ── Version ──────────────────────────────────────────────────────

    def get_version(self, path: Path) -> Optional[str]:
        """Returns ``None`` — no version detection for generic sites.

        Args:
            path: Filesystem path (ignored).
        """
        return None

    # ── Database config ──────────────────────────────────────────────

    def get_database_config(self, path: Path) -> Dict[str, Any]:
        """Returns an empty dict — no config parsing for generic sites.

        Args:
            path: Filesystem path (ignored).
        """
        return {}

    # ── Core integrity ───────────────────────────────────────────────

    def verify_core_integrity(self, path: Path) -> List[Dict[str, Any]]:
        """Returns an empty list — no checksums available for generic sites.

        Args:
            path: Filesystem path (ignored).
        """
        return []

    # ── Extension audit ──────────────────────────────────────────────

    def audit_extensions(self, path: Path) -> List[Dict[str, Any]]:
        """Returns an empty list — no extension concept for generic sites.

        Args:
            path: Filesystem path (ignored).
        """
        return []
