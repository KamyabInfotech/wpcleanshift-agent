"""
CleanShift CMS Adapter Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Provides a pluggable adapter layer that decouples CMS-specific scanning
logic from the generic scanning engine.  Each supported CMS implements
the :class:`CMSAdapter` abstract interface; the :class:`CMSRegistry`
auto-detects which adapter to use for a given filesystem path.

Quick start::

    from agent.src.cms import CMSRegistry
    adapter = CMSRegistry.detect(Path("/var/www/html"))
    print(adapter.name, adapter.get_version(Path("/var/www/html")))

Exports:
    CMSAdapter       — abstract base class every adapter must implement
    CMSRegistry      — registry that auto-detects and returns the right adapter
    WordPressAdapter — concrete adapter for WordPress sites
    GenericPHPAdapter — fallback adapter for unknown / generic PHP sites
"""

from __future__ import annotations

from .base import CMSAdapter
from .registry import CMSRegistry
from .wordpress import WordPressAdapter
from .generic import GenericPHPAdapter

__all__ = [
    "CMSAdapter",
    "CMSRegistry",
    "WordPressAdapter",
    "GenericPHPAdapter",
]
