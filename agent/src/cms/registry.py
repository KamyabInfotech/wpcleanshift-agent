"""
CleanShift CMS Adapter — Registry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :class:`CMSRegistry` maintains an ordered list of
:class:`CMSAdapter` classes and provides a single :meth:`detect`
entry-point that probes a filesystem path against every registered
adapter (sorted by descending ``priority``).

On module import the registry automatically registers:

1. :class:`WordPressAdapter` (priority 100)
2. :class:`GenericPHPAdapter` (priority 0 — fallback)

Third-party adapters can be added at runtime via
:meth:`CMSRegistry.register`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Type

from .base import CMSAdapter

logger = logging.getLogger("cleanshift.cms.registry")


class CMSRegistry:
    """Registry that auto-detects the CMS at a given filesystem path.

    Adapters are stored as *classes* (not instances) and instantiated
    lazily during detection so each detection call works with a fresh
    adapter instance.

    Class-level API — no need to instantiate the registry itself.

    Usage::

        from agent.src.cms import CMSRegistry

        adapter = CMSRegistry.detect(Path("/var/www/html"))
        print(adapter.name)
    """

    _adapters: List[Type[CMSAdapter]] = []

    # ── Registration ─────────────────────────────────────────────────

    @classmethod
    def register(cls, adapter_class: Type[CMSAdapter]) -> None:
        """Register a CMS adapter class.

        The adapter is inserted into the internal list and the list is
        re-sorted by descending ``priority`` so that high-priority
        adapters are always tried first.

        Args:
            adapter_class: A concrete subclass of :class:`CMSAdapter`.

        Raises:
            TypeError: If *adapter_class* is not a subclass of
                       :class:`CMSAdapter`.
        """
        if not (isinstance(adapter_class, type) and issubclass(adapter_class, CMSAdapter)):
            raise TypeError(
                f"Expected a CMSAdapter subclass, got {adapter_class!r}"
            )

        # Avoid duplicate registrations.
        if adapter_class in cls._adapters:
            logger.debug("Adapter %s already registered — skipping", adapter_class.__name__)
            return

        cls._adapters.append(adapter_class)
        # Sort by priority descending (instantiate temporarily to read
        # the priority property).
        cls._adapters.sort(key=lambda a: a().priority, reverse=True)

        logger.debug(
            "Registered adapter %s (priority=%d); %d adapters total",
            adapter_class.__name__,
            adapter_class().priority,
            len(cls._adapters),
        )

    # ── Detection ────────────────────────────────────────────────────

    @classmethod
    def detect(cls, path: Path) -> CMSAdapter:
        """Return the first adapter whose :meth:`detect` returns ``True``.

        Adapters are tried in descending priority order.  If no
        specific adapter matches, the :class:`GenericPHPAdapter`
        fallback (which always matches) is returned.

        If the registry is empty for some reason, a
        :class:`GenericPHPAdapter` instance is created on-the-fly.

        Args:
            path: Absolute filesystem path to probe.

        Returns:
            An instantiated :class:`CMSAdapter`.
        """
        for adapter_class in cls._adapters:
            adapter = adapter_class()
            logger.debug(
                "Trying adapter %s (priority=%d) at %s",
                adapter.name,
                adapter.priority,
                path,
            )
            try:
                if adapter.detect(path):
                    logger.info(
                        "CMS detected: %s at %s",
                        adapter.name,
                        path,
                    )
                    return adapter
            except Exception as exc:
                logger.warning(
                    "Adapter %s raised during detection: %s",
                    adapter.name,
                    exc,
                )
                continue

        # Should never reach here if GenericPHPAdapter is registered,
        # but be defensive.
        logger.warning("No adapter matched at %s — creating GenericPHPAdapter", path)
        from .generic import GenericPHPAdapter
        return GenericPHPAdapter()

    # ── Introspection ────────────────────────────────────────────────

    @classmethod
    def registered_adapters(cls) -> List[Type[CMSAdapter]]:
        """Return a snapshot of currently registered adapter classes.

        The list is ordered by descending priority.
        """
        return list(cls._adapters)

    @classmethod
    def clear(cls) -> None:
        """Remove all registered adapters.  Useful for testing."""
        cls._adapters.clear()
        logger.debug("Registry cleared")


# ── Auto-registration on import ──────────────────────────────────────

def _bootstrap() -> None:
    """Register the built-in adapters when this module is first imported."""
    from .wordpress import WordPressAdapter
    from .generic import GenericPHPAdapter

    CMSRegistry.register(WordPressAdapter)
    CMSRegistry.register(GenericPHPAdapter)


_bootstrap()
