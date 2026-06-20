"""
CleanShift Parallel Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Multi-process scanning engine that distributes WordPress site scans
across multiple worker processes for faster server-wide analysis.

Uses ``multiprocessing.Pool`` with ``starmap`` to avoid pickle issues
with bound methods.  Each worker process instantiates its own
``SiteScanner`` so no shared state crosses process boundaries.

Architecture::

    ParallelScanner.scan_server()
      ├─ discover_wp_sites()          (same as ServerScanner)
      ├─ partition sites into batches
      ├─ Pool.starmap(_scan_site_worker, ...)
      │     ├─ Worker 0: SiteScanner → [Threat, …]
      │     ├─ Worker 1: SiteScanner → [Threat, …]
      │     └─ …
      ├─ merge results into single ScanResult
      └─ _cross_site_correlate()      (flag same threat across sites)

Designed as a drop-in replacement for ``ServerScanner.scan_server``.
"""

from __future__ import annotations

import json
import logging
import math
import os
import socket
import time
from dataclasses import dataclass, field
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from .intelligence import IntelligenceDB
from .models import ScanResult, Severity, Threat, WordPressSite
from .scanner import ScanMode, SiteScanner, _apply_nice_priority, _throttle_if_overloaded
from .wp import build_site_info, discover_wp_sites

logger = logging.getLogger("cleanshift.parallel")
console = Console()


# ─── Serialisable Result Container ──────────────────────────────────
# dataclass is picklable — used to shuttle results back from workers.

@dataclass
class _WorkerResult:
    """Pickle-safe container returned by each worker process."""
    site: Optional[WordPressSite] = None
    threats: List[Threat] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_seconds: float = 0.0


# ─── Top-Level Worker Function ──────────────────────────────────────
# MUST be a module-level function (not a method) because
# multiprocessing.Pool uses pickle which cannot serialise bound methods.

def _scan_site_worker(
    wp_root: str,
    scanner_kwargs: Dict[str, Any],
) -> _WorkerResult:
    """Scan a single WordPress site inside a worker process.

    Instantiates a fresh ``SiteScanner`` per invocation to avoid
    sharing state across processes.

    Args:
        wp_root: Absolute path to the WordPress installation root.
        scanner_kwargs: Keyword arguments forwarded to ``SiteScanner``.

    Returns:
        ``_WorkerResult`` with site info, threats, and timing.
    """
    start = time.monotonic()
    _apply_nice_priority()

    try:
        # Build the SiteScanner inside the worker — nothing is shared
        intel_path = scanner_kwargs.pop("intel_path", None)
        if intel_path:
            intel = IntelligenceDB(intel_path)
        else:
            intel = IntelligenceDB()

        site_scanner = SiteScanner(intel=intel, **{k: v for k, v in scanner_kwargs.items() if k != "all_cms"})
        site = build_site_info(Path(wp_root))
        threats = site_scanner.scan(site)

        return _WorkerResult(
            site=site,
            threats=threats,
            elapsed_seconds=time.monotonic() - start,
        )
    except Exception as exc:
        logger.error("Worker process failed unexpectedly on %s: %s", wp_root, exc, exc_info=True)
        return _WorkerResult(site=None, threats=[], elapsed_seconds=time.monotonic() - start, error=str(exc))

def _scan_site_worker_wrapper(args):
    return _scan_site_worker(*args)

def _write_progress_file(total: int, scanned: int, last_site: str):
    prog = {
        "status": "running",
        "total": total,
        "scanned": scanned,
        "percent": round((scanned / total * 100), 2) if total else 0,
        "last_site": last_site
    }
    try:
        with open("/var/run/cleanshift_progress.json", "w") as f:
            json.dump(prog, f)
    except Exception:
        pass


# ─── Parallel Scanner ──────────────────────────────────────────────

class ParallelScanner:
    """Parallel multi-site scanner using Python multiprocessing.

    Drop-in alternative to ``ServerScanner`` that distributes site
    scans across worker processes for servers with many WordPress
    installations.

    Workers are capped at ``min(cpu_count, 8)`` to prevent
    overwhelming shared-hosting servers.

    Example::

        intel = IntelligenceDB()
        scanner = ParallelScanner(workers=4, intel=intel, scan_mode=ScanMode.DEEP)
        result = scanner.scan_server("/home")
    """

    # Ceiling for worker count — prevents CPU saturation on big boxes
    MAX_WORKERS = 8

    def __init__(
        self,
        workers: int | None = None,
        intel: IntelligenceDB | None = None,
        scan_mode: ScanMode = ScanMode.DEEP,
        per_file_timeout: int = 30,
        total_site_timeout: int = 600,
        memory_limit_mb: int = 512,
        agent_id: str = "",
        server_hostname: str = "",
        **scanner_kwargs: Any,
    ) -> None:
        cpu = os.cpu_count() or 2
        self.workers = min(workers or cpu, self.MAX_WORKERS)

        self.intel = intel or IntelligenceDB()
        self.agent_id = agent_id
        self.server_hostname = server_hostname or self._get_hostname()

        # These will be forwarded to workers via a plain dict (pickle-safe)
        self._scanner_kwargs: Dict[str, Any] = {
            "scan_mode": scan_mode,
            "per_file_timeout": per_file_timeout,
            "total_site_timeout": total_site_timeout,
            "memory_limit_mb": memory_limit_mb,
            **scanner_kwargs,
        }

        # If the IntelligenceDB was created from a file path, pass the
        # path so workers can reconstruct it.  Otherwise workers will
        # use the default path.
        if hasattr(self.intel, "db_path"):
            self._scanner_kwargs["intel_path"] = str(self.intel.db_path)

        _apply_nice_priority()
        logger.info(
            "ParallelScanner initialised: %d workers, mode=%s",
            self.workers,
            scan_mode.value,
        )

    # ── Public API ──────────────────────────────────────────────────

    def scan_server(
        self,
        base_path: str = "/home",
        exclude_paths: list[str] | None = None,
    ) -> ScanResult:
        """Discover all WordPress sites and scan them in parallel.

        1. Discover WP sites under *base_path* (reuses ``discover_wp_sites``).
        2. Apply *exclude_paths* filter.
        3. Partition sites into batches for the worker pool.
        4. Scan in parallel using ``multiprocessing.Pool.starmap``.
        5. Merge all ``_WorkerResult`` objects into one ``ScanResult``.
        6. Run cross-site correlation on the merged threat list.

        Args:
            base_path: Root directory to search for WordPress sites.
            exclude_paths: Paths to skip during scanning.

        Returns:
            Complete ``ScanResult`` with all sites and threats.
        """
        result = ScanResult(
            agent_id=self.agent_id,
            server_hostname=self.server_hostname,
        )

        # ── Step 1: discover ────────────────────────────────────────
        wp_roots = discover_wp_sites(base_path)

        if exclude_paths:
            wp_roots = [
                r for r in wp_roots
                if not any(str(r).startswith(ex) for ex in exclude_paths)
            ]

        total_sites = len(wp_roots)
        if total_sites == 0:
            logger.info("No WordPress sites found under %s", base_path)
            result.finalize()
            return result

        logger.info(
            "Parallel scanning %d WordPress site(s) with %d workers …",
            total_sites,
            self.workers,
        )

        # ── Step 2: partition into batches ──────────────────────────
        batches = self._partition(wp_roots, self.workers)

        # ── Step 3 + 4: scan in parallel with progress ─────────────
        worker_results = self._run_pool(batches, total_sites)

        # ── Step 5: merge results ───────────────────────────────────
        failed = 0
        for wr in worker_results:
            if wr.error:
                failed += 1
                logger.error("Worker returned error: %s", wr.error)
                continue
            if wr.site is not None:
                result.sites.append(wr.site)
            result.threats.extend(wr.threats)

        logger.info(
            "Parallel scan complete: %d sites scanned, %d failures, %d threats",
            len(result.sites),
            failed,
            len(result.threats),
        )

        # ── Step 6: cross-site correlation ──────────────────────────
        self._cross_site_correlate(result)

        result.finalize()
        return result

    # ── Internal Helpers ────────────────────────────────────────────

    @staticmethod
    def _partition(items: List[Path], n: int) -> List[List[Path]]:
        """Split *items* into *n* roughly-equal sized batches.

        Returns at most *n* batches (fewer if there are fewer items
        than workers).
        """
        n = min(n, len(items))
        batch_size = math.ceil(len(items) / n)
        return [items[i : i + batch_size] for i in range(0, len(items), batch_size)]

    def _run_pool(
        self,
        batches: List[List[Path]],
        total_sites: int,
    ) -> List[_WorkerResult]:
        """Execute worker pool across all batches with progress display.

        Each batch is submitted as a group of ``starmap`` arguments.
        Between batches we call ``_throttle_if_overloaded()`` to be
        gentle on shared-hosting CPUs.

        Args:
            batches: Pre-partitioned lists of WP root paths.
            total_sites: Total number of sites (for progress bar).

        Returns:
            Flat list of ``_WorkerResult`` from all workers.
        """
        all_results: List[_WorkerResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Scanning sites", total=total_sites)

            for batch_idx, batch in enumerate(batches):
                if batch_idx > 0:
                    _throttle_if_overloaded()

                # Build starmap arguments: (wp_root_str, scanner_kwargs)
                args = [
                    (str(wp_root), dict(self._scanner_kwargs))
                    for wp_root in batch
                ]

                try:
                    with Pool(processes=min(self.workers, len(batch))) as pool:
                        for wr in pool.imap_unordered(_scan_site_worker_wrapper, args):
                            all_results.append(wr)
                            progress.advance(task_id)
                            
                            # Write progress
                            scanned_so_far = len(all_results)
                            last_site = wr.site.path if wr.site else (args[0][0] if args else "Unknown")
                            _write_progress_file(total_sites, scanned_so_far, last_site)
                            
                            if wr.site is not None:
                                status = (
                                    f"[green]✓[/green] {wr.site.path} "
                                    f"({len(wr.threats)} threats, "
                                    f"{wr.elapsed_seconds:.1f}s)"
                                )
                            elif wr.error:
                                status = f"[red]✗[/red] Error: {wr.error}"
                            else:
                                status = "[yellow]?[/yellow] Unknown result"
                            progress.console.print(status)
                except Exception as exc:
                    # Pool-level crash — log and continue with remaining batches
                    logger.error(
                        "Worker pool crashed on batch %d/%d: %s",
                        batch_idx + 1,
                        len(batches),
                        exc,
                        exc_info=True,
                    )
                    # Record failures for every site in the crashed batch
                    for wp_root in batch:
                        all_results.append(
                            _WorkerResult(error=f"Pool crash: {exc}")
                        )
                        progress.advance(task_id)

        try:
            if os.path.exists("/var/run/cleanshift_progress.json"):
                os.remove("/var/run/cleanshift_progress.json")
        except Exception:
            pass

        return all_results

    @staticmethod
    def _cross_site_correlate(result: ScanResult) -> None:
        """Flag threats that appear across multiple sites.

        When the same threat signature (same title + type) is found on
        two or more sites it is likely a server-wide compromise rather
        than an isolated incident.  This method tags those threats with
        a ``cross_site`` detail key listing all affected site paths, and
        bumps their severity to at least HIGH.

        Args:
            result: The merged ``ScanResult`` to analyse in-place.
        """
        if len(result.sites) < 2:
            return

        # Group threats by a normalised key: (threat_type, title)
        from collections import defaultdict
        groups: Dict[Tuple[str, str], List[Threat]] = defaultdict(list)
        for threat in result.threats:
            key = (threat.threat_type.value, threat.title)
            groups[key].append(threat)

        cross_site_count = 0
        for key, threats in groups.items():
            affected_paths = {t.site_path for t in threats}
            if len(affected_paths) < 2:
                continue

            cross_site_count += 1
            for threat in threats:
                threat.details["cross_site"] = sorted(affected_paths)
                threat.details["cross_site_count"] = len(affected_paths)

                # Escalate severity: a threat on multiple sites is at
                # least HIGH — indicates server-wide compromise.
                if threat.severity in (Severity.LOW, Severity.MEDIUM):
                    original = threat.severity.value
                    threat.severity = Severity.HIGH
                    threat.details["severity_escalated_from"] = original

        if cross_site_count:
            logger.warning(
                "Cross-site correlation: %d threat pattern(s) found on multiple sites",
                cross_site_count,
            )

    @staticmethod
    def _get_hostname() -> str:
        """Get the server hostname."""
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
