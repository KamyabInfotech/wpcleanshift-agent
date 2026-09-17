"""
CleanShift CLI Agent
~~~~~~~~~~~~~~~~~~~~~

Command-line interface for the CleanShift server agent.
Provides commands for scanning, cleaning, reporting, and
managing the agent's connection to the central API.

Usage:
    cleanshift scan [--site PATH] [--server] [--output json|markdown]
    cleanshift scan --post-migration <user_or_domain> [--json-output PATH]
    cleanshift clean --site PATH [--playbook NAME] [--dry-run] [--approve-all]
    cleanshift report --scan-id ID [--tier free|paid]
    cleanshift status
    cleanshift connect --api-url URL --api-key KEY

Exit codes:
    0 = clean (no threats found)
    1 = threats found
    2 = error (scan failed, invalid args, etc.)

Production hardening:
    - Lock file (/var/run/cleanshift.lock) prevents concurrent scans
    - Signal handling (SIGTERM/SIGINT → graceful shutdown)
    - --json-output /path/to/results.json option
    - --post-migration <user_or_domain> mode
    - --scan-mode quick|deep
    - Proper exit codes
"""

from __future__ import annotations

import atexit
try:
    import fcntl
    _FCNTL_AVAILABLE = True
except ImportError:
    _FCNTL_AVAILABLE = False
import json
import logging
import os
import re
import signal
import tarfile
import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import click
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text
    from rich import box
    import yaml
except ImportError as e:
    print('Missing dependency: %s. Run: pip install -r requirements.txt' % e)
    sys.exit(1)

from . import __version__
from .intelligence import IntelligenceDB
from .models import (
    RemediationMode,
    ReportTier,
    ScanResult,
    Severity,
    Threat,
    ThreatType,
)
from .scanner import ServerScanner, ScanMode
from .cleaner import RemediationEngine

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
from .reporter import ReportGenerator
from .alerter import TelegramAlerter
from .wp import discover_wp_sites
from .config_crypto import (
    is_encrypted,
    load_encrypted_config,
    save_encrypted_config,
    migrate_plaintext_config,
    decrypt_config_to_yaml,
    ConfigKeyMissing,
    ConfigDecryptionError,
    DEFAULT_KEY_PATH,
)

# ─── Exit Codes ─────────────────────────────────────────────────────

EXIT_CLEAN = 0       # No threats found
EXIT_THREATS = 1     # Threats detected
EXIT_ERROR = 2       # Scan/runtime error

# ─── Globals ────────────────────────────────────────────────────────

console = Console()
logger = logging.getLogger("cleanshift.agent")
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"
_DEFAULT_INTEL_DIR = Path(__file__).resolve().parent.parent.parent / "intelligence"
_LOCK_FILE_PATH = Path("/var/run/cleanshift.lock")
_DEFAULT_KEY_PATH = DEFAULT_KEY_PATH

# Severity colors for rich output
_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold bright_red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

# Global state for graceful shutdown
_shutdown_requested = False
_lock_fd = None


# ─── Lock File Management ──────────────────────────────────────────

def _acquire_lock(lock_path: Path = _LOCK_FILE_PATH) -> bool:
    """
    Acquire an exclusive lock file to prevent concurrent scans.

    Uses fcntl.flock for atomic locking. Falls back gracefully
    if /var/run is not writable (e.g. non-root, dev environment).

    Returns True if lock acquired, False if another scan is running.
    """
    global _lock_fd

    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        _lock_fd = open(lock_path, "w")
        if _FCNTL_AVAILABLE:
            fcntl.flock(_lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd.write(f"{os.getpid()}\n")
        _lock_fd.flush()
        atexit.register(_release_lock, lock_path)
        return True
    except (IOError, OSError, PermissionError) as e:
        if _lock_fd:
            try:
                _lock_fd.close()
            except Exception:
                pass
            _lock_fd = None
        # Check if it's a lock contention vs permission issue
        if isinstance(e, BlockingIOError) or (hasattr(e, 'errno') and e.errno == 11):
            # Lock is held by another process
            return False
        # Permission issue — try fallback lock paths
        if lock_path == _LOCK_FILE_PATH:
            for fallback in [
                Path("/opt/cleanshift/.lock"),
                Path("/tmp/.cleanshift.lock"),
            ]:
                result = _acquire_lock(fallback)
                if not result:
                    return False  # Another scan running
                if result:
                    return True
        # All fallbacks exhausted — warn and proceed without lock
        logging.getLogger("cleanshift.agent").warning(
            "Could not create lock file at %s: %s — proceeding without lock",
            lock_path, e,
        )
        return True


def _release_lock(lock_path: Path = _LOCK_FILE_PATH) -> None:
    """Release the exclusive lock file."""
    global _lock_fd
    if _lock_fd:
        try:
            if _FCNTL_AVAILABLE:
                fcntl.flock(_lock_fd.fileno(), fcntl.LOCK_UN)
            _lock_fd.close()
        except Exception:
            pass
        _lock_fd = None
    try:
        lock_path.unlink()
    except (OSError, PermissionError, FileNotFoundError):
        pass


# ─── Signal Handling ────────────────────────────────────────────────

def _setup_signal_handlers() -> None:
    """
    Install signal handlers for graceful shutdown.

    On SIGTERM/SIGINT, sets _shutdown_requested flag so the scan
    loop can exit cleanly and produce partial results.
    """
    def _handler(signum, frame):
        global _shutdown_requested
        _shutdown_requested = True
        # Don't call console.print or raise here — not async-signal-safe
        # and raising kills operations mid-flight (corrupt backups, leaked
        # DB connections). Let current operation finish, then exit.
        # Second signal forces immediate exit via default handler.
        signal.signal(signum, signal.SIG_DFL)

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def is_shutdown_requested() -> bool:
    """Check if a graceful shutdown has been requested."""
    return _shutdown_requested


# ─── Configuration ──────────────────────────────────────────────────

def load_config(config_path: Optional[Path] = None, key_path: Optional[Path] = None) -> dict:
    """Load agent configuration from YAML file (plaintext or encrypted)."""
    path = config_path or _DEFAULT_CONFIG_PATH
    kpath = key_path or _DEFAULT_KEY_PATH
    config = {
        "agent": {
            "agent_id": str(uuid.uuid4())[:8],
            "server_hostname": socket.gethostname(),
        },
        "scan": {
            "base_path": "auto",
            "exclude_paths": [],
        },
        "remediation": {
            "mode": "manual",
            "approval_required_for": ["delete_user", "reset_password", "drop_table"],
        },
        "api": {
            "url": "",
            "key": "",
        },
        "intelligence": {
            "directory": str(_DEFAULT_INTEL_DIR),
        },
        "telegram": {
            "bot_token": "",
            "chat_id": "",
            "topic_id": "",
        },
    }

    if path.exists():
        try:
            if is_encrypted(path):
                file_config = load_encrypted_config(path, kpath)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    file_config = yaml.safe_load(f) or {}
            # Deep merge
            _deep_merge(config, file_config)
        except (ConfigKeyMissing, ConfigDecryptionError) as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(EXIT_ERROR)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load config from {path}: {e}[/yellow]")

    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict into base dict."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        elif key in base and not isinstance(value, type(base[key])) and base[key] is not None:
            logger.warning("Config type mismatch for '%s': expected %s, got %s — skipping", key, type(base[key]).__name__, type(value).__name__)
            continue
        else:
            base[key] = value
    return base


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                show_path=verbose,
                rich_tracebacks=True,
                markup=True,
            ),
        ],
    )
    # Suppress noisy libraries
    logging.getLogger("pymysql").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# ─── CLI Banner ─────────────────────────────────────────────────────

def print_banner() -> None:
    """Display the CleanShift banner."""
    from . import __version__
    banner_text = Text()
    banner_text.append("CleanShift", style="bold bright_green")
    banner_text.append(f" v{__version__}\n", style="dim")
    banner_text.append("AI-Powered WordPress Security Agent", style="italic")

    console.print(Panel(
        banner_text,
        border_style="bright_green",
        padding=(0, 2),
        title="🛡️",
        title_align="left",
    ))


# ─── Click CLI Group ───────────────────────────────────────────────

@click.group()
@click.version_option(version=__version__, package_name='cleanshift')
@click.option("--config", "-c", type=click.Path(exists=False), default=None, help="Path to config file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbose: bool) -> None:
    """CleanShift — AI-powered security agent for web hosting."""
    ctx.ensure_object(dict)
    setup_logging(verbose)
    _setup_signal_handlers()
    ctx.obj["config"] = load_config(Path(config) if config else None)
    ctx.obj["verbose"] = verbose


# ─── Scan Command ───────────────────────────────────────────────────

@cli.command()
@click.option("--site", "-s", type=click.Path(), default=None, help="Path to a specific WordPress site")
@click.option("--server", is_flag=True, help="Scan all WordPress sites on the server")
@click.option("--output", "-o", type=click.Choice(["json", "markdown", "table"]), default="table", help="Output format")
@click.option("--save", type=click.Path(), default=None, help="Save report to file or directory")
@click.option("--tier", type=click.Choice(["free", "paid"]), default="free", help="Report tier")
@click.option("--json-output", type=click.Path(), default=None, help="Save JSON results to this path")
@click.option("--post-migration", type=str, default=None, help="Scan a specific user/domain's sites after migration (cPanel or Plesk)")
@click.option("--scan-mode", type=click.Choice(["quick", "deep"]), default="deep", help="Scan mode: quick (IOCs only) or deep (full analysis)")
@click.option("--no-telegram", is_flag=True, help="Disable Telegram alerts for this scan")
@click.option("--diff", "diff_file", type=click.Path(exists=True), default=None, help="Path to a previous scan JSON to diff against")
@click.option('--auto-patch', is_flag=True, help='Auto-update vulnerable plugins during scan')
@click.option('--all-cms', is_flag=True, help='Scan all CMS platforms (Joomla, Drupal, Magento, etc.), not just WordPress')
@click.option('--quick', 'quick_flag', is_flag=True, help='Shorthand for --scan-mode quick')
@click.option('--workers', type=int, default=None, help='Number of parallel workers for server scan (default: CPU count)')
@click.pass_context
def scan(
    ctx: click.Context,
    site: Optional[str],
    server: bool,
    output: str,
    save: Optional[str],
    tier: str,
    json_output: Optional[str],
    post_migration: Optional[str],
    scan_mode: str,
    no_telegram: bool,
    diff_file: Optional[str],
    auto_patch: bool,
    all_cms: bool,
    quick_flag: bool,
    workers: Optional[int],
) -> None:
    """Scan WordPress sites for security threats."""
    print_banner()
    config = ctx.obj["config"]

    # --quick shorthand overrides --scan-mode
    if quick_flag:
        scan_mode = 'quick'

    # Acquire lock to prevent concurrent scans
    if not _acquire_lock():
        console.print("[red]Error:[/red] Another CleanShift scan is already running.")
        console.print("[dim]Lock file: /var/run/cleanshift.lock[/dim]")
        sys.exit(EXIT_ERROR)

    # Parse scan mode
    mode = ScanMode.QUICK if scan_mode == "quick" else ScanMode.DEEP

    # Load intelligence
    intel_dir = config.get("intelligence", {}).get("directory", str(_DEFAULT_INTEL_DIR))
    intel = IntelligenceDB(Path(intel_dir))

    with console.status("[bold green]Loading intelligence database...", spinner="dots"):
        intel.load()

    console.print(f"[green]✓[/green] Intelligence loaded: {len(intel.malware_domains)} domains, "
                  f"{len(intel.backdoor_filenames)} backdoor patterns, "
                  f"{len(intel.vulnerable_plugins)} vulnerable plugins, "
                  f"{len(intel.detection_queries)} detection queries")
    console.print(f"[green]✓[/green] Scan mode: [bold]{mode.value}[/bold]")
    console.print()

    # Initialize scanner
    scanner = ServerScanner(
        intel=intel,
        agent_id=config.get("agent", {}).get("agent_id", ""),
        server_hostname=config.get("agent", {}).get("server_hostname", ""),
        scan_mode=mode,
        all_cms=all_cms,
    )

    # Check for pending scan requests from the dashboard
    api_url = config.get("api", {}).get("url", "")
    api_key = config.get("api", {}).get("key", "")
    if api_url and api_key:
        try:
            from .api_client import AgentAPIClient
            client = AgentAPIClient(api_url=api_url, api_key=api_key)
            pending = client.poll_pending_scans()
            if pending:
                console.print(f'[cyan]ℹ[/cyan]  {len(pending)} pending scan request(s) from dashboard')
                for req in pending:
                    client.ack_scan_request(req['id'])
                # If a pending request specified a scan type, use it
                if pending[0].get('scan_type'):
                    scan_mode = pending[0]['scan_type']
                    mode = ScanMode.QUICK if scan_mode == 'quick' else ScanMode.DEEP
        except Exception as e:
            logging.getLogger('cleanshift.agent').warning('Could not check pending scans: %s', e)

    result: Optional[ScanResult] = None

    try:
        # Run scan
        if post_migration:
            # Security: validate username to prevent path traversal
            if not re.match(r'^[a-zA-Z0-9._-]+$', post_migration):
                console.print('[red]Invalid username format for --post-migration[/red]')
                raise SystemExit(1)
            # Post-migration mode: scan a specific user's sites (cPanel or Plesk)
            user_home = Path(f"/home/{post_migration}")
            if not user_home.exists():
                # Try Plesk layout
                user_home = Path(f"/var/www/vhosts/{post_migration}")
            if not user_home.exists():
                console.print(f"[red]Error:[/red] User/domain directory not found.")
                console.print(f"[dim]Checked: /home/{post_migration} and /var/www/vhosts/{post_migration}[/dim]")
                sys.exit(EXIT_ERROR)

            console.print(f"[bold]Post-migration scan:[/bold] {post_migration} ({user_home})")
            console.print()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning user sites...", total=None)
                result = scanner.scan_user_home(post_migration)
                progress.update(task, completed=True, description="Post-migration scan complete")

        elif site:
            site_path = Path(site).resolve()
            is_wp = (site_path / "wp-config.php").exists()
            if not is_wp:
                if not all_cms:
                    console.print(f"[red]Error:[/red] No WordPress installation found at {site_path}")
                    console.print("[dim]To scan non-WordPress directories or generic PHP sites, run with the --all-cms flag.[/dim]")
                    sys.exit(EXIT_ERROR)
                else:
                    console.print(f"[yellow]Notice:[/yellow] No WordPress configuration found. Scanning directory as a generic site (--all-cms is active).")

            console.print(f"[bold]Scanning site:[/bold] {site_path}")
            console.print()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                result = scanner.scan_site(str(site_path))
                progress.update(task, completed=True, description="Scan complete")

        elif server:
            base_path = config.get("scan", {}).get("base_path", "auto")
            if base_path == "auto":
                try:
                    from .hosting import HostingDetector
                    base_path = HostingDetector.get_base_paths()[0]
                except (ImportError, IndexError):
                    base_path = "/home"
            exclude_paths = config.get("scan", {}).get("exclude_paths", [])

            console.print(f"[bold]Server-wide scan:[/bold] {base_path}")
            if all_cms:
                console.print("[bold cyan]🔍 All-CMS mode:[/bold cyan] scanning WordPress + Joomla, Drupal, Magento, and more")
            console.print()

            # Discover sites first
            with console.status("[bold green]Discovering WordPress sites...", spinner="dots"):
                wp_roots = discover_wp_sites(base_path)

            console.print(f"[green]✓[/green] Found {len(wp_roots)} WordPress site(s)")
            console.print()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning server...", total=None)
                if workers != 1:
                    from .parallel import ParallelScanner
                    parallel_scanner = ParallelScanner(
                        workers=workers,
                        intel=intel,
                        agent_id=config.get("agent", {}).get("agent_id", ""),
                        server_hostname=config.get("agent", {}).get("server_hostname", ""),
                        scan_mode=mode,
                        all_cms=all_cms,
                    )
                    result = parallel_scanner.scan_server(base_path, exclude_paths)
                else:
                    result = scanner.scan_server(base_path, exclude_paths)
                progress.update(task, completed=True, description="Server scan complete")
        else:
            console.print("[red]Error:[/red] Specify --site PATH, --server, or --post-migration USER")
            console.print("[dim]Use --site to scan a specific site, --server for all sites, or --post-migration for a user/domain.[/dim]")
            sys.exit(EXIT_ERROR)

    except Exception as e:
        console.print(f"[red]Error during scan:[/red] {e}")
        logging.getLogger("cleanshift.agent").error("Scan failed: %s", e, exc_info=True)
        sys.exit(EXIT_ERROR)

    if result is None:
        sys.exit(EXIT_ERROR)

    # Auto-patch vulnerable plugins if requested (rc.632: same entitlement as destructive clean)
    auto_patch_active = auto_patch or config.get("remediation", {}).get("auto_patch", False)
    if auto_patch_active and result and result.threats:
        try:
            from .license import LicenseValidator
            if not LicenseValidator.from_config(config).can_remediate():
                console.print(
                    "[yellow]Auto-patch skipped — not entitled on current plan "
                    "(scan results are still available).[/yellow]"
                )
                auto_patch_active = False
        except Exception as exc:
            logging.getLogger("cleanshift.agent").warning("Auto-patch license check failed — skipping patch: %s", exc)
            console.print(
                "[yellow]Auto-patch skipped — could not verify remediation entitlement.[/yellow]"
            )
            auto_patch_active = False
    if auto_patch_active and result and result.threats:
        vuln_count = sum(1 for t in result.threats if t.threat_type == ThreatType.VULNERABLE_PLUGIN)
        if vuln_count > 0:
            console.print(f"[bold yellow]Auto-patching {vuln_count} vulnerable plugin(s)...[/bold yellow]")
            try:
                patch_engine = RemediationEngine(
                    intel=intel,
                    mode=RemediationMode.AUTO,
                    auto_patch=True,
                )
                patch_actions = patch_engine.auto_patch_vulnerable_plugins(result)
                patched = sum(1 for a in patch_actions if a.status.value == 'completed')
                failed = sum(1 for a in patch_actions if a.status.value == 'failed')
                if patched > 0:
                    console.print(f"[green]\u2713[/green] Auto-patched {patched} plugin(s)")
                if failed > 0:
                    console.print(f"[yellow]\u26a0[/yellow]  Failed to patch {failed} plugin(s)")
                # Re-finalize the result since threats may have been removed
                result.finalize()
            except Exception as e:
                console.print(f"[yellow]\u26a0[/yellow]  Auto-patch failed: {e}")
                logging.getLogger("cleanshift.agent").error("Auto-patch failed: %s", e, exc_info=True)

    # Display results
    console.print()
    _display_scan_results(result, output, ReportTier(tier), save)

    # Save JSON output if requested
    if json_output:
        _save_json_output(result, json_output)

    # Submit anonymized threat telemetry to the central API
    api_url = config.get("api", {}).get("url", "")
    api_key = config.get("api", {}).get("key", "")
    if api_url and api_key and result and result.threats:
        try:
            from .telemetry import TelemetryCollector
            collector = TelemetryCollector(
                api_url=api_url,
                api_key=api_key,
                agent_version=__version__,
            )
            for threat in result.threats:
                _details = threat.details or {}
                collector.record(
                    filepath=threat.location,
                    threat_type=threat.threat_type.value if hasattr(threat.threat_type, "value") else str(threat.threat_type),
                    detection_method=_details.get("scanner", "heuristic"),
                    severity=threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
                    yara_rule=_details.get("rule_name", ""),
                    site_path=threat.site_path,
                )
            scan_type = "single" if site else ("migration" if post_migration else "full")
            collector.flush(scan_type=scan_type)
        except Exception as e:
            logging.getLogger("cleanshift.agent").warning("Could not submit threat telemetry: %s", e)

    # Submit scan results to central API
    if api_url and api_key and result:
        try:
            from .api_client import AgentAPIClient
            client = AgentAPIClient(api_url=api_url, api_key=api_key)
            # Build sites list from scan context
            sites_data = []
            if hasattr(result, 'sites') and result.sites:
                for site_info in result.sites:
                    sites_data.append({
                        'path': site_info.path,
                        'domain': site_info.domain,
                        'wp_version': site_info.wp_version,
                        'db_name': site_info.db_name,
                        'db_prefix': site_info.db_prefix,
                    })
            scan_type_str = 'single' if site else ('migration' if post_migration else 'full')
            submitted = client.submit_scan_result(result, sites_data, scan_type_str)
            if submitted:
                console.print('[green]✓[/green] Scan results submitted to CleanShift API')
            else:
                console.print('[yellow]⚠[/yellow]  Could not reach API — results buffered for next sync')
            # Flush any previously buffered results
            flushed = client.flush_buffer()
            if flushed:
                console.print(f'[green]✓[/green] Flushed {flushed} previously buffered result(s)')
        except Exception as e:
            logging.getLogger('cleanshift.agent').warning('Could not submit scan results: %s', e)

    # Send Telegram alerts (unless disabled)
    if not no_telegram:
        try:
            alerter = TelegramAlerter.from_config(config)
            if alerter.is_enabled:
                alerter.send_scan_summary(result)
                # Send individual alerts for critical/high threats
                for threat in result.threats:
                    if alerter.messages_remaining <= 0:
                        break
                    alerter.send_threat_alert(threat)
                console.print(f"[green]✓[/green] Telegram alerts sent ({alerter.max_messages_per_run - alerter.messages_remaining} messages)")
        except Exception as e:
            console.print(f"[dim]Telegram alerts skipped: {e}[/dim]")

    # Show diff against previous scan if --diff was provided
    if diff_file:
        _display_scan_diff(result, diff_file)

    # ── Auto-Remediate: scan → detect → clean in one pass ──
    rem_mode_str = config.get("remediation", {}).get("mode", "report-only")
    pre_clean_threat_count = len(result.threats) if result else 0
    if result.threats and rem_mode_str == "auto":
        remaining_threats = [
            t for t in result.threats
            if t.threat_type != ThreatType.VULNERABLE_PLUGIN  # Already handled by auto-patch
        ]
        if remaining_threats:
            console.print()
            console.print(f"[bold]Auto-remediation:[/bold] {len(remaining_threats)} threat(s) to clean")
            try:
                clean_engine = RemediationEngine(
                    intel=intel,
                    mode=RemediationMode.AUTO,
                    backup_before_clean=config.get("remediation", {}).get("backup_before_clean", True),
                )
                actions = clean_engine.remediate(result)
                completed = sum(1 for a in actions if a.status.value == "completed")
                failed = sum(1 for a in actions if a.status.value == "failed")
                skipped = sum(1 for a in actions if a.status.value == "skipped")
                pending = sum(1 for a in actions if a.status.value == "pending_approval")

                if completed > 0:
                    console.print(f"[green]✓[/green] Cleaned {completed} threat(s)")
                if failed > 0:
                    console.print(f"[red]✗[/red] Failed to clean {failed} threat(s)")
                if skipped > 0:
                    console.print(f"[dim]Skipped {skipped} (low confidence)[/dim]")
                if pending > 0:
                    console.print(f"[yellow]⚠[/yellow]  {pending} action(s) need manual approval — run: cleanshift clean --site <path> --mode manual")

                # ── Save remediation report to file ──
                report_content = clean_engine.generate_report()
                if report_content:
                    report_dir = Path("/var/log/wpcleanshift/reports")
                    report_dir.mkdir(parents=True, exist_ok=True)
                    report_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                    report_path = report_dir / f"remediation-{report_ts}.md"
                    try:
                        report_path.write_text(report_content, encoding="utf-8")
                        console.print(f"[dim]Remediation report saved: {report_path}[/dim]")
                    except Exception as e:
                        console.print(f"[dim]Could not save report: {e}[/dim]")

                # ── Verification Re-Scan ──
                # Re-scan to prove threats were actually removed
                if completed > 0:
                    console.print()
                    console.print("[bold]Verification re-scan:[/bold] confirming threats are gone...")
                    try:
                        verify_scanner = ServerScanner(
                            intel=intel,
                            scan_mode=ScanMode(scan_mode) if isinstance(scan_mode, str) else scan_mode,
                        )
                        verify_result = None
                        if site:
                            verify_result = verify_scanner.scan_site(site)
                        elif server:
                            verify_result = verify_scanner.scan_server(
                                base_path=config.get("scan", {}).get("base_path", "/home"),
                            )

                        if verify_result:
                            post_clean_threats = len(verify_result.threats)
                            removed = pre_clean_threat_count - post_clean_threats
                            if post_clean_threats == 0:
                                console.print(f"[bold green]✓ VERIFIED:[/bold green] All {pre_clean_threat_count} threats cleaned — site is clean!")
                            elif removed > 0:
                                console.print(f"[yellow]Partial clean:[/yellow] {removed}/{pre_clean_threat_count} threats removed, {post_clean_threats} remain")
                                for t in verify_result.threats:
                                    console.print(f"  [red]→[/red] {t.severity.value}: {t.title} ({t.location})")
                            else:
                                console.print(f"[red]✗ Cleaning may not have worked:[/red] {post_clean_threats} threats still detected")

                            # Save verification result
                            if json_output:
                                verify_path = str(json_output).replace(".json", "-verified.json")
                                _save_json_output(verify_result, verify_path)
                                console.print(f"[dim]Verification scan saved: {verify_path}[/dim]")

                    except Exception as e:
                        console.print(f"[yellow]⚠[/yellow]  Verification scan failed: {e}")
                        logging.getLogger("cleanshift.agent").error("Verification scan failed: %s", e, exc_info=True)

            except Exception as e:
                console.print(f"[yellow]⚠[/yellow]  Auto-remediation failed: {e}")
                logging.getLogger("cleanshift.agent").error("Auto-remediation failed: %s", e, exc_info=True)

    # Determine exit code based on threats
    if result.threats:
        sys.exit(EXIT_THREATS)
    else:
        sys.exit(EXIT_CLEAN)


def _load_scan_result_from_json(json_path: str) -> ScanResult:
    """Load and reconstruct a ScanResult from a JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    reconstructed_threats = []
    for td in data.get("threats", []):
        try:
            reconstructed_threats.append(Threat(
                id=td.get("id", ""),
                threat_type=ThreatType(td.get("threat_type", "backdoor_file")),
                severity=Severity(td.get("severity", "medium")),
                title=td.get("title", ""),
                description=td.get("description", ""),
                location=td.get("location", ""),
                evidence=td.get("evidence", ""),
                site_path=td.get("site_path", ""),
                cve=td.get("cve"),
                details=td.get("details", {}),
                confidence=td.get("confidence", 1.0),
            ))
        except (ValueError, KeyError) as exc:
            logging.getLogger("cleanshift.agent").warning(
                "Skipping malformed threat in diff JSON: %s", exc,
            )

    from .models import WordPressSite
    sites = []
    for sd in data.get("sites", []):
        sites.append(WordPressSite(
            path=sd.get("path", ""),
            domain=sd.get("domain", ""),
            wp_version=sd.get("wp_version", ""),
        ))

    return ScanResult(
        id=data.get("id", ""),
        agent_id=data.get("agent_id", ""),
        server_hostname=data.get("server_hostname", ""),
        scan_started=data.get("scan_started", ""),
        scan_completed=data.get("scan_completed", ""),
        summary=data.get("summary", {}),
        threats=reconstructed_threats,
        sites=sites,
    )


def _display_scan_diff(current: ScanResult, previous_json: str) -> None:
    """Load a previous scan result from JSON, compute diff, and display it."""
    try:
        previous = _load_scan_result_from_json(previous_json)
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not load previous scan for diff: {e}")
        return

    diff = ScanResult.diff(previous, current)

    console.print()
    console.print(Panel(
        f"[bold]Scan Diff[/bold] — comparing against {Path(previous_json).name}\n\n"
        f"🆕 New threats: [bold]{len(diff['new_threats'])}[/bold]\n"
        f"✅ Resolved threats: [bold]{len(diff['resolved_threats'])}[/bold]\n"
        f"➕ Sites added: [bold]{len(diff['sites_added'])}[/bold]\n"
        f"➖ Sites removed: [bold]{len(diff['sites_removed'])}[/bold]",
        title="📊 Diff Results",
        border_style="cyan",
    ))

    if diff["new_threats"]:
        console.print()
        new_table = Table(title="🆕 New Threats", box=box.ROUNDED, show_lines=True)
        new_table.add_column("Type", width=18)
        new_table.add_column("Title", min_width=30)
        new_table.add_column("Location", min_width=20)
        new_table.add_column("Severity", width=10)
        for t in diff["new_threats"]:
            new_table.add_row(
                t.get("threat_type", ""),
                t.get("title", "")[:50],
                t.get("location", "")[:40],
                t.get("severity", "").upper(),
            )
        console.print(new_table)

    if diff["resolved_threats"]:
        console.print()
        resolved_table = Table(title="✅ Resolved Threats", box=box.ROUNDED, show_lines=True)
        resolved_table.add_column("Type", width=18)
        resolved_table.add_column("Title", min_width=30)
        resolved_table.add_column("Location", min_width=20)
        for t in diff["resolved_threats"]:
            resolved_table.add_row(
                t.get("threat_type", ""),
                t.get("title", "")[:50],
                t.get("location", "")[:40],
            )
        console.print(resolved_table)

    if diff["sites_added"]:
        console.print()
        for s in diff["sites_added"]:
            console.print(f"  [green]+[/green] {s}")

    if diff["sites_removed"]:
        console.print()
        for s in diff["sites_removed"]:
            console.print(f"  [red]-[/red] {s}")


def _save_json_output(result: ScanResult, output_path: str) -> None:
    """Save scan results as JSON to the specified path.

    Uses os.open with O_CREAT|O_TRUNC and mode 0o600 so the file is
    *never* world-readable, not even momentarily.
    """
    try:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        json_content = json.dumps(result.to_dict(), indent=2, default=str)
        # M6: Atomic creation — file is born with 0o600, never world-readable
        fd = os.open(str(output_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(json_content)
        except BaseException:
            # fd is closed by os.fdopen even on error; re-raise
            raise
        console.print(f"[green]✓[/green] JSON results saved to {output_file}")
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not save JSON output: {e}")


def _display_scan_results(
    result: ScanResult,
    output_format: str,
    tier: ReportTier,
    save_path: Optional[str],
) -> None:
    """Display scan results in the chosen format."""
    if output_format == "json":
        reporter = ReportGenerator(tier=tier)
        json_output = reporter.generate_json(result)
        if save_path:
            Path(save_path).write_text(json_output, encoding="utf-8")
            console.print(f"[green]✓[/green] JSON report saved to {save_path}")
        else:
            console.print_json(json_output)

    elif output_format == "markdown":
        reporter = ReportGenerator(tier=tier)
        md_output = reporter.generate(result)
        if save_path:
            save_file = reporter.save(md_output, Path(save_path))
            console.print(f"[green]✓[/green] Markdown report saved to {save_file}")
        else:
            console.print(md_output)

    else:
        # Rich table output (default)
        _display_results_table(result)

        # Save if requested
        if save_path:
            reporter = ReportGenerator(tier=tier)
            md_output = reporter.generate(result)
            save_file = reporter.save(md_output, Path(save_path))
            console.print(f"\n[green]✓[/green] Report saved to {save_file}")


def _display_results_table(result: ScanResult) -> None:
    """Display scan results as rich tables."""
    # Summary panel
    total = len(result.threats)
    by_sev = result.summary.get("threats_by_severity", {})

    if total == 0:
        console.print(Panel(
            "[bold green]✅ No threats detected![/bold green]\n"
            f"Scanned {len(result.sites)} site(s)",
            title="Scan Result",
            border_style="green",
        ))
        return

    # Build summary
    summary_parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = by_sev.get(sev, 0)
        if count > 0:
            icon = _SEVERITY_ICONS.get(Severity(sev), "")
            summary_parts.append(f"{icon} {count} {sev.upper()}")

    summary_text = " • ".join(summary_parts)

    console.print(Panel(
        f"[bold]{total} threat(s) detected[/bold] across "
        f"{result.summary.get('sites_with_threats', 0)} of {len(result.sites)} site(s)\n\n"
        f"{summary_text}\n\n"
        f"[dim]Scan completed in {result.summary.get('scan_duration_seconds', 0):.1f}s[/dim]",
        title="⚠️ Scan Result",
        border_style="red" if by_sev.get("critical", 0) > 0 else "yellow",
    ))
    console.print()

    # Threats table
    table = Table(
        title="Detected Threats",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=12)
    table.add_column("Type", width=18)
    table.add_column("Title", min_width=30)
    table.add_column("Site", width=20)
    table.add_column("CVE", width=16)

    sorted_threats = sorted(
        result.threats,
        key=lambda t: (list(Severity).index(t.severity), t.threat_type.value),
    )

    for i, threat in enumerate(sorted_threats, 1):
        icon = _SEVERITY_ICONS.get(threat.severity, "")
        sev_style = _SEVERITY_STYLES.get(threat.severity, "")
        sev_label = f"{icon} {threat.severity.value.upper()}"

        type_labels = {
            ThreatType.ROGUE_ADMIN: "Rogue Admin",
            ThreatType.BACKDOOR_FILE: "Backdoor",
            ThreatType.DB_MARKER: "DB Marker",
            ThreatType.SCRIPT_INJECTION: "Script Injection",
            ThreatType.VULNERABLE_PLUGIN: "Vuln Plugin",
            ThreatType.CORE_MODIFIED: "Core Modified",
            ThreatType.PERMISSION_ISSUE: "Permissions",
            ThreatType.SUSPICIOUS_FILE: "Suspicious File",
        }

        site_name = Path(threat.site_path).name if threat.site_path else ""

        table.add_row(
            str(i),
            Text(sev_label, style=sev_style),
            type_labels.get(threat.threat_type, threat.threat_type.value),
            threat.title[:50],
            site_name,
            threat.cve or "",
        )

    console.print(table)

    # Sites table
    if result.sites:
        console.print()
        sites_table = Table(
            title="Scanned Sites",
            box=box.SIMPLE,
            title_style="bold",
        )
        sites_table.add_column("Path", min_width=30)
        sites_table.add_column("WordPress", width=12)
        sites_table.add_column("Plugins", width=10, justify="right")
        sites_table.add_column("Threats", width=10, justify="right")

        for site in result.sites:
            threat_count = sum(1 for t in result.threats if t.site_path == site.path)
            style = "red" if threat_count > 0 else "green"

            sites_table.add_row(
                site.path,
                site.wp_version,
                str(len(site.plugins)),
                Text(str(threat_count), style=style),
            )

        console.print(sites_table)

    # Non-WordPress CMS sites table
    if hasattr(result, 'non_wp_sites') and result.non_wp_sites:
        console.print()
        nw_table = Table(
            title="Non-WordPress Sites (All-CMS)",
            box=box.SIMPLE,
            title_style="bold cyan",
        )
        nw_table.add_column("Path", min_width=30)
        nw_table.add_column("Platform", width=14)
        nw_table.add_column("Version", width=12)
        nw_table.add_column("Confidence", width=12, justify="right")
        nw_table.add_column("Threats", width=10, justify="right")

        for nw_site in result.non_wp_sites:
            threat_count = sum(1 for t in result.threats if t.site_path == nw_site.path)
            style = "red" if threat_count > 0 else "green"

            nw_table.add_row(
                nw_site.path,
                nw_site.platform_type.title(),
                nw_site.version or "unknown",
                f"{nw_site.detection_confidence:.0%}",
                Text(str(threat_count), style=style),
            )

        console.print(nw_table)


# ─── Clean Command ──────────────────────────────────────────────────

@cli.command()
@click.option("--site", "-s", type=click.Path(exists=True), default=None, help="Path to WordPress site")
@click.option("--server", is_flag=True, help="Discover and clean all WordPress sites on the server")
@click.option("--playbook", "-p", type=str, default=None, help="Specific playbook to run")
@click.option("--dry-run", is_flag=True, help="Show what would happen without executing")
@click.option("--approve-all", is_flag=True, help="Auto-approve all actions (dangerous!)")
@click.option(
    "--approve-destructive",
    is_flag=True,
    default=False,
    help="Auto-approve destructive actions (delete_user, reset_password, drop_table). Requires --approve-all.",
)
@click.option("--mode", type=click.Choice(["auto", "manual", "report-only"]), default=None, help="Remediation mode")
@click.option("--scan-mode", type=click.Choice(["quick", "deep"]), default="deep", help="Scan mode: quick (IOCs only) or deep (full analysis)")
@click.pass_context
def clean(
    ctx: click.Context,
    site: Optional[str],
    server: bool,
    playbook: Optional[str],
    dry_run: bool,
    approve_all: bool,
    approve_destructive: bool,
    mode: Optional[str],
    scan_mode: str,
) -> None:
    """Run remediation on a WordPress site or all sites on the server."""
    print_banner()
    config = ctx.obj["config"]

    # Validate: --site and --server are mutually exclusive, one is required
    if site and server:
        console.print("[red]Error:[/red] --site and --server are mutually exclusive.")
        sys.exit(EXIT_ERROR)
    if not site and not server:
        console.print("[red]Error:[/red] Specify --site PATH or --server.")
        console.print("[dim]Use --site to clean a specific site, --server for all sites on the server.[/dim]")
        sys.exit(EXIT_ERROR)

    # Acquire lock
    if not _acquire_lock():
        console.print("[red]Error:[/red] Another CleanShift scan is already running.")
        sys.exit(EXIT_ERROR)

    # Determine mode
    if mode:
        mode_map = {
            "auto": RemediationMode.AUTO,
            "manual": RemediationMode.MANUAL,
            "report-only": RemediationMode.REPORT_ONLY,
        }
        rem_mode = mode_map.get(mode, RemediationMode.REPORT_ONLY)
    else:
        config_mode = config.get("remediation", {}).get("mode", "report-only")
        rem_mode = RemediationMode(config_mode) if config_mode in [m.value for m in RemediationMode] else RemediationMode.REPORT_ONLY

    # Warning for dangerous options
    if approve_all and not dry_run:
        console.print(Panel(
            "[bold red]⚠️ WARNING: --approve-all is enabled![/bold red]\n"
            "All remediation actions will execute without confirmation.\n"
            "This includes deleting user accounts and files.",
            border_style="red",
        ))
        if not click.confirm("Are you sure you want to continue?"):
            sys.exit(EXIT_CLEAN)

    if dry_run:
        console.print("[yellow]ℹ️  Dry-run mode — no changes will be made[/yellow]\n")

    # Load intelligence
    intel_dir = config.get("intelligence", {}).get("directory", str(_DEFAULT_INTEL_DIR))
    intel = IntelligenceDB(Path(intel_dir))
    intel.load()

    if server:
        _clean_server(ctx, config, intel, rem_mode, playbook, dry_run, approve_all, approve_destructive, scan_mode)
    else:
        _clean_single_site(ctx, config, intel, rem_mode, site, playbook, dry_run, approve_all, approve_destructive, scan_mode)


def _clean_single_site(
    ctx: click.Context,
    config: dict,
    intel: IntelligenceDB,
    rem_mode: RemediationMode,
    site: str,
    playbook: Optional[str],
    dry_run: bool,
    approve_all: bool,
    approve_destructive: bool = False,
    scan_mode: str = "deep",
) -> None:
    """Run scan + remediation on a single WordPress site."""
    site_path = Path(site).resolve()
    if not (site_path / "wp-config.php").exists():
        console.print(f"[red]Error:[/red] No WordPress installation at {site_path}")
        sys.exit(EXIT_ERROR)

    # Step 1: Scan first
    console.print(f"[bold]Step 1:[/bold] Scanning for threats...")
    scanner = ServerScanner(
        intel=intel,
        agent_id=config.get("agent", {}).get("agent_id", ""),
        scan_mode=ScanMode(scan_mode),
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        scan_result = scanner.scan_site(str(site_path))
        progress.update(task, completed=True, description="Scan complete")

    _display_results_table(scan_result)
    console.print()

    if not scan_result.threats:
        console.print("[green]No threats found — nothing to remediate.[/green]")
        sys.exit(EXIT_CLEAN)

    # Step 2: Remediate
    console.print(f"[bold]Step 2:[/bold] Remediating threats (mode: {rem_mode.value})...")
    console.print()

    def approval_callback(action) -> bool:
        """Interactive approval prompt."""
        console.print(Panel(
            f"[bold]Action:[/bold] {action.action_type}\n"
            f"[bold]Target:[/bold] {action.target}\n"
            f"[bold]Command:[/bold] `{action.command}`",
            title="🔒 Approval Required",
            border_style="yellow",
        ))
        return click.confirm("  Approve this action?")

    engine = RemediationEngine(
        intel=intel,
        mode=rem_mode,
        dry_run=dry_run,
        approve_all=approve_all,
        approve_destructive=approve_destructive,
        approval_callback=approval_callback if not approve_all else None,
    )

    actions = engine.remediate(
        scan_result,
        site_path=str(site_path),
        playbook_name=playbook,
    )

    # Display results
    console.print()
    if actions:
        actions_table = Table(
            title="Remediation Actions",
            box=box.ROUNDED,
            show_lines=True,
        )
        actions_table.add_column("#", width=4)
        actions_table.add_column("Action", width=18)
        actions_table.add_column("Target", min_width=25)
        actions_table.add_column("Status", width=20)

        status_styles = {
            "completed": "green",
            "failed": "red",
            "skipped": "dim",
            "pending": "yellow",
            "requires_approval": "yellow",
        }

        for i, action in enumerate(actions, 1):
            style = status_styles.get(action.status.value, "")
            actions_table.add_row(
                str(i),
                action.action_type,
                action.target[:40],
                Text(action.status.value, style=style),
            )

        console.print(actions_table)

        # Generate and save remediation report
        report_md = engine.generate_report()
        report_path = site_path / f".cleanshift-remediation-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
        report_path.write_text(report_md, encoding="utf-8")
        console.print(f"\n[green]✓[/green] Remediation report saved to {report_path}")

        # Exit with threats code since we had threats
        sys.exit(EXIT_THREATS)
    else:
        console.print("[dim]No remediation actions were taken.[/dim]")
        sys.exit(EXIT_THREATS)


def _clean_server(
    ctx: click.Context,
    config: dict,
    intel: IntelligenceDB,
    rem_mode: RemediationMode,
    playbook: Optional[str],
    dry_run: bool,
    approve_all: bool,
    approve_destructive: bool = False,
    scan_mode: str = "deep",
) -> None:
    """Discover all WordPress sites on the server, scan and remediate each."""
    base_path = config.get("scan", {}).get("base_path", "auto")
    if base_path == "auto":
        try:
            from .hosting import HostingDetector
            base_path = HostingDetector.get_base_paths()[0]
        except (ImportError, IndexError):
            base_path = "/home"

    console.print(f"[bold]Server-wide clean:[/bold] {base_path}")
    console.print()

    # Discover sites
    with console.status("[bold green]Discovering WordPress sites...", spinner="dots"):
        wp_roots = discover_wp_sites(base_path)

    if not wp_roots:
        console.print("[yellow]No WordPress sites found.[/yellow]")
        sys.exit(EXIT_CLEAN)

    console.print(f"[green]✓[/green] Found {len(wp_roots)} WordPress site(s)")
    console.print()

    scanner = ServerScanner(
        intel=intel,
        agent_id=config.get("agent", {}).get("agent_id", ""),
        scan_mode=ScanMode(scan_mode),
    )

    all_actions: list = []
    all_engines: list = []
    sites_with_threats = 0
    total_threats = 0

    for idx, wp_root in enumerate(wp_roots, 1):
        site_path = Path(wp_root)
        console.print(f"\n[bold]── Site {idx}/{len(wp_roots)}: {site_path} ──[/bold]")

        # Scan
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {site_path.name}...", total=None)
            scan_result = scanner.scan_site(str(site_path))
            progress.update(task, completed=True, description=f"Scan complete: {len(scan_result.threats)} threat(s)")

        if not scan_result.threats:
            console.print(f"  [green]✓[/green] No threats found")
            continue

        sites_with_threats += 1
        total_threats += len(scan_result.threats)

        # Remediate
        def approval_callback(action) -> bool:
            """Interactive approval prompt."""
            console.print(Panel(
                f"[bold]Action:[/bold] {action.action_type}\n"
                f"[bold]Target:[/bold] {action.target}\n"
                f"[bold]Command:[/bold] `{action.command}`",
                title="🔒 Approval Required",
                border_style="yellow",
            ))
            return click.confirm("  Approve this action?")

        engine = RemediationEngine(
            intel=intel,
            mode=rem_mode,
            dry_run=dry_run,
            approve_all=approve_all,
            approve_destructive=approve_destructive,
            approval_callback=approval_callback if not approve_all else None,
        )

        actions = engine.remediate(
            scan_result,
            site_path=str(site_path),
            playbook_name=playbook,
        )

        if actions:
            all_actions.extend(actions)
            all_engines.append((site_path, engine))
            completed = sum(1 for a in actions if a.status.value == "completed")
            failed = sum(1 for a in actions if a.status.value == "failed")
            console.print(f"  [green]✓ {completed} completed[/green], [red]{failed} failed[/red] of {len(actions)} action(s)")

    # Consolidated summary
    console.print(f"\n{'─' * 60}")
    console.print(Panel(
        f"[bold]Sites scanned:[/bold] {len(wp_roots)}\n"
        f"[bold]Sites with threats:[/bold] {sites_with_threats}\n"
        f"[bold]Total threats:[/bold] {total_threats}\n"
        f"[bold]Total actions:[/bold] {len(all_actions)}\n"
        f"[bold]Completed:[/bold] {sum(1 for a in all_actions if a.status.value == 'completed')}\n"
        f"[bold]Failed:[/bold] {sum(1 for a in all_actions if a.status.value == 'failed')}\n"
        f"[bold]Skipped/Pending:[/bold] {sum(1 for a in all_actions if a.status.value in ('skipped', 'pending', 'requires_approval'))}",
        title="🛡️ Server-Wide Clean Summary",
        border_style="bright_green" if not all_actions else "yellow",
    ))

    # Save consolidated reports per-site
    for site_path, engine in all_engines:
        report_md = engine.generate_report()
        report_path = site_path / f".cleanshift-remediation-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
        try:
            report_path.write_text(report_md, encoding="utf-8")
            console.print(f"[green]✓[/green] Report saved: {report_path}")
        except OSError as e:
            console.print(f"[yellow]Warning:[/yellow] Could not save report for {site_path}: {e}")

    if total_threats > 0:
        sys.exit(EXIT_THREATS)
    else:
        sys.exit(EXIT_CLEAN)


# ─── Report Command ────────────────────────────────────────────────

@cli.command()
@click.option("--scan-file", "-f", type=click.Path(exists=True), required=True, help="Path to scan result JSON file")
@click.option("--tier", type=click.Choice(["free", "paid"]), default="free", help="Report tier")
@click.option("--output", "-o", type=click.Choice(["markdown", "json"]), default="markdown", help="Output format")
@click.option("--save", type=click.Path(), default=None, help="Save report to file")
@click.pass_context
def report(
    ctx: click.Context,
    scan_file: str,
    tier: str,
    output: str,
    save: Optional[str],
) -> None:
    """Generate a report from scan results."""
    print_banner()

    # Load scan results from JSON
    try:
        with open(scan_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error:[/red] Could not load scan results: {e}")
        sys.exit(EXIT_ERROR)

    # Reconstruct ScanResult with threats from JSON data
    threats_data = data.get("threats", [])
    reconstructed_threats = []
    for td in threats_data:
        try:
            reconstructed_threats.append(Threat(
                id=td.get("id", ""),
                threat_type=ThreatType(td.get("threat_type", "backdoor_file")),
                severity=Severity(td.get("severity", "medium")),
                title=td.get("title", ""),
                description=td.get("description", ""),
                location=td.get("location", ""),
                evidence=td.get("evidence", ""),
                site_path=td.get("site_path", ""),
                cve=td.get("cve"),
                details=td.get("details", {}),
                confidence=td.get("confidence", 1.0),
            ))
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed threat in JSON: %s", exc)

    result = ScanResult(
        id=data.get("id", ""),
        agent_id=data.get("agent_id", ""),
        server_hostname=data.get("server_hostname", ""),
        scan_started=data.get("scan_started", ""),
        scan_completed=data.get("scan_completed", ""),
        summary=data.get("summary", {}),
        threats=reconstructed_threats,
    )

    reporter = ReportGenerator(tier=ReportTier(tier))

    if output == "json":
        content = reporter.generate_json(result)
    else:
        content = reporter.generate(result)

    if save:
        save_file = reporter.save(content, Path(save), format=output)
        console.print(f"[green]✓[/green] Report saved to {save_file}")
    else:
        console.print(content)


# ─── Status Command ────────────────────────────────────────────────

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show agent status and configuration."""
    print_banner()
    config = ctx.obj["config"]

    # Agent info
    info_table = Table(title="Agent Status", box=box.ROUNDED)
    info_table.add_column("Setting", style="bold")
    info_table.add_column("Value")

    info_table.add_row("Agent ID", config.get("agent", {}).get("agent_id", "not set"))
    info_table.add_row("Hostname", config.get("agent", {}).get("server_hostname", socket.gethostname()))
    info_table.add_row("Scan Base Path", config.get("scan", {}).get("base_path", "/home"))
    info_table.add_row("Remediation Mode", config.get("remediation", {}).get("mode", "manual"))

    api_url = config.get("api", {}).get("url", "")
    api_status = "[green]Connected[/green]" if api_url else "[dim]Not configured[/dim]"
    info_table.add_row("API Connection", api_status)
    if api_url:
        info_table.add_row("API URL", api_url)

    intel_dir = config.get("intelligence", {}).get("directory", str(_DEFAULT_INTEL_DIR))
    info_table.add_row("Intelligence Dir", intel_dir)

    # Lock status (with PID-based stale detection)
    if _LOCK_FILE_PATH.exists():
        try:
            pid = int(_LOCK_FILE_PATH.read_text().strip())
            # Check if PID is still alive
            try:
                os.kill(pid, 0)  # Signal 0 = check existence only
                info_table.add_row("Lock Status", f"[yellow]Locked (PID: {pid})[/yellow]")
            except OSError:
                # PID is dead — stale lock
                info_table.add_row("Lock Status", f"[red]Stale lock (PID {pid} dead) — auto-cleaning[/red]")
                try:
                    _LOCK_FILE_PATH.unlink()
                except OSError:
                    pass
        except (ValueError, Exception):
            info_table.add_row("Lock Status", "[yellow]Locked[/yellow]")
    else:
        info_table.add_row("Lock Status", "[green]Unlocked[/green]")

    console.print(info_table)

    # Intelligence status
    console.print()
    try:
        intel = IntelligenceDB(Path(intel_dir))
        intel.load()

        intel_table = Table(title="Intelligence Database", box=box.SIMPLE)
        intel_table.add_column("Category", style="bold")
        intel_table.add_column("Count", justify="right")

        intel_table.add_row("Malware Domains", str(len(intel.malware_domains)))
        intel_table.add_row("Rogue Admin Patterns", str(len(intel.rogue_admin_patterns)))
        intel_table.add_row("DB Markers", str(len(intel.db_markers)))
        intel_table.add_row("Backdoor Patterns", str(len(intel.backdoor_filenames)))
        intel_table.add_row("Vulnerable Plugins", str(len(intel.vulnerable_plugins)))
        intel_table.add_row("Detection Queries", str(len(intel.detection_queries)))
        intel_table.add_row("Playbooks", str(len(intel.playbooks)))

        console.print(intel_table)

        if intel.playbooks:
            console.print()
            for name, pb in intel.playbooks.items():
                console.print(
                    f"  [bold]Playbook:[/bold] {name} — "
                    f"{pb.description} "
                    f"[dim]({len(pb.phases)} phases)[/dim]"
                )

    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not load intelligence: {e}")

    # Discover sites (quick count)
    console.print()
    base_path = config.get("scan", {}).get("base_path", "/home")
    if Path(base_path).exists():
        try:
            sites = discover_wp_sites(base_path)
            console.print(f"[green]✓[/green] {len(sites)} WordPress site(s) found under {base_path}")
        except Exception:
            console.print(f"[dim]Could not discover sites under {base_path}[/dim]")
    else:
        console.print(f"[dim]Base path {base_path} not accessible[/dim]")


# ─── Connect Command ───────────────────────────────────────────────

@cli.command()
@click.option("--api-url", required=True, help="Central API URL")
@click.option("--api-key", required=True, help="API authentication key")
@click.pass_context
def connect(ctx: click.Context, api_url: str, api_key: str) -> None:
    """Configure connection to the central CleanShift API."""
    print_banner()

    config_path = _DEFAULT_CONFIG_PATH
    was_encrypted = is_encrypted(config_path)

    # Load existing config or create new
    if config_path.exists():
        if was_encrypted:
            try:
                config = load_encrypted_config(config_path, _DEFAULT_KEY_PATH)
            except (ConfigKeyMissing, ConfigDecryptionError) as e:
                console.print(f"[red]Error:[/red] {e}")
                sys.exit(EXIT_ERROR)
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
    else:
        config = {}

    # Update API settings
    if "api" not in config:
        config["api"] = {}
    config["api"]["url"] = api_url
    config["api"]["key"] = api_key

    # Save — preserve encryption if config was previously encrypted
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if was_encrypted:
        save_encrypted_config(config, config_path, _DEFAULT_KEY_PATH)
    else:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        # Restrict permissions — config contains API key
        try:
            os.chmod(str(config_path), 0o600)
        except OSError:
            pass

    console.print(f"[green]✓[/green] API connection configured")
    console.print(f"  URL: {api_url}")
    console.print(f"  Key: {'*' * (len(api_key) - 4) + api_key[-4:]}")
    console.print(f"\n  Config saved to: {config_path}")
    if was_encrypted:
        console.print("  [dim](encrypted at rest)[/dim]")

    # TODO: Test connection via WebSocket
    console.print("\n[dim]Note: WebSocket connection to API will be established on next scan.[/dim]")


# ─── Telegram CLI Commands ──────────────────────────────────────────

@cli.group()
def telegram() -> None:
    """Configure Telegram alerting."""
    pass


@telegram.command("setup")
@click.option("--bot-token", prompt="Bot Token", help="Telegram Bot API token from @BotFather")
@click.option("--chat-id", prompt="Chat ID", help="Telegram chat/group/channel ID")
@click.option("--topic-id", default="", help="Optional topic/thread ID for forum groups")
@click.pass_context
def telegram_setup(
    ctx: click.Context,
    bot_token: str,
    chat_id: str,
    topic_id: str,
) -> None:
    """Set up Telegram alerts (interactive or via flags)."""
    print_banner()

    config_path = _DEFAULT_CONFIG_PATH
    was_encrypted = is_encrypted(config_path)

    # Load existing config
    if config_path.exists():
        if was_encrypted:
            try:
                config = load_encrypted_config(config_path, _DEFAULT_KEY_PATH)
            except (ConfigKeyMissing, ConfigDecryptionError) as e:
                console.print(f"[red]Error:[/red] {e}")
                sys.exit(EXIT_ERROR)
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
    else:
        config = {}

    # Update telegram settings
    config["telegram"] = {
        "bot_token": bot_token.strip(),
        "chat_id": chat_id.strip(),
        "topic_id": topic_id.strip() or "",
        "max_messages_per_run": config.get("telegram", {}).get("max_messages_per_run", 10),
    }

    # Save — preserve encryption if config was previously encrypted
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if was_encrypted:
        save_encrypted_config(config, config_path, _DEFAULT_KEY_PATH)
    else:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        try:
            os.chmod(str(config_path), 0o600)
        except OSError:
            pass

    console.print(f"[green]✓[/green] Telegram configured")
    console.print(f"  Chat ID: {chat_id}")
    console.print(f"  Token: {'*' * (len(bot_token) - 4)}{bot_token[-4:]}")
    if topic_id:
        console.print(f"  Topic ID: {topic_id}")
    console.print(f"\n  Config saved to: {config_path}")
    if was_encrypted:
        console.print("  [dim](encrypted at rest)[/dim]")

    # Offer to send a test message
    if click.confirm("\n  Send a test message now?", default=True):
        _send_telegram_test(config)


@telegram.command("test")
@click.pass_context
def telegram_test(ctx: click.Context) -> None:
    """Send a test message to verify Telegram is working."""
    print_banner()

    config_path = _DEFAULT_CONFIG_PATH
    if not config_path.exists():
        console.print("[red]Error:[/red] No config found. Run `cleanshift telegram setup` first.")
        sys.exit(EXIT_ERROR)

    if is_encrypted(config_path):
        try:
            config = load_encrypted_config(config_path, _DEFAULT_KEY_PATH)
        except (ConfigKeyMissing, ConfigDecryptionError) as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(EXIT_ERROR)
    else:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    _send_telegram_test(config)


def _send_telegram_test(config: dict) -> None:
    """Send a test message via Telegram."""
    import socket
    from datetime import datetime, timezone

    alerter = TelegramAlerter.from_config(config)
    if not alerter.is_enabled:
        console.print("[red]Error:[/red] Telegram not configured (missing bot_token or chat_id)")
        return

    hostname = socket.gethostname()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    test_msg = (
        f"✅ *CleanShift Test Message*\n\n"
        f"🖥 Server: `{TelegramAlerter._escape_md(hostname)}`\n"
        f"📅 Time: {TelegramAlerter._escape_md(now)}\n\n"
        f"Telegram alerting is working\\!"
    )

    success = alerter._send_message(test_msg, parse_mode="MarkdownV2")
    if success:
        console.print("[green]✓[/green] Test message sent successfully!")
    else:
        console.print("[red]✗[/red] Failed to send test message. Check token/chat_id.")


# ─── Intelligence Sync Controls ────────────────────────────────────


@cli.group()
def intel():
    """Intelligence database sync controls."""
    pass


@intel.command("sync")
@click.option("--api-url", default=None, help="Override API URL for intelligence sync")
@click.option("--api-key", default=None, help="API key for authenticated downloads")
@click.option("--force", is_flag=True, help="Force sync even if no updates detected")
@click.pass_context
def intel_sync(ctx: click.Context, api_url: Optional[str], api_key: Optional[str], force: bool) -> None:
    """Sync intelligence files from the central API."""
    print_banner()
    config = ctx.obj["config"]

    from .intel_sync import IntelligenceSyncClient

    # Resolve parameters from config or CLI overrides
    url = api_url or config.get("api", {}).get("url", "")
    key = api_key or config.get("api", {}).get("key", "")
    intel_dir = config.get("intelligence", {}).get("directory", str(_DEFAULT_INTEL_DIR))

    if not url:
        console.print("[red]Error:[/red] No API URL configured.")
        console.print("[dim]Set it in config.yaml under api.url or pass --api-url[/dim]")
        sys.exit(EXIT_ERROR)

    client = IntelligenceSyncClient(
        api_url=url,
        intel_dir=intel_dir,
        api_key=key if key else None,
    )

    console.print(f"[bold]Intelligence Sync[/bold]")
    console.print(f"  API: {url}")
    console.print(f"  Dir: {intel_dir}")
    console.print()

    with console.status("[bold green]Checking for updates...", spinner="dots"):
        has_updates = client.check_for_updates()

    if not has_updates and not force:
        console.print("[green]✓[/green] Intelligence is already up-to-date.")
        return

    if not has_updates and force:
        console.print("[yellow]ℹ️  Force sync requested[/yellow]")

    with console.status("[bold green]Syncing intelligence files...", spinner="dots"):
        result = client.sync()

    # Display results
    console.print()
    if result["downloaded"]:
        console.print(f"[green]✓[/green] Downloaded {len(result['downloaded'])} file(s):")
        for f in result["downloaded"]:
            console.print(f"  [green]+[/green] {f}")
    if result["skipped"]:
        console.print(f"[dim]Skipped {len(result['skipped'])} unchanged file(s)[/dim]")
    if result["errors"]:
        console.print(f"[red]✗[/red] {len(result['errors'])} error(s):")
        for err in result["errors"]:
            console.print(f"  [red]✗[/red] {err['name']}: {err['error']}")

    console.print()
    if result["version"]:
        console.print(f"[bold]Version:[/bold] {result['version']}")
    console.print(f"[bold]Synced at:[/bold] {result['synced_at']}")


@intel.command("status")
@click.pass_context
def intel_status(ctx: click.Context) -> None:
    """Show current intelligence version and last sync time."""
    print_banner()
    config = ctx.obj["config"]

    from .intel_sync import IntelligenceSyncClient

    url = config.get("api", {}).get("url", "")
    intel_dir = config.get("intelligence", {}).get("directory", str(_DEFAULT_INTEL_DIR))

    client = IntelligenceSyncClient(
        api_url=url or "https://not-configured",
        intel_dir=intel_dir,
    )

    status_info = client.get_status()

    table = Table(title="Intelligence Status", box=box.ROUNDED)
    table.add_column("Property", style="bold", min_width=20)
    table.add_column("Value", min_width=40)

    table.add_row("Intel Directory", status_info["intel_dir"])
    table.add_row("API URL", status_info["api_url"])
    table.add_row("Last Sync", status_info["last_sync"])
    table.add_row("Last Version", status_info["last_version"])
    table.add_row("Last Hash", status_info["last_hash"][:16] + "…" if len(status_info["last_hash"]) > 16 else status_info["last_hash"])
    table.add_row("Local Files", str(status_info["local_files"]))
    table.add_row("Files Downloaded (last sync)", str(status_info["files_last_downloaded"]))

    console.print(table)


# ─── File Watcher Controls ──────────────────────────────────────────

@cli.group()
def watch():
    """Real-time file watcher daemon controls."""
    pass



@watch.command("start")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (not as systemd service)")
@click.option("--base-path", default=None, help="Override base path for site discovery")
@click.pass_context
def watch_start(ctx: click.Context, foreground: bool, base_path: Optional[str]) -> None:
    """Start the real-time file watcher daemon."""
    print_banner()

    if foreground:
        # Run the watcher in the foreground (for debugging)
        try:
            from .watcher import WatcherDaemon

            config = ctx.obj["config"]
            bp = base_path or config.get("scan", {}).get("base_path", "/home")
            if bp == "auto":
                bp = "/home"

            tg_config = config.get("telegram", {})
            daemon = WatcherDaemon(
                base_path=bp,
                bot_token=tg_config.get("bot_token", ""),
                chat_id=tg_config.get("chat_id", ""),
            )
            console.print("[green]✓[/green] Starting watcher in foreground (Ctrl+C to stop)...")
            daemon.run()
        except KeyboardInterrupt:
            console.print("\n[yellow]Watcher stopped.[/yellow]")
        except ImportError as e:
            console.print(f"[red]✗[/red] Could not import watcher: {e}")
    else:
        # Start via systemd
        import subprocess
        svc = "cleanshift-watcher"
        try:
            subprocess.run(["systemctl", "start", svc], check=True, capture_output=True)
            subprocess.run(["systemctl", "enable", svc], check=True, capture_output=True)
            console.print(f"[green]✓[/green] Watcher started and enabled ({svc}.service)")
            console.print("[dim]View logs: journalctl -u cleanshift-watcher -f[/dim]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to start watcher service: {e}")
            console.print("[dim]Try: cleanshift watch start --foreground[/dim]")
        except FileNotFoundError:
            console.print("[red]✗[/red] systemctl not found — use --foreground mode")


@watch.command("stop")
def watch_stop() -> None:
    """Stop the real-time file watcher daemon."""
    import subprocess
    svc = "cleanshift-watcher"
    try:
        subprocess.run(["systemctl", "stop", svc], check=True, capture_output=True)
        console.print(f"[green]✓[/green] Watcher stopped ({svc}.service)")
    except subprocess.CalledProcessError:
        console.print(f"[yellow]⚠[/yellow]  Watcher service was not running")
    except FileNotFoundError:
        console.print("[red]✗[/red] systemctl not found")


@watch.command("status")
def watch_status() -> None:
    """Check the real-time file watcher status."""
    import subprocess
    svc = "cleanshift-watcher"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", svc],
            capture_output=True, text=True,
        )
        state = result.stdout.strip()
        if state == "active":
            console.print(f"[green]✓[/green] Watcher is running ({svc}.service)")
            # Show basic stats
            result2 = subprocess.run(
                ["systemctl", "show", svc, "--property=MainPID,MemoryCurrent"],
                capture_output=True, text=True,
            )
            for line in result2.stdout.strip().split("\n"):
                if "=" in line:
                    key, val = line.split("=", 1)
                    if key == "MainPID" and val != "0":
                        console.print(f"  PID: {val}")
                    elif key == "MemoryCurrent" and val not in ("[not set]", ""):
                        try:
                            mem_mb = int(val) / (1024 * 1024)
                            console.print(f"  Memory: {mem_mb:.1f} MB")
                        except (ValueError, TypeError):
                            pass
        elif state == "inactive":
            console.print(f"[yellow]⚠[/yellow]  Watcher is stopped")
            console.print("[dim]Start with: cleanshift watch start[/dim]")
        else:
            console.print(f"[red]✗[/red] Watcher status: {state}")
    except FileNotFoundError:
        console.print("[yellow]⚠[/yellow]  systemctl not found — watcher may be running in foreground mode")
        # Check for running process
        try:
            result = subprocess.run(
                ["pgrep", "-f", "watcher"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                console.print(f"[green]✓[/green] Watcher process found (PID: {result.stdout.strip()})")
            else:
                console.print("[yellow]⚠[/yellow]  No watcher process found")
        except FileNotFoundError:
            pass


# ─── Worker Command ───────────────────────────────────────────────

@cli.command("worker")
@click.pass_context
def worker(ctx: click.Context) -> None:
    """Start the background task worker to process dashboard commands."""
    print_banner()
    config = ctx.obj["config"]
    api_url = config.get("api", {}).get("url", "")
    api_key = config.get("api", {}).get("key", "")

    if not api_url or not api_key:
        console.print("[red]✗[/red] API not configured. Set api.url and api.key in config.yaml.")
        sys.exit(1)

    # Resolve the server_id and agent_id from the API using our agent key
    server_id = None
    agent_id = ""
    try:
        from .api_client import AgentAPIClient
        client = AgentAPIClient(api_url=api_url, api_key=api_key)
        agent_info = client._request("GET", "/agents/me")
        if agent_info:
            server_id = agent_info.get("server_id")
            agent_id = agent_info.get("id", "")
            console.print(f"[green]✓[/green] Agent identified: {agent_info.get('name', '?')} (server {server_id[:8]}...)")
    except Exception as e:
        logging.getLogger("cleanshift.agent").warning("Could not resolve server_id: %s", e)

    if not server_id:
        # Fallback: use agent_id from config
        server_id = config.get("agent", {}).get("agent_id", "unknown")
        console.print(f"[yellow]⚠[/yellow]  Using fallback server_id: {server_id}")

    try:
        from .task_worker import TaskWorker
        worker = TaskWorker(
            api_url=api_url,
            api_key=api_key,
            server_id=server_id,
            agent_id=agent_id,
            poll_interval=15,
        )
        console.print(f"[green]✓[/green] Worker started — polling every 15s for remediation tasks")
        worker.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Worker stopped.[/yellow]")
    except ImportError as e:
        console.print(f"[red]✗[/red] Could not start worker: {e}")


# ─── Reputation Command ─────────────────────────────────────────────

@cli.command()
@click.option("--domains", "-d", multiple=True, help="Domain(s) to check (can specify multiple)")
@click.option("--json-output", type=click.Path(), default=None, help="Save JSON results to this path")
@click.option("--server-ip", type=str, default=None, help="Override auto-detected server IP")
@click.pass_context
def reputation(ctx: click.Context, domains: tuple, json_output: Optional[str], server_ip: Optional[str]) -> None:
    """Check server and domain reputation against DNSBL/SURBL blocklists."""
    print_banner()

    from .reputation import ReputationChecker

    checker = ReputationChecker()

    # Collect domains from arguments and from discovered WP sites
    domain_list = list(domains)

    if not domain_list:
        # Try to discover domains from WP sites on the server
        config = ctx.obj["config"]
        try:
            intel_dir = config.get("intelligence", {}).get("directory", str(_DEFAULT_INTEL_DIR))
            intel = IntelligenceDB(Path(intel_dir))
            intel.load()
            base_path = config.get("scan", {}).get("base_path", "auto")
            if base_path == "auto":
                try:
                    from .hosting import HostingDetector
                    base_path = HostingDetector.get_base_paths()[0]
                except (ImportError, IndexError):
                    base_path = "/home"
            wp_roots = discover_wp_sites(base_path)
            for root in wp_roots[:20]:  # Cap at 20 domains
                try:
                    from .wp import build_site_info
                    site = build_site_info(root)
                    if site.domain:
                        d = site.domain.replace('https://', '').replace('http://', '').split('/')[0]
                        if d and d not in domain_list:
                            domain_list.append(d)
                except Exception:
                    pass
        except Exception as e:
            console.print(f"[dim]Could not auto-discover domains: {e}[/dim]")

    with console.status("[bold green]Checking reputation...", spinner="dots"):
        report = checker.check_server(domains=domain_list if domain_list else None)

    # Override server IP if specified
    if server_ip:
        report.server_ip = server_ip
        with console.status("[bold green]Checking overridden IP...", spinner="dots"):
            ip_results = checker.check_ip(server_ip)
            report.results = ip_results + [r for r in report.results if r.target != report.server_ip]
            report.finalize()

    # Display results
    console.print()
    console.print(Panel(
        f"[bold]Server:[/bold] {report.server_hostname} ({report.server_ip})\n"
        f"[bold]Domains checked:[/bold] {len(report.domains_checked)}\n"
        f"[bold]Total checks:[/bold] {report.summary.get('total_checks', 0)}\n"
        f"[bold]Listings found:[/bold] {report.summary.get('listings_found', 0)}",
        title="\U0001f50d Reputation Check",
        border_style="cyan" if report.summary.get('clean', False) else "red",
    ))

    # Results table
    table = Table(title="Blocklist Results", box=box.ROUNDED, show_lines=True)
    table.add_column("Target", min_width=20)
    table.add_column("Blocklist", min_width=20)
    table.add_column("Status", width=10)
    table.add_column("Details", min_width=30)

    for r in report.results:
        if r.error:
            status = "[yellow]ERROR[/yellow]"
            details = r.error
        elif r.listed:
            status = "[red]LISTED[/red]"
            details = f"{r.meaning} ({r.return_code})"
        else:
            status = "[green]CLEAN[/green]"
            details = ""

        table.add_row(r.target, r.blocklist, status, details)

    console.print(table)

    # Summary
    if report.summary.get('clean', False):
        console.print("\n[green]\u2713 Server reputation is clean[/green]")
    else:
        listings = report.summary.get('listings_found', 0)
        if listings > 0:
            console.print(f"\n[red]\u2717 Found {listings} blocklist listing(s) \u2014 action required[/red]")
        else:
            console.print("\n[green]\u2713 No listings found[/green]")

    # Save JSON if requested
    if json_output:
        import json as json_mod
        output_path = Path(json_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json_mod.dump(report.to_dict(), f, indent=2)
        console.print(f"\n[green]\u2713[/green] Results saved to {output_path}")


# ─── Guard Emergency Controls ──────────────────────────────────────

@cli.group()
def guard():
    """Emergency guard controls (disable/enable/status)."""
    pass


_KILL_SWITCH_PATH = Path("/var/run/cleanshift/.cleanshift-disable")
_ERROR_COUNT_PATH = Path("/var/run/cleanshift/.cleanshift-error-count")


@guard.command()
def disable():
    """Emergency-disable the guard on all sites (touch kill switch)."""
    click.confirm(
        'This will disable the security guard on ALL WordPress sites. Continue?',
        abort=True,
    )
    try:
        _KILL_SWITCH_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KILL_SWITCH_PATH.touch()
        console.print(f"[yellow]⚠[/yellow]  Guard DISABLED — kill switch active at {_KILL_SWITCH_PATH}")
        console.print("[dim]Run 'cleanshift guard enable' to re-enable[/dim]")
    except OSError as e:
        console.print(f"[red]✗[/red] Could not create kill switch: {e}")


@guard.command()
def enable():
    """Re-enable the guard (remove kill switch)."""
    removed = []
    for f in [_KILL_SWITCH_PATH, _ERROR_COUNT_PATH]:
        if f.exists():
            try:
                f.unlink()
                removed.append(str(f))
            except OSError:
                pass
    if removed:
        console.print(f"[green]✓[/green] Guard re-enabled — removed: {', '.join(removed)}")
    else:
        console.print("[green]✓[/green] Guard was already enabled (no kill switch found)")


@guard.command("status")
def guard_status():
    """Check guard kill switch and error counter status."""
    if _KILL_SWITCH_PATH.exists():
        console.print("[red]✗[/red] Guard is DISABLED (kill switch active)")
    elif _ERROR_COUNT_PATH.exists():
        try:
            count = int(_ERROR_COUNT_PATH.read_text().strip())
            if count >= 5:
                console.print(f"[red]✗[/red] Guard is AUTO-DISABLED ({count} consecutive errors)")
            else:
                console.print(f"[yellow]⚠[/yellow]  Guard has {count}/5 error(s) before auto-disable")
        except (ValueError, OSError):
            console.print("[green]✓[/green] Guard is active")
    else:
        console.print("[green]✓[/green] Guard is active — no errors")


# ─── Restore Command ───────────────────────────────────────────────

@cli.command()
@click.option('--backup-id', '-b', type=str, required=False, default=None, help='Backup ID to restore from')
@click.option('--list', 'list_backups', is_flag=True, help='List available backups')
@click.option('--dry-run', is_flag=True, help='Show what would be restored without doing it')
@click.pass_context
def restore(ctx: click.Context, backup_id: Optional[str], list_backups: bool, dry_run: bool) -> None:
    """Restore a site from a pre-remediation backup."""
    print_banner()
    config = ctx.obj["config"]

    # Discover all backup directories across known base paths
    base_path = config.get("scan", {}).get("base_path", "auto")
    if base_path == "auto":
        try:
            from .hosting import HostingDetector
            base_path = HostingDetector.get_base_paths()[0]
        except (ImportError, IndexError):
            base_path = "/home"

    backup_entries = _discover_backups(base_path)

    if not backup_entries:
        console.print("[yellow]No backups found.[/yellow]")
        console.print(f"[dim]Searched under: {base_path}[/dim]")
        sys.exit(EXIT_CLEAN)

    # --list: display all available backups and exit
    if list_backups:
        table = Table(
            title="Available Backups",
            box=box.ROUNDED,
            show_lines=True,
            title_style="bold",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Backup ID", min_width=20)
        table.add_column("Site", min_width=20)
        table.add_column("Date", width=22)
        table.add_column("Size", width=12, justify="right")
        table.add_column("Path", min_width=30)

        for i, entry in enumerate(backup_entries, 1):
            table.add_row(
                str(i),
                entry["id"],
                entry["site_name"],
                entry["date"],
                entry["size"],
                str(entry["path"]),
            )

        console.print(table)
        console.print(f"\n[dim]Use: cleanshift restore --backup-id <ID> [--dry-run][/dim]")
        return

    # Restore requires --backup-id
    if not backup_id:
        console.print("[red]Error:[/red] Specify --backup-id or use --list to see available backups.")
        sys.exit(EXIT_ERROR)

    # Find the matching backup
    match = None
    for entry in backup_entries:
        if entry["id"] == backup_id or entry["id"].startswith(backup_id):
            match = entry
            break

    if not match:
        console.print(f"[red]Error:[/red] No backup found with ID: {backup_id}")
        console.print("[dim]Use --list to see available backups.[/dim]")
        sys.exit(EXIT_ERROR)

    backup_path = match["path"]
    site_name = match["site_name"]
    restore_target = backup_path.parent.parent / site_name

    console.print(Panel(
        f"[bold]Backup:[/bold] {backup_path.name}\n"
        f"[bold]Site:[/bold] {site_name}\n"
        f"[bold]Date:[/bold] {match['date']}\n"
        f"[bold]Size:[/bold] {match['size']}\n"
        f"[bold]Restore to:[/bold] {restore_target}",
        title="🔄 Restore Details",
        border_style="cyan",
    ))

    # Show what would be restored (list archive contents)
    if dry_run:
        console.print("\n[yellow]ℹ️  Dry-run mode — listing archive contents only[/yellow]\n")
        try:
            with tarfile.open(str(backup_path), "r:gz") as tar:
                members = tar.getmembers()
                files_table = Table(
                    title="Files in Backup",
                    box=box.SIMPLE,
                    title_style="bold",
                )
                files_table.add_column("Type", width=6)
                files_table.add_column("Path", min_width=40)
                files_table.add_column("Size", width=12, justify="right")

                display_limit = 50
                for member in members[:display_limit]:
                    ftype = "dir" if member.isdir() else "file"
                    fsize = f"{member.size:,}" if member.isfile() else "-"
                    files_table.add_row(
                        ftype,
                        member.name,
                        fsize,
                    )

                console.print(files_table)

                if len(members) > display_limit:
                    console.print(f"\n[dim]... and {len(members) - display_limit} more file(s)[/dim]")

                console.print(f"\n[bold]Total:[/bold] {len(members)} entries")
        except Exception as e:
            console.print(f"[red]Error reading backup:[/red] {e}")
            sys.exit(EXIT_ERROR)
        return

    # Actual restore — confirm first
    console.print()
    if not click.confirm("⚠️  This will overwrite files in the site directory. Continue?"):
        console.print("[dim]Restore cancelled.[/dim]")
        return

    console.print()
    with console.status("[bold green]Restoring from backup...", spinner="dots"):
        try:
            with tarfile.open(str(backup_path), "r:gz") as tar:
                # Security: validate tar members to prevent path traversal
                dest_resolved = restore_target.parent.resolve()
                safe_members = []
                for member in tar.getmembers():
                    member_path = Path(member.name)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        logger.warning(
                            "Unsafe path in backup archive: %s — skipping",
                            member.name,
                        )
                        continue
                    if member.issym() or member.islnk():
                        logger.warning(
                            "Skipping symlink in backup archive: %s",
                            member.name,
                        )
                        continue
                    resolved = (dest_resolved / member_path).resolve()
                    if not str(resolved).startswith(str(dest_resolved) + os.sep) and resolved != dest_resolved:
                        logger.warning(
                            "Path escape in archive: %s -> %s — skipping",
                            member.name, resolved,
                        )
                        continue
                    safe_members.append(member)

                tar.extractall(path=str(restore_target.parent), members=safe_members)

            console.print(f"[green]✓[/green] Restore complete: {len(safe_members)} entries restored")
            console.print(f"[green]✓[/green] Site restored to: {restore_target}")
        except Exception as e:
            console.print(f"[red]Error during restore:[/red] {e}")
            logger.error("Restore failed: %s", e, exc_info=True)
            sys.exit(EXIT_ERROR)


def _discover_backups(base_path: str) -> list:
    """
    Discover all .cleanshift-backups directories and enumerate backup files.

    Returns a list of dicts with keys: id, site_name, date, size, path.
    """
    backups = []
    base = Path(base_path)

    if not base.exists():
        return backups

    # Search for .cleanshift-backups directories (up to 3 levels deep)
    try:
        for backup_dir in base.rglob(".cleanshift-backups"):
            if not backup_dir.is_dir():
                continue
            for backup_file in sorted(backup_dir.glob("pre-remediation-*.tar.gz"), reverse=True):
                try:
                    stat = backup_file.stat()
                    size_mb = stat.st_size / (1024 * 1024)
                    size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{stat.st_size / 1024:.1f} KB"

                    # Parse site name and timestamp from filename
                    # Format: pre-remediation-{site_name}-{YYYYMMDD_HHMMSS}.tar.gz
                    stem = backup_file.name.replace(".tar.gz", "")
                    parts = stem.replace("pre-remediation-", "", 1)
                    # Last part is timestamp (YYYYMMDD_HHMMSS)
                    segments = parts.rsplit("-", 1)
                    if len(segments) == 2:
                        site_name = segments[0]
                        ts_raw = segments[1]
                    else:
                        site_name = parts
                        ts_raw = ""

                    # Format date
                    if len(ts_raw) == 15:  # YYYYMMDD_HHMMSS
                        try:
                            dt = datetime.strptime(ts_raw, "%Y%m%d_%H%M%S")
                            date_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        except ValueError:
                            date_str = ts_raw
                    else:
                        date_str = ts_raw or "unknown"

                    # Generate a short ID from the filename
                    backup_id = f"{site_name}-{ts_raw}" if ts_raw else stem

                    backups.append({
                        "id": backup_id,
                        "site_name": site_name,
                        "date": date_str,
                        "size": size_str,
                        "path": backup_file,
                    })
                except OSError:
                    continue
    except PermissionError:
        pass

    return backups


# ─── False Positive Reporting Command ──────────────────────────────

_FP_REPORTS_DIR = Path("/opt/cleanshift/fp-reports")


@cli.command('report-fp')
@click.option('--scan-file', '-f', type=click.Path(exists=True), required=True, help='Path to scan JSON output')
@click.option('--threat-id', '-t', type=str, required=True, help='Threat ID to report as false positive')
@click.option('--reason', '-r', type=str, default='', help='Why this is a false positive')
@click.pass_context
def report_false_positive(ctx: click.Context, scan_file: str, threat_id: str, reason: str) -> None:
    """Report a scan finding as a false positive."""
    print_banner()
    config = ctx.obj["config"]

    # Load the scan JSON
    try:
        with open(scan_file, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error:[/red] Could not load scan file: {e}")
        sys.exit(EXIT_ERROR)

    # Find the threat by ID
    threats = scan_data.get("threats", [])
    matched_threat = None
    for t in threats:
        if t.get("id", "") == threat_id or t.get("id", "").startswith(threat_id):
            matched_threat = t
            break

    if not matched_threat:
        console.print(f"[red]Error:[/red] Threat ID '{threat_id}' not found in scan results.")
        console.print(f"[dim]Available threat IDs:[/dim]")
        for t in threats[:20]:
            console.print(f"  [dim]{t.get('id', 'N/A')}[/dim] — {t.get('title', 'untitled')}")
        sys.exit(EXIT_ERROR)

    # Build FP report
    fp_report = {
        "id": str(uuid.uuid4()),
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "scan_file": str(Path(scan_file).resolve()),
        "scan_id": scan_data.get("id", ""),
        "agent_id": scan_data.get("agent_id", config.get("agent", {}).get("agent_id", "")),
        "server_hostname": scan_data.get("server_hostname", socket.gethostname()),
        "threat": {
            "id": matched_threat.get("id", ""),
            "threat_type": matched_threat.get("threat_type", ""),
            "severity": matched_threat.get("severity", ""),
            "title": matched_threat.get("title", ""),
            "description": matched_threat.get("description", ""),
            "location": matched_threat.get("location", ""),
            "evidence": matched_threat.get("evidence", "")[:500],
            "site_path": matched_threat.get("site_path", ""),
            "confidence": matched_threat.get("confidence", 1.0),
        },
        "reason": reason,
        "status": "pending",
    }

    # Save to local FP reports directory
    try:
        _FP_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_filename = f"fp-{fp_report['id'][:8]}-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        report_path = _FP_REPORTS_DIR / report_filename
        fd = os.open(str(report_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(fp_report, f, indent=2, default=str)
        except BaseException:
            raise
        console.print(f"[green]✓[/green] FP report saved to {report_path}")
    except PermissionError:
        # Fall back to a user-writable location
        fallback_dir = Path("/tmp/cleanshift-fp-reports")
        fallback_dir.mkdir(parents=True, exist_ok=True)
        report_filename = f"fp-{fp_report['id'][:8]}-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        report_path = fallback_dir / report_filename
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(fp_report, f, indent=2, default=str)
        console.print(f"[yellow]⚠[/yellow]  Could not write to {_FP_REPORTS_DIR}, saved to {report_path}")
    except Exception as e:
        console.print(f"[red]Error:[/red] Could not save FP report: {e}")
        sys.exit(EXIT_ERROR)

    # Display confirmation
    console.print()
    console.print(Panel(
        f"[bold]Report ID:[/bold] {fp_report['id'][:8]}\n"
        f"[bold]Threat:[/bold] {matched_threat.get('title', '')}\n"
        f"[bold]Type:[/bold] {matched_threat.get('threat_type', '')}\n"
        f"[bold]Location:[/bold] {matched_threat.get('location', '')}\n"
        f"[bold]Reason:[/bold] {reason or '(none provided)'}",
        title="📋 False Positive Report",
        border_style="cyan",
    ))

    # Try to POST to API if configured
    api_url = config.get("api", {}).get("url", "")
    api_key = config.get("api", {}).get("key", "")

    if api_url:
        endpoint = f"{api_url.rstrip('/')}/threats/{threat_id}/status"
        console.print(f"\n[dim]Submitting to API: {endpoint}[/dim]")
        try:
            if not _REQUESTS_AVAILABLE:
                console.print("[yellow]⚠[/yellow]  'requests' library not available — skipping API submission")
            else:
                headers = {"Content-Type": "application/json"}
                if api_key:
                    headers["X-API-Key"] = api_key
                resp = _requests.patch(
                    endpoint,
                    json={"remediation_status": "false_positive", "reason": reason},
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code in (200, 201):
                    console.print(f"[green]✓[/green] FP report submitted to API (HTTP {resp.status_code})")
                    fp_report["status"] = "submitted"
                else:
                    console.print(f"[yellow]⚠[/yellow]  API returned HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow]  Could not submit to API: {e}")
            console.print("[dim]The report has been saved locally and can be submitted later.[/dim]")
    else:
        console.print("\n[dim]No API configured — report saved locally only.[/dim]")
        console.print("[dim]Configure API with: cleanshift connect --api-url URL --api-key KEY[/dim]")


# ─── Doctor Command ─────────────────────────────────────────────────

@cli.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Run system health checks and report status."""
    print_banner()
    config = ctx.obj.get("config", {})

    table = Table(
        title="CleanShift System Health Check",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        pad_edge=True,
    )
    table.add_column("Check", style="white", min_width=30)
    table.add_column("Status", justify="center", min_width=8)
    table.add_column("Details", style="dim")

    issues = 0
    warnings = 0

    def _pass(check: str, detail: str = "") -> None:
        table.add_row(check, "[green]✅[/green]", detail)

    def _warn(check: str, detail: str = "") -> None:
        nonlocal warnings
        warnings += 1
        table.add_row(check, "[yellow]⚠️[/yellow]", f"[yellow]{detail}[/yellow]")

    def _fail(check: str, detail: str = "") -> None:
        nonlocal issues
        issues += 1
        table.add_row(check, "[red]❌[/red]", f"[red]{detail}[/red]")

    # 1. Python version
    import sys
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        _pass("Python version", py_ver)
    else:
        _fail("Python version", f"{py_ver} (requires >= 3.8)")

    # 2. Required dependencies
    missing_deps = []
    for mod_name in ["click", "yaml", "rich"]:
        try:
            __import__(mod_name)
        except ImportError:
            missing_deps.append(mod_name)
    optional_missing = []
    for mod_name in ["pymysql", "requests"]:
        try:
            __import__(mod_name)
        except ImportError:
            optional_missing.append(mod_name)
    if missing_deps:
        _fail("Required dependencies", f"Missing: {', '.join(missing_deps)}")
    elif optional_missing:
        _pass("Required dependencies", f"OK (optional missing: {', '.join(optional_missing)})")
    else:
        _pass("Required dependencies", "All installed")

    # 3. Config file
    config_path = Path("/opt/cleanshift/config.yaml")
    alt_paths = [Path.home() / ".cleanshift" / "config.yaml", Path("/etc/cleanshift/config.yaml"),
                 _DEFAULT_CONFIG_PATH]
    found_config = None
    for p in [config_path] + alt_paths:
        if p.exists():
            found_config = p
            break
    if found_config:
        try:
            import yaml
            with open(found_config) as f:
                yaml.safe_load(f)
            _pass("Config file", str(found_config))
        except Exception as e:
            _fail("Config file", f"{found_config} — invalid YAML: {e}")
    else:
        _warn("Config file", "Not found (using defaults)")

    # 4. Intelligence database
    try:
        from .intelligence import IntelligenceDB
        intel = IntelligenceDB()
        intel.load()
        bd_count = len(intel.backdoor_filenames)
        ioc_count = len(getattr(intel, 'ioc_hashes', []))
        _pass("Intelligence database", f"{bd_count} backdoor patterns, {ioc_count} IoC hashes")
    except Exception as e:
        _fail("Intelligence database", str(e))

    # 5. Lock file
    lock_path = Path("/var/run/cleanshift.lock")
    if lock_path.exists():
        try:
            lock_age_s = time.time() - lock_path.stat().st_mtime
            if lock_age_s > 3600:
                _warn("Lock file", f"Stale lock ({lock_age_s / 3600:.1f}h old) — remove: {lock_path}")
            else:
                _warn("Lock file", f"Active scan in progress ({lock_age_s:.0f}s old)")
        except OSError:
            _warn("Lock file", "Exists but cannot read — check permissions")
    else:
        _pass("Lock file", "No active lock")

    # 6. API connectivity
    api_url = config.get("api", {}).get("url") or config.get("api_url") or os.environ.get("CLEANSHIFT_API_URL", "")
    if api_url:
        try:
            import urllib.request
            req = urllib.request.Request(f"{api_url.rstrip('/')}/health", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    import json as _json
                    body = _json.loads(resp.read())
                    _pass("API connectivity", f"{api_url} — {body.get('status', 'ok')} v{body.get('version', '?')}")
                else:
                    _warn("API connectivity", f"{api_url} — HTTP {resp.status}")
        except Exception as e:
            _fail("API connectivity", f"{api_url} — {e}")
    else:
        _warn("API connectivity", "No API URL configured")

    # 7. Disk space
    try:
        st = os.statvfs("/")
        free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
        if free_gb < 1.0:
            _fail("Disk space", f"{free_gb:.1f} GB free (< 1 GB)")
        elif free_gb < 5.0:
            _warn("Disk space", f"{free_gb:.1f} GB free")
        else:
            _pass("Disk space", f"{free_gb:.1f} GB free")
    except (OSError, AttributeError):
        _warn("Disk space", "Cannot check (statvfs unavailable)")

    # 8. Guard plugin status
    guard_source = Path("/opt/cleanshift/guard/wpcleanshift-guard.php")
    if not guard_source.exists():
        # Check alternate locations
        alt_guard = Path(__file__).parent.parent.parent / "guard" / "wpcleanshift-guard.php"
        if alt_guard.exists():
            guard_source = alt_guard
    if guard_source.exists():
        _pass("Guard plugin", f"Available at {guard_source}")
    else:
        _warn("Guard plugin", "Guard source not found")

    # 9. Systemd watcher service
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "cleanshift-watcher"],
            capture_output=True, text=True, timeout=5,
        )
        svc_status = result.stdout.strip()
        if svc_status == "active":
            _pass("Watcher service", "cleanshift-watcher is running")
        elif svc_status == "inactive":
            _warn("Watcher service", "cleanshift-watcher is inactive")
        else:
            _warn("Watcher service", f"cleanshift-watcher: {svc_status}")
    except FileNotFoundError:
        _warn("Watcher service", "systemctl not available")
    except Exception:
        _warn("Watcher service", "Cannot check service status")

    # 10. Buffered results
    try:
        from .result_buffer import ResultBuffer
        buf = ResultBuffer()
        pending = buf.pending_count()
        stats = buf.all_stats()
        if pending > 0:
            _warn("Buffered results", f"{pending} pending, {stats.get('sent', 0)} sent, {stats.get('abandoned', 0)} abandoned")
        else:
            _pass("Buffered results", f"None pending ({stats.get('sent', 0)} sent)")
    except Exception:
        _pass("Buffered results", "No buffer database")

    # Print results
    console.print()
    console.print(table)
    console.print()

    if issues > 0:
        console.print(f"[bold red]✗ {issues} issue(s) found[/bold red] — fix before running scans")
        sys.exit(EXIT_ERROR)
    elif warnings > 0:
        console.print(f"[bold yellow]⚠ {warnings} warning(s)[/bold yellow] — system functional but review recommended")
    else:
        console.print(f"[bold green]✓ All checks passed[/bold green] — system healthy")


# ─── Update Command ─────────────────────────────────────────────────

@cli.command()
@click.option("--rules", is_flag=True, help="Update YARA rules and IoC database")
@click.option("--agent", is_flag=True, help="Update the agent binary")
@click.option("--all", "update_all", is_flag=True, help="Update everything")
@click.pass_context
def update(ctx: click.Context, rules: bool, agent: bool, update_all: bool) -> None:
    """Update YARA rules, intelligence data, or the agent itself."""
    console = Console()
    config = ctx.obj["config"]

    if not any([rules, agent, update_all]):
        console.print("[yellow]Specify what to update: --rules, --agent, or --all[/yellow]")
        sys.exit(EXIT_ERROR)

    if rules or update_all:
        console.print("\n[bold cyan]📦 Updating intelligence data...[/bold cyan]")

        try:
            from .intel_sync import IntelSync

            api_url = config.get("api", {}).get("url", "")
            api_key = config.get("api", {}).get("key", "")

            if not api_url or not api_key:
                console.print("[red]✗ API not configured. Run: cleanshift connect --api-url URL --api-key KEY[/red]")
                sys.exit(EXIT_ERROR)

            syncer = IntelSync(api_url=api_url, api_key=api_key)
            result = syncer.auto_sync()

            if result.get("updated"):
                console.print(f"[green]✓ Intelligence updated: {result.get('files_updated', 0)} files[/green]")
            else:
                console.print("[green]✓ Intelligence already up to date[/green]")
        except ImportError:
            console.print("[yellow]⚠ Intel sync module not available[/yellow]")
        except Exception as e:
            console.print(f"[red]✗ Update failed: {e}[/red]")

        # Count YARA rules
        rules_dir = Path(__file__).resolve().parent.parent.parent / "intelligence" / "rules"
        rule_count = 0
        for ext in ("*.yar", "*.yara"):
            rule_count += len(list(rules_dir.rglob(ext)))
        console.print(f"[dim]  YARA rule files: {rule_count}[/dim]")

    if agent or update_all:
        console.print("\n[bold cyan]🔄 Checking for agent updates...[/bold cyan]")
        try:
            from .updater import SecureUpdater

            api_url = config.get("api", {}).get("url", "")
            api_key = config.get("api", {}).get("key", "")
            updater = SecureUpdater(api_url=api_url, api_key=api_key)
            result = updater.check_and_update()

            if result.get("updated"):
                console.print(f"[green]✓ Agent updated to v{result.get('version', '?')}[/green]")
            else:
                console.print(f"[green]✓ Agent is up to date (v{__version__})[/green]")
        except Exception as e:
            console.print(f"[red]✗ Agent update failed: {e}[/red]")

    console.print()


# ─── Harden Command ─────────────────────────────────────────────────

@cli.command()
@click.option("--site", "-s", type=click.Path(), required=True, help="Path to WordPress site")
@click.option("--format", "output_format", type=click.Choice(["htaccess", "nginx", "both"]), default="htaccess", help="Output format")
@click.option("--min-blocks", type=int, default=10, help="Min BLOCKED events to auto-block IP (default: 10)")
@click.option("--block-xmlrpc/--allow-xmlrpc", default=True, help="Block xmlrpc.php")
@click.option("--dry-run", is_flag=True, help="Preview rules without writing")
@click.option("--disable", is_flag=True, help="Remove CleanShift rules from .htaccess")
@click.pass_context
def harden(
    ctx: click.Context,
    site: str,
    output_format: str,
    min_blocks: int,
    block_xmlrpc: bool,
    dry_run: bool,
    disable: bool,
) -> None:
    """Generate server-level security rules from Guard audit data.

    Converts Guard BLOCKED events into .htaccess or Nginx deny rules
    to stop attacks before PHP boots.
    """
    console = Console()

    from .htaccess_hardener import HtaccessHardener

    hardener = HtaccessHardener(
        site_path=site,
        min_blocks=min_blocks,
    )

    if disable:
        result = hardener.remove_from_htaccess()
        if result["status"] == "removed":
            console.print("[green]✓ CleanShift rules removed from .htaccess[/green]")
        elif result["status"] == "no_rules_found":
            console.print("[yellow]No CleanShift rules found in .htaccess[/yellow]")
        else:
            console.print(f"[dim]{result['status']}[/dim]")
        return

    blocked_ips = hardener.get_blocked_ips_from_guard()
    console.print(f"\n[bold cyan]🛡  CleanShift Server Hardener[/bold cyan]")
    console.print(f"  Site: {site}")
    console.print(f"  IPs to block: {len(blocked_ips)} (min {min_blocks} BLOCKED events)")
    console.print(f"  XML-RPC: {'blocked' if block_xmlrpc else 'allowed'}")
    console.print()

    if output_format in ("htaccess", "both"):
        rules = hardener.generate_htaccess_rules(
            block_ips=blocked_ips,
            block_xmlrpc=block_xmlrpc,
        )
        if dry_run:
            console.print("[bold yellow]── .htaccess rules (DRY RUN) ──[/bold yellow]")
            console.print(rules)
        else:
            result = hardener.apply_to_htaccess()
            if result["status"] == "applied":
                console.print(f"[green]✓ .htaccess updated — {result['ips_blocked']} IPs blocked[/green]")
            else:
                console.print(f"[red]✗ Failed: {result.get('error', result['status'])}[/red]")

    if output_format in ("nginx", "both"):
        rules = hardener.generate_nginx_rules(
            block_ips=blocked_ips,
            block_xmlrpc=block_xmlrpc,
        )
        console.print("[bold yellow]── Nginx rules ──[/bold yellow]")
        console.print(rules)
        console.print("[dim]Add these to your server {{ }} block in nginx.conf[/dim]")

    console.print()


# ─── Config Encryption CLI ──────────────────────────────────────────

@cli.group("config")
def config_group() -> None:
    """Config file encryption management."""
    pass


@config_group.command("encrypt")
@click.option(
    "--key-path",
    type=click.Path(),
    default=str(_DEFAULT_KEY_PATH),
    show_default=True,
    help="Path to store the Fernet encryption key",
)
@click.pass_context
def config_encrypt(ctx: click.Context, key_path: str) -> None:
    """Encrypt the plaintext config file (migration)."""
    print_banner()

    config_path = _DEFAULT_CONFIG_PATH
    kp = Path(key_path)

    if not config_path.exists():
        console.print(f"[red]Error:[/red] Config file not found at {config_path}")
        sys.exit(EXIT_ERROR)

    if is_encrypted(config_path):
        console.print("[yellow]Config is already encrypted — nothing to do.[/yellow]")
        return

    success = migrate_plaintext_config(config_path, kp)
    if success:
        console.print(f"[green]✓[/green] Config encrypted successfully")
        console.print(f"  Config: {config_path}")
        console.print(f"  Key:    {kp}")
        console.print("\n  [dim]Keep the key file safe — losing it means re-registering the agent.[/dim]")
    else:
        console.print("[red]✗[/red] Failed to encrypt config. Check logs for details.")
        sys.exit(EXIT_ERROR)


@config_group.command("decrypt")
@click.option(
    "--key-path",
    type=click.Path(),
    default=str(_DEFAULT_KEY_PATH),
    show_default=True,
    help="Path to the Fernet encryption key",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write decrypted YAML to file instead of stdout")
@click.pass_context
def config_decrypt(ctx: click.Context, key_path: str, output: Optional[str]) -> None:
    """Decrypt config for inspection (dev / debugging only)."""
    print_banner()

    config_path = _DEFAULT_CONFIG_PATH
    kp = Path(key_path)

    if not config_path.exists():
        console.print(f"[red]Error:[/red] Config file not found at {config_path}")
        sys.exit(EXIT_ERROR)

    if not is_encrypted(config_path):
        console.print("[yellow]Config is not encrypted — showing plaintext.[/yellow]")
        console.print(config_path.read_text(encoding="utf-8"))
        return

    try:
        yaml_text = decrypt_config_to_yaml(config_path, kp)
    except (ConfigKeyMissing, ConfigDecryptionError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(EXIT_ERROR)

    if output:
        out_path = Path(output)
        out_path.write_text(yaml_text, encoding="utf-8")
        console.print(f"[green]✓[/green] Decrypted config written to {out_path}")
        console.print("  [yellow]⚠ This file contains secrets — delete when done.[/yellow]")
    else:
        console.print("[bold]── Decrypted config ──[/bold]")
        console.print(yaml_text)


# ─── Entry Point ────────────────────────────────────────────────────

def main() -> None:
    """Main entry point for the CleanShift CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
