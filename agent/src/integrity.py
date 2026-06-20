"""
CleanShift Binary & Config Integrity Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Lightweight self-integrity checks for the CleanShift agent binary,
configuration files, and runtime environment.

Design philosophy:
    - Integrity failures **warn and report** — they never crash the agent.
    - All checks are non-blocking and fast (< 100 ms typical).
    - In development mode (``EXPECTED_HASH is None``), binary checks
      are skipped with a logged warning.
    - Results are reported to the central API when connectivity allows.

Checks performed:
    1. Binary self-hash verification (CI/CD patches ``EXPECTED_HASH``).
    2. Config file signature verification (SHA-256 HMAC).
    3. Debugger / tracer detection (``sys.gettrace``, ptrace).
    4. Combined startup check with telemetry reporting.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cleanshift.integrity")


# ─── Build-time Constants ─────────────────────────────────────────────
# CI/CD pipeline patches EXPECTED_HASH with the SHA-256 of the built
# binary.  In development mode it stays None and the check is skipped.

EXPECTED_HASH: Optional[str] = None


# ─── Binary Integrity ─────────────────────────────────────────────────

def verify_binary_integrity() -> bool:
    """Verify that the running agent binary has not been modified.

    Computes the SHA-256 hash of the running Python entry point and
    compares it against ``EXPECTED_HASH``, which is patched at build
    time by the CI/CD pipeline.

    In development mode (``EXPECTED_HASH is None``), the check is
    skipped and a warning is logged.

    The function examines:
        1. ``sys.argv[0]`` — the script invoked from the command line.
        2. ``__file__`` fallback — this module's own file as a canary.

    Returns:
        True if the binary matches or the check is skipped (dev mode).
        False if the hash does not match (binary was modified).

    Notes:
        This check is most effective for PyInstaller / Nuitka / shiv
        single-file builds.  For plain ``.py`` execution, it hashes
        the entry-point script.
    """
    if EXPECTED_HASH is None:
        logger.warning(
            "Binary integrity check skipped — EXPECTED_HASH not set "
            "(development mode)"
        )
        return True

    binary_path = _resolve_binary_path()
    if binary_path is None:
        logger.warning(
            "Could not determine binary path — integrity check skipped"
        )
        return True

    try:
        actual_hash = _sha256_file(binary_path)
    except OSError as exc:
        logger.warning("Failed to hash binary at %s: %s", binary_path, exc)
        return True  # Fail open — don't crash on permission errors

    match = hmac.compare_digest(actual_hash, EXPECTED_HASH.lower())
    if not match:
        logger.error(
            "BINARY INTEGRITY FAILURE — expected %s, got %s (path: %s)",
            EXPECTED_HASH[:16] + "...",
            actual_hash[:16] + "...",
            binary_path,
        )
    else:
        logger.debug("Binary integrity verified: %s", actual_hash[:16] + "...")

    return match


def _resolve_binary_path() -> Optional[Path]:
    """Determine the path to the running binary / entry-point script.

    Returns:
        Path to the binary, or None if it cannot be determined.
    """
    # Frozen executables (PyInstaller, cx_Freeze)
    if getattr(sys, "frozen", False):
        return Path(sys.executable)

    # Normal Python execution — use the entry-point script
    if sys.argv and sys.argv[0]:
        candidate = Path(sys.argv[0]).resolve()
        if candidate.is_file():
            return candidate

    # Fallback to this module's own file
    try:
        return Path(__file__).resolve()
    except (NameError, TypeError):
        return None


def _sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file.

    Args:
        path: File to hash.
        chunk_size: Read buffer size in bytes.

    Returns:
        Lowercase hex digest string (64 chars).
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


# ─── Config File Integrity ────────────────────────────────────────────

def verify_config_integrity(config_path: Path, expected_sig: str) -> bool:
    """Verify that a configuration file has not been tampered with.

    Computes the SHA-256 hash of the config file and compares it
    against an expected signature.  Uses constant-time comparison
    to prevent timing side-channel attacks.

    Args:
        config_path: Absolute path to the configuration file.
        expected_sig: Expected SHA-256 hex digest of the file.

    Returns:
        True if the file matches the expected signature.
        False if the file has been modified, is missing, or is
        unreadable.

    Example
    -------
    >>> verify_config_integrity(Path("/etc/cleanshift/config.yaml"), sig)
    True
    """
    if not config_path.is_file():
        logger.warning(
            "Config file not found for integrity check: %s", config_path
        )
        return False

    try:
        actual_sig = _sha256_file(config_path)
    except OSError as exc:
        logger.warning(
            "Failed to hash config file %s: %s", config_path, exc
        )
        return False

    match = hmac.compare_digest(actual_sig, expected_sig.lower())
    if not match:
        logger.error(
            "CONFIG INTEGRITY FAILURE — %s has been modified "
            "(expected %s, got %s)",
            config_path,
            expected_sig[:16] + "...",
            actual_sig[:16] + "...",
        )
    else:
        logger.debug("Config integrity verified: %s", config_path.name)

    return match


# ─── Debugger Detection ──────────────────────────────────────────────

def detect_debugger() -> bool:
    """Detect whether the agent is running under a debugger or tracer.

    Performs two non-intrusive checks:

    1. **Python debugger**: ``sys.gettrace()`` returns a non-None value
       when a debugger (pdb, pydevd, etc.) is attached.
    2. **Native tracer (Linux)**: Reads ``/proc/self/status`` for
       ``TracerPid`` — a non-zero value indicates ptrace attachment.

    This check is informational — it logs a warning and reports to
    the API, but does NOT terminate the agent.  Legitimate use cases
    (CI runners, diagnostic sessions) should not be blocked.

    Returns:
        True if a debugger or tracer is detected, False otherwise.
    """
    # Check 1: Python-level debugger (pdb, pydevd, etc.)
    if _detect_python_debugger():
        return True

    # Check 2: OS-level tracer (ptrace on Linux)
    if _detect_ptrace_tracer():
        return True

    return False


def _detect_python_debugger() -> bool:
    """Check if a Python debugger is attached via sys.gettrace().

    Returns:
        True if a trace function is set.
    """
    try:
        tracer = sys.gettrace()
        if tracer is not None:
            logger.warning(
                "Python debugger detected (trace function: %s)",
                type(tracer).__name__,
            )
            return True
    except Exception:
        pass  # Some environments don't support gettrace()
    return False


def _detect_ptrace_tracer() -> bool:
    """Check for ptrace attachment on Linux via /proc/self/status.

    The ``TracerPid`` field in ``/proc/self/status`` is non-zero
    when another process is tracing this one (strace, gdb, etc.).

    Returns:
        True if a tracer is detected.  Always False on non-Linux.
    """
    if platform.system().lower() != "linux":
        return False

    try:
        status_path = Path("/proc/self/status")
        if not status_path.exists():
            return False

        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("TracerPid:"):
                tracer_pid = line.split(":", 1)[1].strip()
                if tracer_pid != "0":
                    logger.warning(
                        "Native tracer detected — TracerPid: %s",
                        tracer_pid,
                    )
                    return True
                break
    except (OSError, PermissionError):
        pass  # /proc may not be accessible in containers

    return False


# ─── Combined Startup Check ──────────────────────────────────────────

def startup_integrity_check(
    *,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Run all integrity checks and optionally report results to the API.

    This should be called once during agent startup.  It combines:
        1. Binary self-hash verification.
        2. Debugger / tracer detection.

    Results are logged and returned as a dict.  If ``api_base`` and
    ``api_key`` are provided, a summary is reported to the central
    API (best-effort, non-blocking).

    Args:
        api_base: Optional CleanShift API base URL for telemetry.
        api_key: Optional API key for authenticated reporting.

    Returns:
        Dictionary with check results::

            {
                "binary_ok": True,
                "debugger_detected": False,
                "checks_passed": True,
                "details": [...],
            }

    Example
    -------
    >>> result = startup_integrity_check()
    >>> result["checks_passed"]
    True
    """
    results: Dict[str, Any] = {
        "binary_ok": True,
        "debugger_detected": False,
        "checks_passed": True,
        "details": [],
    }

    # ── Binary integrity ──────────────────────────────────────────
    try:
        binary_ok = verify_binary_integrity()
        results["binary_ok"] = binary_ok
        if not binary_ok:
            results["checks_passed"] = False
            results["details"].append(
                "Binary integrity check failed — agent may have been modified"
            )
    except Exception as exc:
        logger.warning("Binary integrity check raised: %s", exc)
        results["details"].append(f"Binary check error: {exc}")

    # ── Debugger detection ────────────────────────────────────────
    try:
        debugger = detect_debugger()
        results["debugger_detected"] = debugger
        if debugger:
            results["details"].append(
                "Debugger or tracer detected — this is logged for security"
            )
    except Exception as exc:
        logger.warning("Debugger detection raised: %s", exc)
        results["details"].append(f"Debugger check error: {exc}")

    # ── Log summary ───────────────────────────────────────────────
    if results["checks_passed"] and not results["debugger_detected"]:
        logger.info("Startup integrity checks passed")
    else:
        for detail in results["details"]:
            logger.warning("Integrity: %s", detail)

    # ── Report to API (best-effort) ───────────────────────────────
    if api_base and api_key:
        _report_integrity(api_base, api_key, results)

    return results


def _report_integrity(
    api_base: str,
    api_key: str,
    results: Dict[str, Any],
) -> None:
    """Report integrity check results to the central API (best-effort).

    This is a fire-and-forget call — failures are logged but never
    raised.  Uses httpx if available, otherwise silently skips.

    Args:
        api_base: CleanShift API base URL.
        api_key: Agent API key for authentication.
        results: Integrity check results dict.
    """
    try:
        import httpx
    except ImportError:
        logger.debug("httpx not available — skipping integrity report")
        return

    url = f"{api_base.rstrip('/')}/api/telemetry/integrity"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "CleanShift-Agent/1.0",
    }
    payload = {
        "binary_ok": results["binary_ok"],
        "debugger_detected": results["debugger_detected"],
        "checks_passed": results["checks_passed"],
        "platform": platform.system(),
        "python_version": platform.python_version(),
    }

    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(url, json=payload, headers=headers)
        logger.debug("Integrity report sent: HTTP %d", response.status_code)
    except Exception as exc:
        logger.debug("Failed to send integrity report: %s", exc)
