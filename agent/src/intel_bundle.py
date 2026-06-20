"""
CleanShift Intel Bundle — Runtime Decryptor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Loads and decrypts the pre-packed intelligence bundle at runtime.
The bundle contains IoC indicators, remediation playbooks, and YARA
rules in a single encrypted blob.

The decryption key is derived from a seed string that is deliberately
split across multiple variables to raise the bar against casual
extraction.  This is NOT a security boundary — it is defence-in-depth
obfuscation only.  The real protection is the server-side API that
issues live updates to Pro+ subscribers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("cleanshift.intel_bundle")

# ── Module-level cache ──────────────────────────────────────────────

_CACHED_BUNDLE: Optional[Dict] = None


# ── Obfuscated Key Derivation ──────────────────────────────────────

def _derive_bundle_key() -> bytes:
    """
    Reconstruct the Fernet key from a split seed.

    The seed string is intentionally fragmented across multiple
    variables to make it non-trivial to extract via simple string
    scanning of the compiled bytecode.
    """
    # Fragment the seed across variables
    _pfx = "cleanshift"
    _mid = "-intel-bundle-"
    _sfx = "v1-2024"

    seed = _pfx + _mid + _sfx

    # SHA-256 → first 32 bytes → base64url (Fernet requirement)
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:32])


# ── Bundle Loading ──────────────────────────────────────────────────

def load_bundle() -> Dict:
    """
    Load and decrypt the intelligence bundle.

    Returns a dict with keys:
        - version      (str)
        - timestamp    (str, ISO-8601)
        - indicators   (dict)
        - playbooks    (list[dict])
        - yara_rules   (list[dict])

    Returns an empty dict on any failure (file missing, decryption
    error, parse error) so the caller can fall back to raw YAML.
    """
    global _CACHED_BUNDLE

    if _CACHED_BUNDLE is not None:
        return _CACHED_BUNDLE

    bundle_path = Path(__file__).resolve().parent / "data" / "intel_bundle.dat"

    if not bundle_path.exists():
        logger.debug("Intel bundle not found at %s — falling back to YAML", bundle_path)
        return {}

    try:
        # Lazy import: cryptography may not be installed in dev
        from cryptography.fernet import Fernet, InvalidToken

        encrypted = bundle_path.read_bytes()
        key = _derive_bundle_key()
        fernet = Fernet(key)
        plaintext = fernet.decrypt(encrypted)

        bundle = json.loads(plaintext.decode("utf-8"))

        # Validate expected keys
        expected_keys = {"version", "timestamp", "indicators", "playbooks", "yara_rules"}
        if not expected_keys.issubset(bundle.keys()):
            logger.warning("Intel bundle is missing expected keys: %s",
                           expected_keys - bundle.keys())
            return {}

        _CACHED_BUNDLE = bundle
        logger.info(
            "Intel bundle loaded successfully (v%s, %s)",
            bundle.get("version", "?"),
            bundle.get("timestamp", "?"),
        )
        return _CACHED_BUNDLE

    except ImportError:
        logger.debug("cryptography package not available — cannot decrypt bundle")
        return {}
    except Exception as exc:
        logger.warning("Failed to load intel bundle: %s", exc)
        return {}


# ── Convenience Accessors ───────────────────────────────────────────

def get_bundle_version() -> Optional[str]:
    """Return the cached bundle version, or None if not loaded."""
    if _CACHED_BUNDLE is not None:
        return _CACHED_BUNDLE.get("version")
    return None


def get_bundle_timestamp() -> Optional[str]:
    """Return the cached bundle timestamp, or None if not loaded."""
    if _CACHED_BUNDLE is not None:
        return _CACHED_BUNDLE.get("timestamp")
    return None
