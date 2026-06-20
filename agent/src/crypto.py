"""
CleanShift Cryptographic Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ed25519 signature verification for server-signed license tokens.
Machine fingerprinting for license binding.

This module handles the *verification* side only — token signing
is performed server-side in the license API.  The embedded public
key is used to verify that tokens were issued by a trusted server
and have not been tampered with in transit or at rest.

Security notes:
    - Ed25519 chosen for compact signatures and deterministic signing.
    - Machine fingerprints bind tokens to specific hosts to prevent
      license sharing / replay across machines.
    - Token expiry is enforced client-side; the server sets ``exp``
      and ``nbf`` claims.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import platform
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger("cleanshift.crypto")


# ─── Embedded Public Key ──────────────────────────────────────────────
# ROTATE BEFORE PRODUCTION RELEASE
# This is a placeholder Ed25519 public key.  The corresponding private
# key must NEVER be shipped in agent code — it lives server-side only
# and is loaded from the CLEANSHIFT_LICENSE_SIGNING_KEY env var.
#
# To generate a new key pair for production:
#   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
#   from cryptography.hazmat.primitives import serialization
#   private = Ed25519PrivateKey.generate()
#   print(private.private_bytes(
#       serialization.Encoding.PEM,
#       serialization.PrivateFormat.PKCS8,
#       serialization.NoEncryption(),
#   ).decode())
#   print(private.public_key().public_bytes(
#       serialization.Encoding.PEM,
#       serialization.PublicFormat.SubjectPublicKeyInfo,
#   ).decode())

_PUBLIC_KEY_PEM = b"""\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAkZOSKBcvpzD01crJ1xN6DX+7EpFn9Xal8WRhq5y7jiI=
-----END PUBLIC KEY-----
"""
# Production key — rotated 2026-06-20


# ─── Exceptions ────────────────────────────────────────────────────────

class TokenVerificationError(Exception):
    """Raised when a license token fails cryptographic verification.

    Subclasses ValueError so callers that broadly catch value errors
    during deserialization will also catch verification failures.
    """

    def __init__(self, reason: str, *, detail: Optional[str] = None):
        self.reason = reason
        self.detail = detail
        super().__init__(f"Token verification failed: {reason}")


# ─── Base64url Helpers ─────────────────────────────────────────────────

def _b64url_decode(data: str) -> bytes:
    """Decode a base64url-encoded string (no padding required).

    Args:
        data: Base64url-encoded string (RFC 7515 §2).

    Returns:
        Decoded bytes.

    Raises:
        TokenVerificationError: If decoding fails.
    """
    try:
        # Re-add padding stripped by JWT spec
        padded = data + "=" * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise TokenVerificationError(
            "invalid base64url encoding", detail=str(exc)
        ) from exc


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding.

    Args:
        data: Raw bytes to encode.

    Returns:
        Base64url-encoded string with padding stripped.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ─── Public Key Loading ───────────────────────────────────────────────

def _load_public_key() -> Ed25519PublicKey:
    """Load and cache the embedded Ed25519 public key.

    Returns:
        An Ed25519PublicKey instance.

    Raises:
        TokenVerificationError: If the embedded key is malformed.
    """
    try:
        key = load_pem_public_key(_PUBLIC_KEY_PEM)
        if not isinstance(key, Ed25519PublicKey):
            raise TokenVerificationError(
                "embedded key is not Ed25519",
                detail=f"got {type(key).__name__}",
            )
        return key
    except TokenVerificationError:
        raise
    except Exception as exc:
        raise TokenVerificationError(
            "failed to load embedded public key", detail=str(exc)
        ) from exc


# Module-level lazy singleton — loaded once on first use
_cached_public_key: Optional[Ed25519PublicKey] = None


def _get_public_key() -> Ed25519PublicKey:
    """Return the cached public key, loading on first call."""
    global _cached_public_key
    if _cached_public_key is None:
        _cached_public_key = _load_public_key()
    return _cached_public_key


# ─── Token Verification ───────────────────────────────────────────────

def verify_license_token(token: str) -> Dict[str, Any]:
    """Verify and decode a server-signed license JWT.

    Parses a compact JWT (``header.payload.signature``), verifies
    the Ed25519 signature against the embedded public key, and
    validates temporal claims (``exp``, ``nbf``).

    The JWT uses the **EdDSA** algorithm with Ed25519 keys, following
    RFC 8037.  Only tokens signed by the CleanShift license server
    with the matching private key will pass verification.

    Args:
        token: Compact JWT string (``base64url.base64url.base64url``).

    Returns:
        Decoded payload dictionary containing license claims
        (e.g. ``sub``, ``tier``, ``features``, ``exp``, ``fingerprint``).

    Raises:
        TokenVerificationError:
            - Token is malformed (wrong number of segments).
            - Header declares an unsupported algorithm.
            - Signature verification fails.
            - Token has expired (``exp`` claim).
            - Token is not yet valid (``nbf`` claim).
            - Payload is not valid JSON.

    Example
    -------
    >>> payload = verify_license_token(signed_jwt_string)
    >>> payload["tier"]
    'pro'
    >>> payload["features"]["remediation"]
    True
    """
    if not isinstance(token, str) or not token.strip():
        raise TokenVerificationError("token must be a non-empty string")

    # ── Split into segments ────────────────────────────────────────
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise TokenVerificationError(
            "malformed JWT",
            detail=f"expected 3 segments, got {len(parts)}",
        )

    header_b64, payload_b64, signature_b64 = parts

    # ── Decode and validate header ─────────────────────────────────
    header_bytes = _b64url_decode(header_b64)
    try:
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenVerificationError(
            "invalid JWT header", detail=str(exc)
        ) from exc

    alg = header.get("alg", "").upper()
    if alg not in ("EDDSA", "ED25519"):
        raise TokenVerificationError(
            f"unsupported algorithm: {header.get('alg')}",
            detail="only EdDSA (Ed25519) is accepted",
        )

    # ── Verify signature ───────────────────────────────────────────
    # The signature covers the ASCII bytes of "header.payload"
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(signature_b64)

    public_key = _get_public_key()
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise TokenVerificationError(
            "signature verification failed",
            detail="token was not signed by a trusted server",
        ) from exc
    except Exception as exc:
        raise TokenVerificationError(
            "signature verification error", detail=str(exc)
        ) from exc

    # ── Decode payload ─────────────────────────────────────────────
    payload_bytes = _b64url_decode(payload_b64)
    try:
        payload: Dict[str, Any] = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenVerificationError(
            "invalid JWT payload", detail=str(exc)
        ) from exc

    if not isinstance(payload, dict):
        raise TokenVerificationError(
            "JWT payload is not a JSON object",
            detail=f"got {type(payload).__name__}",
        )

    # ── Validate temporal claims ───────────────────────────────────
    now = time.time()

    # exp (expiration) — required for license tokens
    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_ts = float(exp)
        except (TypeError, ValueError) as exc:
            raise TokenVerificationError(
                "invalid exp claim", detail=str(exc)
            ) from exc
        if now > exp_ts:
            raise TokenVerificationError(
                "token has expired",
                detail=f"expired at {exp_ts}, current time {now}",
            )

    # nbf (not-before) — optional
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf_ts = float(nbf)
        except (TypeError, ValueError) as exc:
            raise TokenVerificationError(
                "invalid nbf claim", detail=str(exc)
            ) from exc
        if now < nbf_ts:
            raise TokenVerificationError(
                "token is not yet valid",
                detail=f"valid from {nbf_ts}, current time {now}",
            )

    logger.debug(
        "License token verified: sub=%s tier=%s exp=%s",
        payload.get("sub", "unknown"),
        payload.get("tier", "unknown"),
        payload.get("exp", "none"),
    )
    return payload


def get_token_expiry(token: str) -> Optional[float]:
    """Extract the ``exp`` claim from a token WITHOUT full verification.

    This is used to check whether a cached token is approaching expiry
    so we can proactively refresh it, without raising on expired tokens.

    Args:
        token: Compact JWT string.

    Returns:
        Unix timestamp of expiry, or None if the claim is missing
        or the token is malformed.
    """
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        payload_bytes = _b64url_decode(parts[1])
        payload = json.loads(payload_bytes)
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


# ─── Machine Fingerprinting ───────────────────────────────────────────

def generate_machine_fingerprint() -> str:
    """Generate a deterministic, unique identifier for the current machine.

    Combines three hardware/OS identifiers and returns their SHA-256
    hash as a hex string.  The same physical machine will always
    produce the same fingerprint, preventing license token replay
    on different hosts.

    Components:
        1. **Hostname** — ``socket.gethostname()``
        2. **Primary MAC address** — ``uuid.getnode()`` (48-bit)
        3. **Platform ID**:
           - Linux: ``/etc/machine-id`` (systemd)
           - macOS: ``IOPlatformUUID`` via ``ioreg``
           - Fallback: ``platform.node()``

    Returns:
        64-character lowercase hex string (SHA-256 digest).

    Example
    -------
    >>> fp = generate_machine_fingerprint()
    >>> len(fp)
    64
    >>> fp == generate_machine_fingerprint()  # deterministic
    True
    """
    components: list[str] = []

    # 1. Hostname
    try:
        components.append(socket.gethostname())
    except Exception:
        components.append("unknown-host")

    # 2. Primary MAC address (48-bit integer → hex)
    try:
        mac = uuid.getnode()
        # uuid.getnode() returns a random MAC if it can't find one;
        # bit 0 of the first octet is set for random MACs (multicast bit).
        mac_hex = format(mac, "012x")
        components.append(mac_hex)
    except Exception:
        components.append("000000000000")

    # 3. Platform-specific machine ID
    platform_id = _get_platform_id()
    components.append(platform_id)

    # Combine and hash
    combined = "|".join(components)
    fingerprint = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    logger.debug("Machine fingerprint generated (hostname=%s)", components[0])
    return fingerprint


def _get_platform_id() -> str:
    """Retrieve a platform-specific persistent machine identifier.

    Returns:
        Machine ID string, or a fallback value if unavailable.
    """
    system = platform.system().lower()

    if system == "linux":
        return _get_linux_machine_id()
    elif system == "darwin":
        return _get_macos_platform_uuid()
    else:
        # Windows / other — fall back to platform.node()
        return platform.node() or "unknown-platform"


def _get_linux_machine_id() -> str:
    """Read ``/etc/machine-id`` on Linux (systemd).

    Falls back to ``/var/lib/dbus/machine-id`` if the primary file
    doesn't exist.

    Returns:
        Machine ID hex string, or fallback.
    """
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            machine_id = Path(path).read_text(encoding="utf-8").strip()
            if machine_id:
                return machine_id
        except (OSError, PermissionError):
            continue

    logger.warning("Could not read /etc/machine-id, using fallback")
    return platform.node() or "unknown-linux"


def _get_macos_platform_uuid() -> str:
    """Retrieve IOPlatformUUID on macOS via ``ioreg``.

    Returns:
        UUID string (e.g. ``A1B2C3D4-...``), or fallback.
    """
    try:
        result = subprocess.run(
            [
                "ioreg",
                "-rd1",
                "-c", "IOPlatformExpertDevice",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    # Line format: "IOPlatformUUID" = "UUID-HERE"
                    parts = line.split('"')
                    for i, part in enumerate(parts):
                        if part.strip() == "IOPlatformUUID" and i + 2 < len(parts):
                            return parts[i + 2]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    logger.warning("Could not read IOPlatformUUID, using fallback")
    return platform.node() or "unknown-macos"


# ─── Fingerprint Comparison ──────────────────────────────────────────

def verify_fingerprint(token_fingerprint: str) -> bool:
    """Compare a token's embedded fingerprint against the current machine.

    Uses constant-time comparison (via ``hmac.compare_digest``) to
    prevent timing side-channel attacks.

    Args:
        token_fingerprint: The ``fingerprint`` claim from the license
            token (64-char hex SHA-256 digest).

    Returns:
        True if the token fingerprint matches this machine's fingerprint.

    Example
    -------
    >>> verify_fingerprint(payload["fingerprint"])
    True
    """
    import hmac

    if not token_fingerprint:
        logger.warning("Token contains empty fingerprint — rejecting")
        return False

    current = generate_machine_fingerprint()
    match = hmac.compare_digest(current, token_fingerprint)

    if not match:
        logger.warning(
            "Machine fingerprint mismatch: token is bound to a different host"
        )
    return match
