"""
CleanShift License Validator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tier-based feature gating for the CleanShift server agent.
Validates license keys against the central API, verifies
server-signed Ed25519 tokens, and enforces feature access
based on subscription tier.

Tiers:
    free       — 1 server, quick scan only, no remediation
    pro        — 50 servers, deep scan, full features
    enterprise — unlimited servers, deep scan, full features

Token lifecycle:
    - Tokens are signed JWTs issued by the license API (Ed25519).
    - Tokens contain tier, features, machine fingerprint, and expiry.
    - Tokens are valid for 72 hours (``exp`` claim).
    - Auto-refresh when < 12 hours remaining.
    - 7-day grace period after expiry → then downgrade to free.

Graceful degradation:
    - If the API is unreachable, uses cached signed token.
    - Cached tokens are re-verified on load (detects tampering).
    - If no cache exists, defaults to 'free' tier with a minimal
      hardcoded feature set.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel

from agent.src.crypto import (
    TokenVerificationError,
    generate_machine_fingerprint,
    get_token_expiry,
    verify_fingerprint,
    verify_license_token,
)

logger = logging.getLogger("cleanshift.license")
console = Console(stderr=True)


# ─── Fallback Free Tier ───────────────────────────────────────────────
# Minimal feature set used when no signed token is available and the
# API is unreachable.  This is the ONLY hardcoded tier definition in
# the agent — all other tier data comes from signed token claims.

_FREE_TIER_FALLBACK: Dict[str, Any] = {
    "max_servers": 1,
    "scan_modes": ["quick", "deep"],
    "guard": True,
    "remediation": False,
    "intel_sync": False,
    "vuln_scan": True,
    "telegram_alerts": True,
}

# Human-readable names for upgrade prompts
_FEATURE_LABELS: Dict[str, str] = {
    "remediation": "Automated remediation",
    "intel_sync": "Live threat intelligence updates",
    "max_servers": "More server slots",
    "concurrent_scans": "Concurrent scanning",
    "scan_history_days": "Extended scan history",
}

# Cache configuration
_CACHE_DIR = Path.home() / ".cleanshift" / "cache"
_CACHE_FILE = _CACHE_DIR / "license_token.dat"

# Token timing
_TOKEN_TTL_SECONDS = 72 * 60 * 60         # 72 hours
_REFRESH_THRESHOLD = 12 * 60 * 60         # Refresh when < 12 h remaining
_GRACE_PERIOD_SECONDS = 7 * 24 * 60 * 60  # 7-day grace after expiry

# API configuration
_DEFAULT_API_BASE = "https://api-cleanshift.osg.co.in"
_VALIDATE_ENDPOINT = "/api/license/validate"
_REFRESH_ENDPOINT = "/api/license/refresh"
_HTTP_TIMEOUT = 15  # seconds


# ─── Exceptions ────────────────────────────────────────────────────────

class LicenseError(Exception):
    """Raised when a licensed feature is accessed without authorization."""
    pass


class FeatureGatedError(LicenseError):
    """Raised when a feature requires a higher tier."""

    def __init__(self, feature: str, required_tier: str, current_tier: str):
        self.feature = feature
        self.required_tier = required_tier
        self.current_tier = current_tier
        label = _FEATURE_LABELS.get(feature, feature)
        super().__init__(
            f"{label} requires {required_tier.title()} tier. "
            f"Current tier: {current_tier}. "
            f"Visit cleanshift.osg.co.in/pricing"
        )


# ─── License Validator ────────────────────────────────────────────────

class LicenseValidator:
    """Validates license keys and enforces tier-based feature access.

    Uses server-signed Ed25519 JWT tokens for tamper-proof license
    verification.  Tier capabilities come from the signed token
    claims — no hardcoded tier definitions beyond the free fallback.

    Parameters
    ----------
    api_base : str
        Base URL of the CleanShift license API.
    cache_ttl : int
        Cache time-to-live in seconds (default: 72 hours).

    Usage
    -----
    >>> validator = LicenseValidator()
    >>> validator.validate("cs_live_abc123...")
    True
    >>> validator.check_feature("remediation")
    True
    >>> validator.get_tier()
    'pro'
    """

    def __init__(
        self,
        api_base: str = _DEFAULT_API_BASE,
        cache_ttl: int = _TOKEN_TTL_SECONDS,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.cache_ttl = cache_ttl
        self._tier: str = "free"
        self._features: Dict[str, Any] = dict(_FREE_TIER_FALLBACK)
        self._license_data: Dict[str, Any] = {}
        self._validated: bool = False
        self._api_key: Optional[str] = None
        self._current_token: Optional[str] = None
        self._token_payload: Optional[Dict[str, Any]] = None
        self._machine_fingerprint: Optional[str] = None

        # Ensure cache directory exists
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────

    def validate(self, api_key: str) -> bool:
        """Validate an API key against the central license server.

        Tries the remote API first to obtain a signed JWT token.
        On failure, falls back to a cached signed token (re-verified
        on load).  If no valid token exists, defaults to 'free' tier.

        Args:
            api_key: The CleanShift API/license key.

        Returns:
            True if validation succeeded (remote or cached), False if
            the key is explicitly invalid.
        """
        self._api_key = api_key

        # Generate machine fingerprint for token binding
        if self._machine_fingerprint is None:
            self._machine_fingerprint = generate_machine_fingerprint()

        # Try remote validation first
        remote_result = self._validate_remote(api_key)
        if remote_result is not None:
            return remote_result

        # Remote failed — try cached signed token
        logger.warning("API unreachable, attempting cached license validation")
        cached_ok = self._load_cache()
        if cached_ok:
            logger.info(
                "Using cached license token: tier=%s",
                self._tier,
            )
            return True

        # No cache or invalid — default to free
        logger.warning(
            "No valid cache found, defaulting to free tier"
        )
        self._apply_free_fallback()
        return True

    def check_feature(self, feature_name: str) -> bool:
        """Check if the current tier has access to a feature.

        Args:
            feature_name: Feature key (e.g. 'remediation', 'vuln_scan',
                          'intel_sync') or scan mode name ('deep').

        Returns:
            True if the feature is available on the current tier.
        """
        features = self._features

        # Check scan modes
        if feature_name in ("quick", "deep", "full", "single", "targeted"):
            return feature_name in features.get("scan_modes", [])

        # Check boolean feature flags
        value = features.get(feature_name, False)
        # None means unlimited → treat as allowed
        if value is None:
            return True
        return bool(value)

    def get_tier(self) -> str:
        """Return the current validated tier name.

        Returns:
            One of 'free', 'pro', or 'enterprise'.
        """
        return self._tier

    def get_limits(self) -> Dict[str, Any]:
        """Return the full limits dict for the current tier.

        Returns:
            Copy of the tier features dictionary.
        """
        return dict(self._features)

    def enforce(self, action: str, tier: str) -> None:
        """Enforce that the current tier meets the minimum required tier.

        If the current tier is insufficient, displays an upgrade prompt
        via rich console and raises FeatureGatedError.

        Args:
            action: The feature/action being attempted (e.g. 'deep',
                    'remediation', 'vuln_scan').
            tier: The minimum tier required (e.g. 'pro', 'enterprise').

        Raises:
            FeatureGatedError: If current tier < required tier.
        """
        tier_rank = {"free": 0, "pro": 1, "enterprise": 2}
        current_rank = tier_rank.get(self._tier, 0)
        required_rank = tier_rank.get(tier, 0)

        if current_rank >= required_rank:
            return  # Access granted

        label = _FEATURE_LABELS.get(action, action)
        self._show_upgrade_prompt(label, tier)
        raise FeatureGatedError(action, tier, self._tier)

    @property
    def is_validated(self) -> bool:
        """Whether the license has been validated (remote or cached)."""
        return self._validated

    @property
    def max_servers(self) -> Optional[int]:
        """Maximum servers allowed on the current tier (None = unlimited)."""
        return self._features.get("max_servers", _FREE_TIER_FALLBACK["max_servers"])

    def needs_refresh(self) -> bool:
        """Check if the current token needs proactive refresh.

        Returns:
            True if the token will expire in less than 12 hours,
            or if no token is present.
        """
        if self._current_token is None:
            return True

        exp = get_token_expiry(self._current_token)
        if exp is None:
            return True

        remaining = exp - time.time()
        return remaining < _REFRESH_THRESHOLD

    def refresh(self) -> bool:
        """Attempt to refresh the license token via the refresh endpoint.

        The refresh endpoint accepts the current (possibly near-expiry)
        token and issues a new 72-hour token.

        Returns:
            True if refresh succeeded, False otherwise.
        """
        if not self._api_key or not self._current_token:
            return False

        return self._refresh_token()

    # ── Private Helpers ────────────────────────────────────────────

    def _validate_remote(self, api_key: str) -> Optional[bool]:
        """Attempt remote license validation via the central API.

        Requests a signed JWT token from the license server, verifies
        the Ed25519 signature and machine fingerprint, and extracts
        tier and feature data from the token claims.

        Returns:
            True if valid, False if explicitly invalid, None if the API
            could not be reached.
        """
        if not _HTTPX_AVAILABLE:
            logger.warning(
                "httpx not installed — cannot validate license remotely"
            )
            return None

        url = f"{self.api_base}{_VALIDATE_ENDPOINT}"
        headers = {
            "X-API-Key": api_key,
            "User-Agent": "CleanShift-Agent/1.0",
            "X-Machine-Fingerprint": self._machine_fingerprint or "",
        }

        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
                response = client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                token = data.get("token")

                if token:
                    # New signed-token path
                    return self._process_signed_token(token, api_key)
                else:
                    # Backward compat: plain JSON response (legacy server)
                    data["api_key"] = api_key
                    self._apply_license_data(data)
                    self._save_cache_legacy(data)
                    logger.info(
                        "License validated (legacy): tier=%s, expires=%s",
                        self._tier,
                        data.get("expires_at", "never"),
                    )
                    return True

            if response.status_code in (401, 403):
                logger.error("License key is invalid or expired")
                self._tier = "free"
                self._validated = False
                return False

            # Unexpected status — treat as unreachable
            logger.warning(
                "Unexpected API response: %d %s",
                response.status_code,
                response.text[:200],
            )
            return None

        except httpx.HTTPError as exc:
            logger.warning("License API request failed: %s", exc)
            return None
        except Exception as exc:
            logger.warning("Unexpected error during license validation: %s", exc)
            return None

    def _process_signed_token(self, token: str, api_key: str) -> bool:
        """Verify a signed JWT token and apply its claims.

        Args:
            token: Signed JWT string from the license API.
            api_key: The API key used for this validation.

        Returns:
            True if the token is valid and applied successfully.
        """
        try:
            payload = verify_license_token(token)
        except TokenVerificationError as exc:
            logger.error("License token verification failed: %s", exc)
            return False

        # Verify machine fingerprint binding
        token_fp = payload.get("fingerprint")
        if token_fp and not verify_fingerprint(token_fp):
            logger.error(
                "License token is bound to a different machine — "
                "rejecting"
            )
            return False

        # Apply token data
        self._current_token = token
        self._token_payload = payload
        self._apply_token_claims(payload)

        # Cache the raw signed token (not plain JSON)
        self._save_cache(token, api_key)

        logger.info(
            "License validated: tier=%s, sub=%s, exp=%s",
            self._tier,
            payload.get("sub", "unknown"),
            payload.get("exp", "none"),
        )
        return True

    def _apply_token_claims(self, payload: Dict[str, Any]) -> None:
        """Extract tier and features from token claims.

        Args:
            payload: Decoded JWT payload dictionary.
        """
        tier = payload.get("tier", "free").lower()
        # Validate tier name — accept any server-issued tier
        if tier not in ("free", "pro", "enterprise"):
            logger.warning("Unknown tier '%s' in token, defaulting to free", tier)
            tier = "free"

        features = payload.get("features")
        if features and isinstance(features, dict):
            self._features = features
        else:
            # Token should always include features, but fall back safely
            logger.warning("Token missing features claim, using fallback")
            self._features = dict(_FREE_TIER_FALLBACK)

        self._tier = tier
        self._license_data = payload
        self._validated = True

    def _apply_license_data(self, data: Dict[str, Any]) -> None:
        """Apply license data from legacy API response or cache.

        Backward-compatible path for servers that don't yet issue
        signed tokens.
        """
        tier = data.get("tier", "free").lower()
        if tier not in ("free", "pro", "enterprise"):
            logger.warning("Unknown tier '%s', defaulting to free", tier)
            tier = "free"

        features = data.get("features")
        if features and isinstance(features, dict):
            self._features = features
        else:
            self._features = dict(_FREE_TIER_FALLBACK)

        self._tier = tier
        self._license_data = data
        self._validated = True

    def _apply_free_fallback(self) -> None:
        """Reset to free tier with hardcoded minimal features."""
        self._tier = "free"
        self._features = dict(_FREE_TIER_FALLBACK)
        self._license_data = {"tier": "free"}
        self._validated = True
        self._current_token = None
        self._token_payload = None

    def _save_cache(self, token: str, api_key: str) -> None:
        """Write signed token to the local cache file.

        The token itself is tamper-proof (signature verified on load),
        so we store it alongside minimal metadata.

        Args:
            token: Signed JWT string.
            api_key: API key associated with this token.
        """
        try:
            cache_data = {
                "token": token,
                "api_key_hash": self._hash_api_key(api_key),
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            _CACHE_FILE.write_text(
                json.dumps(cache_data, indent=2),
                encoding="utf-8",
            )
            logger.debug("Signed token cached at %s", _CACHE_FILE)
        except OSError as exc:
            logger.warning("Failed to write license cache: %s", exc)

    def _save_cache_legacy(self, data: Dict[str, Any]) -> None:
        """Write legacy (unsigned) license data to cache.

        Backward-compatible path for servers not yet issuing tokens.
        """
        try:
            cache_data = dict(data)
            cache_data["cached_at"] = datetime.now(timezone.utc).isoformat()
            cache_data["cache_expires"] = time.time() + self.cache_ttl

            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            _CACHE_FILE.write_text(
                json.dumps(cache_data, indent=2),
                encoding="utf-8",
            )
            logger.debug("Legacy license cache written to %s", _CACHE_FILE)
        except OSError as exc:
            logger.warning("Failed to write license cache: %s", exc)

    def _load_cache(self) -> bool:
        """Load and verify a cached signed license token.

        Re-verifies the Ed25519 signature on every load to detect
        file tampering.  Checks token expiry with grace period.

        Returns:
            True if a valid cached token was loaded, False otherwise.
        """
        if not _CACHE_FILE.exists():
            return False

        try:
            raw = _CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read license cache: %s", exc)
            return False

        # Check for signed token (new format)
        token = data.get("token")
        if token:
            return self._load_cached_token(token, data)

        # Legacy cache format (unsigned JSON)
        return self._load_cached_legacy(data)

    def _load_cached_token(
        self, token: str, cache_data: Dict[str, Any]
    ) -> bool:
        """Verify and apply a cached signed token.

        Args:
            token: Cached JWT string.
            cache_data: Full cache file contents (for metadata).

        Returns:
            True if the token is valid (possibly in grace period).
        """
        # Verify API key matches (if we have one)
        if self._api_key:
            cached_key_hash = cache_data.get("api_key_hash", "")
            if cached_key_hash and not self._verify_api_key_hash(
                self._api_key, cached_key_hash
            ):
                logger.info("Cached token API key mismatch — ignoring cache")
                return False

        # Check expiry (with grace period) before full verification
        exp = get_token_expiry(token)
        if exp is not None:
            now = time.time()
            if now > exp + _GRACE_PERIOD_SECONDS:
                logger.info(
                    "Cached token expired beyond grace period — removing"
                )
                _CACHE_FILE.unlink(missing_ok=True)
                return False

        # Re-verify signature (detects file tampering)
        try:
            payload = verify_license_token(token)
        except TokenVerificationError as exc:
            if exp is not None and time.time() > exp:
                # Token expired but within grace period — try to use
                # the claims without full temporal validation
                return self._load_grace_period_token(token)
            logger.warning(
                "Cached token failed verification: %s — removing cache",
                exc,
            )
            _CACHE_FILE.unlink(missing_ok=True)
            return False

        # Verify machine fingerprint
        token_fp = payload.get("fingerprint")
        if token_fp and not verify_fingerprint(token_fp):
            logger.error("Cached token bound to different machine — ignoring")
            _CACHE_FILE.unlink(missing_ok=True)
            return False

        # Token is valid — apply claims
        self._current_token = token
        self._token_payload = payload
        self._apply_token_claims(payload)

        # Check if token needs proactive refresh
        if self.needs_refresh():
            logger.info("Cached token nearing expiry — will attempt refresh")

        return True

    def _load_grace_period_token(self, token: str) -> bool:
        """Attempt to use an expired token within the 7-day grace period.

        Parses claims without strict temporal validation.  The token's
        signature is still verified (just not ``exp``/``nbf``).

        Args:
            token: Expired JWT string.

        Returns:
            True if the token's signature is valid and we can use it
            in degraded mode.
        """
        try:
            # Manually parse and verify signature only (skip exp check)
            parts = token.strip().split(".")
            if len(parts) != 3:
                return False

            from agent.src.crypto import _b64url_decode, _get_public_key
            from cryptography.exceptions import InvalidSignature

            header_b64, payload_b64, sig_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            signature = _b64url_decode(sig_b64)

            public_key = _get_public_key()
            public_key.verify(signature, signing_input)

            # Signature valid — decode payload
            payload_bytes = _b64url_decode(payload_b64)
            payload = json.loads(payload_bytes)

            # Check we're within grace period
            exp = payload.get("exp", 0)
            now = time.time()
            if now > float(exp) + _GRACE_PERIOD_SECONDS:
                return False

            self._current_token = token
            self._token_payload = payload
            self._apply_token_claims(payload)

            logger.warning(
                "Using expired token in grace period — "
                "tier=%s, expired %d hours ago",
                self._tier,
                int((now - float(exp)) / 3600),
            )
            return True

        except (InvalidSignature, Exception) as exc:
            logger.warning("Grace period token verification failed: %s", exc)
            return False

    def _load_cached_legacy(self, data: Dict[str, Any]) -> bool:
        """Load a legacy (unsigned) cached license.

        Backward-compatible path for caches created before the
        signed-token upgrade.

        Args:
            data: Cached license data dict.

        Returns:
            True if the cache is valid and not expired.
        """
        # Check if the API key matches
        if self._api_key and data.get("api_key") != self._api_key:
            return False

        # Check expiry
        expires = data.get("cache_expires", 0)
        if time.time() > expires:
            logger.info("Legacy license cache expired, removing")
            _CACHE_FILE.unlink(missing_ok=True)
            return False

        self._apply_license_data(data)
        logger.info(
            "Using legacy cached license: tier=%s (cached %s)",
            self._tier,
            data.get("cached_at", "unknown"),
        )
        return True

    def _refresh_token(self) -> bool:
        """Request a fresh token from the refresh endpoint.

        Returns:
            True if a new token was obtained and verified.
        """
        if not _HTTPX_AVAILABLE:
            return False

        url = f"{self.api_base}{_REFRESH_ENDPOINT}"
        headers = {
            "X-API-Key": self._api_key,
            "User-Agent": "CleanShift-Agent/1.0",
            "X-Machine-Fingerprint": self._machine_fingerprint or "",
        }
        body = {
            "current_token": self._current_token,
        }

        try:
            with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
                response = client.post(url, json=body, headers=headers)

            if response.status_code == 200:
                data = response.json()
                new_token = data.get("token")
                if new_token and self._api_key:
                    return self._process_signed_token(new_token, self._api_key)
                logger.warning("Refresh response missing token")
                return False

            if response.status_code == 429:
                logger.info("Token refresh rate-limited — will retry later")
                return False

            logger.warning(
                "Token refresh failed: HTTP %d", response.status_code
            )
            return False

        except Exception as exc:
            logger.warning("Token refresh request failed: %s", exc)
            return False

    @staticmethod
    def _hash_api_key(api_key: str) -> str:
        """Create a non-reversible hash of the API key for cache matching.

        Uses SHA-256 so we can verify the correct key is being used
        without storing the key in plaintext in the cache file.

        Args:
            api_key: The raw API key string.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        import hashlib
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _verify_api_key_hash(api_key: str, expected_hash: str) -> bool:
        """Verify an API key against its stored hash.

        Args:
            api_key: The raw API key to check.
            expected_hash: SHA-256 hex digest to compare against.

        Returns:
            True if the hash matches.
        """
        import hashlib
        import hmac
        actual = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual, expected_hash)

    def _show_upgrade_prompt(self, feature_label: str, required_tier: str) -> None:
        """Display a rich upgrade prompt to the console."""
        console.print()
        console.print(
            Panel(
                f"[bold yellow]⚡ {feature_label} requires "
                f"{required_tier.title()} tier.[/bold yellow]\n\n"
                f"Current tier: [dim]{self._tier}[/dim]\n"
                f"Required tier: [bold green]{required_tier}[/bold green]\n\n"
                f"[blue underline]Visit cleanshift.osg.co.in/pricing[/blue underline]",
                title="[bold]🔒 Feature Upgrade Required[/bold]",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
