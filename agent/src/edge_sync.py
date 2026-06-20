"""
Cloudflare WAF Integration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pushes CleanShift Guard threat intelligence to Cloudflare WAF via API.
Syncs blocked IPs from Guard audit logs → Cloudflare IP Access Rules,
giving edge-level protection without running our own CDN.

Features:
    - Push blocked IPs as Cloudflare WAF block rules
    - Create/update IP lists for rate-limited attackers
    - Supports zone-level and account-level rules
    - Dry-run mode for previewing changes
    - Automatic deduplication (won't re-add existing blocks)

Requirements:
    - Cloudflare API Token with Zone.Firewall permissions
    - Zone ID from Cloudflare dashboard

Usage:
    connector = CloudflareConnector(api_token="...", zone_id="...")
    connector.sync_blocked_ips(blocked_ips)
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("cleanshift.cloudflare")

_CF_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareConnector:
    """Syncs Guard blocked IPs to Cloudflare WAF Access Rules."""

    def __init__(
        self,
        api_token: str,
        zone_id: str,
        note_prefix: str = "CleanShift Guard",
        max_rules: int = 200,
    ):
        self.api_token = api_token
        self.zone_id = zone_id
        self.note_prefix = note_prefix
        self.max_rules = max_rules

    # ── Public API ─────────────────────────────────────────────────

    def sync_blocked_ips(
        self,
        blocked_ips: list[dict[str, Any]],
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Sync blocked IPs to Cloudflare WAF access rules.

        Args:
            blocked_ips: List of {"ip": "...", "count": N} dicts.
            dry_run: Preview changes without applying.

        Returns:
            Dict with created, skipped, errors counts.
        """
        if not blocked_ips:
            return {"created": 0, "skipped": 0, "errors": 0}

        # Get existing CleanShift rules to avoid duplicates
        existing = self._get_existing_rules()
        existing_ips = {r["configuration"]["value"] for r in existing}

        to_create = []
        skipped = 0
        for entry in blocked_ips[:self.max_rules]:
            ip = entry["ip"]
            if ip in existing_ips:
                skipped += 1
                continue
            to_create.append(entry)

        if dry_run:
            return {
                "status": "dry_run",
                "would_create": len(to_create),
                "skipped": skipped,
                "existing": len(existing_ips),
                "ips": [e["ip"] for e in to_create],
            }

        created = 0
        errors = 0
        for entry in to_create:
            try:
                self._create_access_rule(
                    ip=entry["ip"],
                    mode="block",
                    notes=f"{self.note_prefix}: {entry.get('count', 0)} blocked events",
                )
                created += 1
            except Exception as e:
                logger.warning("Failed to create CF rule for %s: %s", entry["ip"], e)
                errors += 1

        logger.info(
            "Cloudflare sync: %d created, %d skipped, %d errors",
            created, skipped, errors,
        )
        return {"created": created, "skipped": skipped, "errors": errors}

    def remove_all_cleanshift_rules(self) -> dict[str, Any]:
        """Remove all CleanShift-created rules from Cloudflare."""
        existing = self._get_existing_rules()
        removed = 0
        errors = 0

        for rule in existing:
            try:
                self._delete_access_rule(rule["id"])
                removed += 1
            except Exception as e:
                logger.warning("Failed to delete CF rule %s: %s", rule["id"], e)
                errors += 1

        return {"removed": removed, "errors": errors}

    def list_cleanshift_rules(self) -> list[dict[str, Any]]:
        """List all CleanShift-created rules in Cloudflare."""
        return self._get_existing_rules()

    def test_connection(self) -> dict[str, Any]:
        """Test the Cloudflare API connection and permissions."""
        try:
            result = self._cf_request("GET", f"/zones/{self.zone_id}")
            zone = result.get("result", {})
            return {
                "status": "connected",
                "zone_name": zone.get("name", "unknown"),
                "plan": zone.get("plan", {}).get("name", "unknown"),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── Private Methods ────────────────────────────────────────────

    def _get_existing_rules(self) -> list[dict[str, Any]]:
        """Get all existing CleanShift-created access rules."""
        rules = []
        page = 1

        while True:
            try:
                result = self._cf_request(
                    "GET",
                    f"/zones/{self.zone_id}/firewall/access_rules/rules",
                    params={
                        "page": str(page),
                        "per_page": "50",
                        "notes": self.note_prefix,
                    },
                )
                page_rules = result.get("result", [])
                if not page_rules:
                    break

                # Filter to only CleanShift rules
                for rule in page_rules:
                    if self.note_prefix in (rule.get("notes") or ""):
                        rules.append(rule)

                total_pages = result.get("result_info", {}).get("total_pages", 1)
                if page >= total_pages:
                    break
                page += 1

            except Exception as e:
                logger.warning("Failed to fetch CF rules page %d: %s", page, e)
                break

        return rules

    def _create_access_rule(self, ip: str, mode: str = "block", notes: str = "") -> dict:
        """Create a single IP access rule."""
        return self._cf_request(
            "POST",
            f"/zones/{self.zone_id}/firewall/access_rules/rules",
            body={
                "mode": mode,
                "configuration": {
                    "target": "ip",
                    "value": ip,
                },
                "notes": notes,
            },
        )

    def _delete_access_rule(self, rule_id: str) -> dict:
        """Delete an access rule by ID."""
        return self._cf_request(
            "DELETE",
            f"/zones/{self.zone_id}/firewall/access_rules/rules/{rule_id}",
        )

    def _cf_request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        params: dict[str, str] | None = None,
    ) -> dict:
        """Make an authenticated request to the Cloudflare API."""
        url = f"{_CF_API_BASE}{path}"

        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"

        data = None
        if body:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.api_token}")
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            logger.error("Cloudflare API error %d: %s", e.code, body[:200])
            raise RuntimeError(f"Cloudflare API error {e.code}: {body[:200]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cloudflare API connection failed: {e}") from e
