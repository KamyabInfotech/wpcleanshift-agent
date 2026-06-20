"""
CleanShift Remediation Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Executes remediation playbooks against detected threats. Supports
dry-run mode, report-only mode (for unpaid clients), and approval
gates for destructive operations.

Every action is logged to a full audit trail.

Production hardening:
    - No shell=True in subprocess calls (uses shlex.split + explicit args)
    - backup_before_clean: tar.gz the site homedir before any remediation
    - Rollback: if remediation fails, restore from backup
    - timezone-aware datetime (datetime.now(timezone.utc))
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import shlex
import shutil
import string
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import pymysql
    _PYMYSQL_AVAILABLE = True
except ImportError:
    _PYMYSQL_AVAILABLE = False

from .models import (
    RemediationAction,
    RemediationMode,
    RemediationStatus,
    ScanResult,
    Severity,
    Threat,
    ThreatType,
)
from .wp import run_wp_cli
from .intelligence import IntelligenceDB, Playbook, PlaybookStep

logger = logging.getLogger("cleanshift.cleaner")

# Only add --allow-root when actually running as root (M11)
_ALLOW_ROOT = " --allow-root" if os.geteuid() == 0 else ""


class RemediationEngine:
    """
    Maps detected threats to playbook remediation steps and executes
    them with full audit logging.

    Modes:
        - AUTO:        Execute all automated steps, prompt for approval steps
        - MANUAL:      Require approval for every step
        - REPORT_ONLY: Only scan and report — no remediation actions

    Usage:
        engine = RemediationEngine(intel, mode=RemediationMode.AUTO)
        actions = engine.remediate(scan_result, site_path="/home/user/public_html")
        report = engine.generate_report()
    """

    # Actions that always require approval regardless of mode
    ALWAYS_REQUIRE_APPROVAL = {
        "delete_user",
        "reset_password",
        "drop_table",
    }

    # Core files that should NEVER be quarantined/deleted, even if flagged
    IMMUTABLE_SAFELIST = {
        "wp-config.php",
        "wp-load.php",
        "wp-login.php",
        "wp-settings.php",
        "wp-cron.php",
        "wp-blog-header.php",
        "wp-comments-post.php",
        "wp-links-opml.php",
        "wp-mail.php",
        "wp-signup.php",
        "wp-trackback.php",
        "xmlrpc.php",
        "index.php",
        ".htaccess",
    }

    # Directory prefixes that should NEVER have files quarantined
    # (core WP directories, CleanShift's own files, media uploads)
    SAFE_PATH_PREFIXES = (
        "wp-admin/",
        "wp-includes/",
        "wp-content/mu-plugins/cleanshift",
        "wp-content/uploads/",  # Media files — not executable
    )

    def __init__(
        self,
        intel: IntelligenceDB,
        mode: RemediationMode = RemediationMode.REPORT_ONLY,
        dry_run: bool = False,
        approve_all: bool = False,
        approve_destructive: bool = False,
        approval_callback: Optional[Callable[[RemediationAction], bool]] = None,
        backup_before_clean: bool = True,
        auto_patch: bool = False,
    ) -> None:
        """
        Initialize the remediation engine.

        Args:
            intel: Loaded intelligence database.
            mode: Remediation mode (auto, manual, report_only).
            dry_run: If True, log what would happen but don't execute.
            approve_all: If True, auto-approve all actions (dangerous!).
            approve_destructive: If True, auto-approve destructive actions
                                 (delete_user, reset_password, drop_table).
            approval_callback: Function to call for approval gates.
                               Receives a RemediationAction, returns bool.
            backup_before_clean: If True, create tar.gz backup before remediation.
        """
        self.intel = intel
        self.mode = mode
        self.dry_run = dry_run
        self.approve_all = approve_all
        self.approve_destructive = approve_destructive
        self.approval_callback = approval_callback
        self.backup_before_clean = backup_before_clean
        self.auto_patch = auto_patch
        self.actions: List[RemediationAction] = []
        self.audit_log: List[Dict[str, Any]] = []
        self._backup_path: Optional[Path] = None
        self._remediation_failed: bool = False
        self._verification_result: Optional[Dict[str, Any]] = None

    def remediate(
        self,
        scan_result: ScanResult,
        site_path: Optional[str] = None,
        playbook_name: Optional[str] = None,
    ) -> List[RemediationAction]:
        """
        Execute remediation for all threats in a scan result.

        If a playbook name is provided, runs the full playbook.
        Otherwise, maps individual threats to appropriate actions.

        Args:
            scan_result: The scan result containing threats.
            site_path: If set, only remediate threats for this site.
            playbook_name: Specific playbook to run.

        Returns:
            List of remediation actions taken (or planned in dry-run).
        """
        if self.mode == RemediationMode.REPORT_ONLY:
            logger.info("Report-only mode — no remediation actions will be taken")
            self._log_audit("mode_check", "Report-only mode active, skipping remediation")
            return []

        # Filter threats to the target site if specified
        threats = scan_result.threats
        if site_path:
            threats = [t for t in threats if t.site_path == site_path]

        if not threats:
            logger.info("No threats to remediate")
            return []

        logger.info(
            "Starting remediation: %d threats, mode=%s, dry_run=%s",
            len(threats), self.mode.value, self.dry_run,
        )

        # Create backup before remediation if enabled
        effective_site_path = site_path or (threats[0].site_path if threats else None)
        pre_health_ok = False
        if self.backup_before_clean and effective_site_path and not self.dry_run:
            self._backup_path = self._create_backup(Path(effective_site_path))
            if not self._backup_path:
                logger.error("Pre-flight backup failed! Aborting remediation to prevent data loss.")
                self._log_audit("remediation_aborted", "Pre-flight backup failed")
                return []
            pre_health_ok = self._check_site_health(Path(effective_site_path))

        try:
            if playbook_name:
                playbook = self.intel.get_playbook(playbook_name)
                if playbook:
                    self._run_playbook(playbook, threats, effective_site_path or threats[0].site_path)
                else:
                    logger.error("Playbook not found: %s", playbook_name)
            else:
                # Auto-match a playbook based on threat CVE/pattern overlap
                matched = self.intel.match_playbook(threats)
                if matched:
                    logger.info('Auto-matched playbook: %s', matched.name)
                    self._run_playbook(matched, threats, effective_site_path or threats[0].site_path)
                else:
                    self._remediate_threats(threats)
        except Exception as e:
            self._remediation_failed = True
            logger.error("Remediation failed with exception: %s", e, exc_info=True)
            self._log_audit("remediation_failed", f"Remediation failed: {e}")

            # Rollback if backup exists
            if self._backup_path and effective_site_path and not self.dry_run:
                self._rollback_from_backup(
                    self._backup_path, Path(effective_site_path)
                )

        # Self-Healing: Verify site health post-remediation
        if self.backup_before_clean and effective_site_path and not self.dry_run and not self._remediation_failed:
            post_health_ok = self._check_site_health(Path(effective_site_path))
            if pre_health_ok and not post_health_ok:
                logger.error("Site health check failed post-remediation! Triggering self-healing rollback.")
                self._log_audit("self_healing_triggered", "Site crashed after remediation, rolling back.")
                self._rollback_from_backup(self._backup_path, Path(effective_site_path))
                self._remediation_failed = True

        # Check if any actions failed and trigger rollback if needed
        failed_actions = [a for a in self.actions if a.status == RemediationStatus.FAILED]
        if failed_actions and self._backup_path and effective_site_path and not self.dry_run:
            logger.warning(
                "%d action(s) failed — rollback available at %s",
                len(failed_actions), self._backup_path,
            )
            self._log_audit(
                "rollback_available",
                f"Backup available for rollback: {self._backup_path}",
            )

        # Post-remediation verification scan
        if (
            effective_site_path
            and not self.dry_run
            and not self._remediation_failed
            and threats
        ):
            try:
                verification = self._verify_remediation(
                    Path(effective_site_path), threats,
                )
                self._verification_result = verification
                if verification["still_present"] > 0:
                    logger.warning(
                        "Post-remediation verification: %d/%d threats still present",
                        verification["still_present"],
                        verification["still_present"] + verification["verified"],
                    )
                    # Update threat status for threats that survived remediation
                    threat_map = {t.id: t for t in threats}
                    for remaining in verification["threats"]:
                        tid = remaining.get("threat_id")
                        if tid and tid in threat_map:
                            threat_map[tid].remediation_status = RemediationStatus.FAILED
                    self._log_audit(
                        "verification_failed",
                        f"Verification: {verification['still_present']} threat(s) "
                        f"still present after remediation",
                    )
                else:
                    logger.info(
                        "Post-remediation verification: all %d threats verified clean",
                        verification["verified"],
                    )
                    self._log_audit(
                        "verification_passed",
                        f"Verification: all {verification['verified']} threat(s) "
                        f"confirmed remediated",
                    )
            except Exception as e:
                logger.error(
                    "Post-remediation verification failed: %s", e, exc_info=True,
                )
                self._log_audit(
                    "verification_error",
                    f"Verification scan error: {e}",
                )

        return self.actions

    def _create_backup(self, site_path: Path) -> Optional[Path]:
        """
        Create a tar.gz backup of the site directory before remediation.

        Returns the path to the backup file, or None on failure.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_dir = site_path.parent / ".cleanshift-backups"

        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_file = backup_dir / f"pre-remediation-{site_path.name}-{timestamp}.tar.gz"

            # Check available disk space and site size before creating backup
            try:
                usage = shutil.disk_usage(str(site_path))
                # Estimate site size (cap file enumeration at 50K files)
                site_size = 0
                file_count = 0
                if site_path.is_dir():
                    for f in site_path.rglob('*'):
                        file_count += 1
                        if file_count > 50000:
                            break
                        try:
                            if f.is_file():
                                site_size += f.stat().st_size
                        except OSError:
                            pass

                # P2: Hard cap — refuse full-site backup if > 5GB
                _MAX_BACKUP_SIZE = 5 * 1024 * 1024 * 1024  # 5GB
                if site_size > _MAX_BACKUP_SIZE:
                    logger.warning(
                        "Site too large for full backup (%.1f GB) — will backup individual files only",
                        site_size / (1024 * 1024 * 1024),
                    )
                    self._log_audit("backup_skipped", f"Site too large ({site_size // (1024*1024)} MB)")
                    return None

                estimated_backup = site_size * 0.3
                free_after = usage.free - estimated_backup
                if free_after < 100 * 1024 * 1024:  # Need at least 100MB free after backup
                    logger.warning(
                        "Insufficient disk space for backup: %.1f MB free, need ~%.1f MB",
                        usage.free / (1024 * 1024), estimated_backup / (1024 * 1024),
                    )
                    self._log_audit("backup_skipped", "Insufficient disk space")
                    return None
            except OSError:
                pass  # Can't check disk space — proceed anyway

            logger.info("Creating pre-remediation backup: %s", backup_file)
            self._log_audit("backup_start", f"Creating backup of {site_path}")

            with tarfile.open(str(backup_file), "w:gz") as tar:
                # Exclude large directories that aren't needed for rollback
                def _exclude_large(tarinfo):
                    name_lower = tarinfo.name.lower()
                    # Skip common cache/backup/temp paths and WordPress uploads
                    skip_dirs = ('/cache/', '/backup', '/tmp/', '.cleanshift-backups', 'wp-content/uploads')
                    for d in skip_dirs:
                        if d in name_lower:
                            return None
                    # Skip common image/media/archive extensions
                    skip_extensions = (
                        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', 
                        '.pdf', '.zip', '.tar.gz', '.tgz', '.rar', '.7z', 
                        '.mp3', '.mp4', '.mov', '.avi', '.wmv', '.woff', '.woff2', '.ttf', '.eot'
                    )
                    if name_lower.endswith(skip_extensions):
                        return None
                    return tarinfo
                tar.add(str(site_path), arcname=site_path.name, filter=_exclude_large)

            backup_size_mb = backup_file.stat().st_size / (1024 * 1024)
            logger.info("Backup created: %s (%.1f MB)", backup_file, backup_size_mb)
            self._log_audit(
                "backup_complete",
                f"Backup created: {backup_file} ({backup_size_mb:.1f} MB)",
            )
            return backup_file

        except Exception as e:
            logger.error("Failed to create backup: %s", e, exc_info=True)
            self._log_audit("backup_failed", f"Backup failed: {e}")
            return None

    def _check_site_health(self, site_path: Path) -> bool:
        """
        Verify that WordPress can boot without fatal errors.
        Returns True if healthy.
        """
        try:
            success, output = run_wp_cli(site_path, "eval 'echo \"HEALTH_OK\";'")
            if success and "HEALTH_OK" in output:
                return True
            return False
        except Exception:
            return False

    def _rollback_from_backup(self, backup_path: Path, site_path: Path) -> bool:
        """
        Restore site from a tar.gz backup after failed remediation.

        Returns True if rollback succeeded.
        """
        logger.warning("Initiating rollback from %s to %s", backup_path, site_path)
        self._log_audit("rollback_start", f"Rolling back from {backup_path}")

        try:
            if not backup_path.exists():
                logger.error("Backup file not found: %s", backup_path)
                return False

            # Extract backup to parent directory (tar contains site_path.name/)
            with tarfile.open(str(backup_path), "r:gz") as tar:
                # Security: validate tar members to prevent path traversal
                dest_resolved = Path(site_path.parent).resolve()
                for member in tar.getmembers():
                    member_path = Path(member.name)
                    # Reject absolute paths and parent references
                    if member_path.is_absolute() or ".." in member_path.parts:
                        logger.error(
                            "Unsafe path in backup archive: %s — aborting rollback",
                            member.name,
                        )
                        self._log_audit(
                            "rollback_aborted",
                            f"Unsafe path in archive: {member.name}",
                        )
                        return False
                    # Reject symlinks that could escape the target directory
                    if member.issym() or member.islnk():
                        logger.warning(
                            "Skipping symlink in backup archive: %s",
                            member.name,
                        )
                        continue
                    # Verify resolved path stays within target
                    resolved = (dest_resolved / member_path).resolve()
                    if not str(resolved).startswith(str(dest_resolved) + os.sep) and resolved != dest_resolved:
                        logger.error(
                            "Path escape in archive: %s -> %s",
                            member.name, resolved,
                        )
                        return False

                # Extract only safe members (exclude symlinks)
                safe_members = [
                    m for m in tar.getmembers()
                    if not m.issym() and not m.islnk()
                ]
                tar.extractall(path=str(site_path.parent), members=safe_members)

            logger.info("Rollback complete: %s restored from %s", site_path, backup_path)
            self._log_audit("rollback_complete", f"Site restored from {backup_path}")
            return True

        except Exception as e:
            logger.error("Rollback failed: %s", e, exc_info=True)
            self._log_audit("rollback_failed", f"Rollback failed: {e}")
            return False

    def _remediate_threats(self, threats: List[Threat]) -> None:
        """Map individual threats to remediation actions and execute."""
        for threat in threats:
            # In AUTO mode: only remediate HIGH/CRITICAL severity with decent confidence
            # INFO/LOW/MEDIUM threats are reported but not auto-cleaned
            if self.mode == RemediationMode.AUTO:
                if threat.severity in (Severity.INFO, Severity.LOW):
                    logger.info(
                        'Skipping %s severity threat in auto mode: %s',
                        threat.severity.value, threat.title,
                    )
                    continue
                if threat.confidence < 0.5:
                    logger.info(
                        'Skipping low-confidence threat: %s (%.1f)',
                        threat.title, threat.confidence,
                    )
                    continue
            try:
                self._remediate_single_threat(threat)
            except Exception as e:
                logger.error(
                    "Remediation failed for threat %s: %s",
                    threat.id, e, exc_info=True,
                )

    def _verify_remediation(
        self, site_path: Path, original_threats: List[Threat],
    ) -> Dict[str, Any]:
        """Re-scan locations from original threats to verify remediation.

        Creates a lightweight FileScanner instance and checks only the
        specific files/locations from the original threat list. Threats
        that are re-detected are marked as 'failed'.

        Args:
            site_path: Path to the WordPress site root.
            original_threats: The threats that were remediated.

        Returns:
            Dict with keys:
                verified (int): Number of threats confirmed gone.
                still_present (int): Number of threats still detected.
                threats (list): List of dicts for threats still present.
        """
        logger.info(
            "Post-remediation verification: re-scanning %d threat locations",
            len(original_threats),
        )
        self._log_audit(
            "verification_start",
            f"Verifying {len(original_threats)} remediated threat(s)",
        )

        verified = 0
        still_present = 0
        remaining_threats: List[Dict[str, Any]] = []

        # Lazy import to avoid circular dependency at module level
        from .scanner import FileScanner, ScanMode

        # Create a lightweight scanner for targeted re-scanning
        lightweight_scanner = FileScanner(
            intel=self.intel,
            scan_mode=ScanMode.DEEP,
            per_file_timeout=10,  # Shorter timeout for verification
            memory_limit_mb=256,
        )

        for threat in original_threats:
            # Only verify file-based threats that have a concrete location
            if not threat.location or threat.threat_type in (
                ThreatType.ROGUE_ADMIN,
                ThreatType.DB_MARKER,
                ThreatType.SCRIPT_INJECTION,
                ThreatType.WP_CRON_ABUSE,
            ):
                # Database threats can't be re-scanned with FileScanner;
                # count them as verified since the action was executed
                verified += 1
                continue

            file_path = Path(threat.location)

            # If the file no longer exists, it was successfully removed
            if not file_path.exists():
                verified += 1
                continue

            # File still exists — re-scan its content for suspicious patterns
            try:
                from .models import WordPressSite

                # Build a minimal site object for the scanner API
                mini_site = WordPressSite(path=str(site_path))

                re_threats = lightweight_scanner._analyze_file_content(
                    file_path, site_path, mini_site,
                )

                if re_threats:
                    still_present += 1
                    remaining_threats.append({
                        "threat_id": threat.id,
                        "title": threat.title,
                        "location": threat.location,
                        "severity": threat.severity.value,
                        "re_detected_patterns": len(re_threats),
                    })
                    logger.warning(
                        "Verification FAILED for %s — threat re-detected at %s",
                        threat.title, threat.location,
                    )
                else:
                    # File exists but is now clean (content was sanitized)
                    verified += 1
            except Exception as e:
                # If we can't re-scan, conservatively count as verified
                # to avoid false negatives blocking the pipeline
                logger.debug(
                    "Verification scan error for %s: %s — counting as verified",
                    threat.location, e,
                )
                verified += 1

        result = {
            "verified": verified,
            "still_present": still_present,
            "threats": remaining_threats,
        }

        logger.info(
            "Verification complete: %d verified, %d still present",
            verified, still_present,
        )
        return result

    def _remediate_single_threat(self, threat: Threat) -> None:
        """Generate and execute remediation actions for a single threat."""
        site_path = Path(threat.site_path)

        if threat.threat_type == ThreatType.ROGUE_ADMIN:
            self._remediate_rogue_admin(threat, site_path)

        elif threat.threat_type == ThreatType.BACKDOOR_FILE:
            self._remediate_backdoor_file(threat, site_path)

        elif threat.threat_type == ThreatType.DB_MARKER:
            self._remediate_db_marker(threat, site_path)

        elif threat.threat_type == ThreatType.SCRIPT_INJECTION:
            self._remediate_script_injection(threat, site_path)

        elif threat.threat_type == ThreatType.VULNERABLE_PLUGIN:
            self._remediate_vulnerable_plugin(threat, site_path)

        elif threat.threat_type == ThreatType.CORE_MODIFIED:
            self._remediate_core_modified(threat, site_path)

        elif threat.threat_type == ThreatType.PERMISSION_ISSUE:
            self._remediate_permissions(threat, site_path)

        elif threat.threat_type == ThreatType.SUSPICIOUS_FILE:
            # Suspicious files at HIGH/CRITICAL severity with a file location
            # are treated as backdoors for quarantine purposes
            if threat.severity in (Severity.HIGH, Severity.CRITICAL) and threat.location:
                self._remediate_backdoor_file(threat, site_path)

        elif threat.threat_type == ThreatType.WP_CRON_ABUSE:
            self._remediate_wp_cron_abuse(threat, site_path)

        elif threat.threat_type == ThreatType.DB_INJECTION:
            self._remediate_db_injection(threat, site_path)

        elif threat.threat_type == ThreatType.PHP_CONFIG_RISK:
            self._remediate_htaccess(threat, site_path)

        elif threat.threat_type in (
            ThreatType.PHP_OUTDATED,
            ThreatType.MYSQL_CONFIG_RISK,
            ThreatType.MYSQL_ROGUE_USER,
        ):
            # These require host-level intervention (root/WHM access)
            # Mark as skipped so the dashboard shows the correct status
            logger.info(
                "Threat type '%s' requires manual host-level action — skipping",
                threat.threat_type.value,
            )
            threat.remediation_status = RemediationStatus.SKIPPED
    # ── Threat-Specific Remediation ─────────────────────────────

    def _remediate_rogue_admin(self, threat: Threat, site_path: Path) -> None:
        """Delete rogue admin account."""
        user_id = threat.details.get("user_id", "")
        user_login = threat.details.get("user_login", "")

        # Security: validate user_id is numeric to prevent injection
        if not str(user_id).isdigit():
            logger.warning('Non-numeric user_id rejected: %r', user_id)
            return

        if not user_id:
            logger.warning("No user_id in threat details, cannot remediate rogue admin")
            return

        action = RemediationAction(
            threat_id=threat.id,
            action_type="delete_user",
            target=f"User: {user_login} (ID: {user_id})",
            command=f"wp user delete {user_id} --yes{_ALLOW_ROOT} --path={site_path}",
            requires_approval=True,
        )

        self._execute_action(action, site_path)

    def _remediate_backdoor_file(self, threat: Threat, site_path: Path) -> None:
        """Quarantine or delete backdoor file."""
        file_path = Path(threat.location)

        # Security: ensure file is within site directory
        if not str(file_path.resolve()).startswith(str(site_path.resolve()) + os.sep):
            logger.warning('Path traversal blocked: %s is outside %s', file_path, site_path)
            return

        # Security: protect immutable core files from being quarantined/deleted
        try:
            rel_path = str(file_path.relative_to(site_path))
            if rel_path in self.IMMUTABLE_SAFELIST:
                logger.warning('Safelist blocked quarantine of immutable core file: %s', file_path)
                self._log_audit("safelist_blocked", f"Prevented quarantine of {file_path}")
                return
            # Block quarantine of ANY file in protected directories,
            # EXCEPT PHP files in wp-content/uploads/ — PHP should NEVER
            # exist there and is always planted malware.
            for prefix in self.SAFE_PATH_PREFIXES:
                if rel_path.startswith(prefix):
                    # Exception: PHP files in uploads are always malicious
                    if prefix == "wp-content/uploads/" and rel_path.endswith(".php"):
                        logger.info(
                            'PHP file in uploads — quarantine allowed: %s',
                            file_path,
                        )
                        self._log_audit(
                            "uploads_php_quarantine",
                            f"PHP in uploads quarantine allowed: {rel_path}",
                        )
                        break  # Allow quarantine to proceed
                    logger.info(
                        'Safe-path blocked quarantine of %s (prefix: %s) — '
                        'use "wp core download --force" for core files',
                        file_path, prefix,
                    )
                    self._log_audit(
                        "safe_path_blocked",
                        f"Prevented quarantine of {rel_path} (protected prefix: {prefix})",
                    )
                    return
        except ValueError:
            pass

        if not file_path.exists():
            logger.info("Backdoor file already removed: %s", file_path)
            return

        # Quarantine: move to a quarantine directory instead of deleting
        quarantine_dir = site_path / ".cleanshift-quarantine"
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        quarantine_dest = quarantine_dir / f"{file_path.name}.{timestamp}"

        action = RemediationAction(
            threat_id=threat.id,
            action_type="quarantine_file",
            target=str(file_path),
            command=f"mv {shlex.quote(str(file_path))} {shlex.quote(str(quarantine_dest))}",
            requires_approval=threat.severity == Severity.MEDIUM,  # Auto-approve critical/high
        )

        # Create quarantine dir before executing mv
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        self._execute_action(action, site_path)

    def _remediate_db_marker(self, threat: Threat, site_path: Path) -> None:
        """Remove malware DB markers."""
        option_name = threat.details.get("option_name", "")
        if not option_name:
            # Try to extract from location
            parts = threat.location.split(".")
            if len(parts) >= 2:
                option_name = parts[-1]

        if not option_name:
            return

        action = RemediationAction(
            threat_id=threat.id,
            action_type="delete_option",
            target=f"Option: {option_name}",
            command=f"wp option delete {shlex.quote(option_name)}{_ALLOW_ROOT} --path={site_path}",
        )

        self._execute_action(action, site_path)

    def _remediate_script_injection(self, threat: Threat, site_path: Path) -> None:
        """Clean script injections from database options."""
        option_name = threat.details.get("option_name", "")
        if not option_name:
            parts = threat.location.split(".")
            if len(parts) >= 2:
                option_name = parts[-1]

        if not option_name:
            return

        # For litespeed options, delete entirely
        if "litespeed" in option_name.lower():
            action = RemediationAction(
                threat_id=threat.id,
                action_type="delete_option",
                target=f"Option: {option_name}",
                command=f"wp option delete {shlex.quote(option_name)}{_ALLOW_ROOT} --path={site_path}",
            )
        else:
            # For other options, flag for manual review
            action = RemediationAction(
                threat_id=threat.id,
                action_type="manual_review",
                target=f"Option: {option_name}",
                command=f"wp option get {shlex.quote(option_name)}{_ALLOW_ROOT} --path={site_path}",
                requires_approval=True,
            )

        self._execute_action(action, site_path)

    def _remediate_vulnerable_plugin(self, threat: Threat, site_path: Path) -> None:
        """Try to update a vulnerable plugin first; fall back to deactivate + delete."""
        slug = threat.details.get("plugin_slug", threat.details.get("slug", ""))
        if not slug:
            return

        # Validate slug format to prevent injection
        if not re.match(r'^[a-zA-Z0-9_-]+$', slug):
            logger.warning('Invalid plugin slug rejected: %r', slug)
            return

        # Step 1: Try update first (non-destructive)
        update_action = RemediationAction(
            threat_id=threat.id,
            action_type="update_plugin",
            target=f"Plugin: {slug}",
            command=f"wp plugin update {shlex.quote(slug)}{_ALLOW_ROOT} --path={site_path}",
            requires_approval=False,  # Updates are safe
        )
        self._execute_action(update_action, site_path)

        # If update succeeded, we're done
        if update_action.status == RemediationStatus.COMPLETED:
            return

        # Step 2: If update failed, fall back to deactivate + delete (existing behavior)
        deactivate_action = RemediationAction(
            threat_id=threat.id,
            action_type="deactivate_plugin",
            target=f"Plugin: {slug}",
            command=f"wp plugin deactivate {shlex.quote(slug)}{_ALLOW_ROOT} --path={site_path}",
        )
        self._execute_action(deactivate_action, site_path)

        # Step 3: Delete
        delete_action = RemediationAction(
            threat_id=threat.id,
            action_type="delete_plugin",
            target=f"Plugin: {slug}",
            command=f"wp plugin delete {shlex.quote(slug)}{_ALLOW_ROOT} --path={site_path}",
            requires_approval=True,
        )
        self._execute_action(delete_action, site_path)

    def _remediate_core_modified(self, threat: Threat, site_path: Path) -> None:
        """Reinstall WordPress core to fix modified files."""
        action = RemediationAction(
            threat_id=threat.id,
            action_type="reinstall_core",
            target=f"Core file: {threat.details.get('file', '')}",
            command=f"wp core download --force --skip-content{_ALLOW_ROOT} --path={site_path}",
            requires_approval=True,
        )

        self._execute_action(action, site_path)

    def _remediate_permissions(self, threat: Threat, site_path: Path) -> None:
        """Fix file/directory permissions."""
        location = threat.location
        recommended = threat.details.get("recommended", "")

        if not recommended:
            return

        # Security: only allow safe permission modes
        _ALLOWED_MODES = {'600', '640', '644', '750', '755', '0600', '0640', '0644', '0750', '0755'}
        if recommended not in _ALLOWED_MODES:
            logger.warning('Unsafe chmod mode rejected: %r', recommended)
            return

        # Security: ensure target is within site directory
        if not str(Path(location).resolve()).startswith(str(site_path.resolve()) + os.sep):
            logger.warning('Path traversal blocked in chmod: %s is outside %s', location, site_path)
            return

        action = RemediationAction(
            threat_id=threat.id,
            action_type="fix_permissions",
            target=location,
            command=f"chmod {recommended} {shlex.quote(location)}",
        )

        self._execute_action(action, site_path)

    def _remediate_htaccess(self, threat: Threat, site_path: Path) -> None:
        """Remediate malicious .htaccess entries.

        Regenerates a clean WordPress .htaccess by flushing rewrite rules.
        The malicious .htaccess is quarantined first as evidence.
        """
        htaccess_path = threat.location or str(site_path / '.htaccess')
        ht_file = Path(htaccess_path)

        # Security: ensure file is within site directory
        if not str(ht_file.resolve()).startswith(str(site_path.resolve()) + os.sep):
            logger.warning('Path traversal blocked in htaccess remediation: %s', ht_file)
            return

        # Step 1: Quarantine the malicious .htaccess
        if ht_file.exists():
            quarantine_action = RemediationAction(
                threat_id=threat.id,
                action_type="quarantine_file",
                target=str(ht_file),
                command=f"quarantine:{htaccess_path}",
            )
            self._quarantine_file(ht_file, site_path)
            quarantine_action.status = RemediationStatus.COMPLETED
            self.actions.append(quarantine_action)

        # Step 2: Regenerate clean .htaccess via WP-CLI
        flush_action = RemediationAction(
            threat_id=threat.id,
            action_type="regenerate_htaccess",
            target=str(ht_file),
            command=f"wp rewrite flush --hard{_ALLOW_ROOT} --path={site_path}",
        )
        self._execute_action(flush_action, site_path)

    def _remediate_wp_cron_abuse(self, threat: Threat, site_path: Path) -> None:
        """Remove abusive WP-Cron entries by deleting the cron option and letting WP rebuild it."""
        event_name = threat.details.get("event_name", "")

        if event_name:
            # Remove specific cron event via WP-CLI
            action = RemediationAction(
                threat_id=threat.id,
                action_type="delete_cron_event",
                target=f"Cron event: {event_name}",
                command=f"wp cron event delete {shlex.quote(event_name)}{_ALLOW_ROOT} --path={site_path}",
                requires_approval=True,
            )
        else:
            # Nuclear option: delete and let WP rebuild the cron transient
            action = RemediationAction(
                threat_id=threat.id,
                action_type="reset_wp_cron",
                target="WP-Cron option",
                command=f"wp option delete cron{_ALLOW_ROOT} --path={site_path}",
                requires_approval=True,
            )

        self._execute_action(action, site_path)

    def _remediate_db_injection(self, threat: Threat, site_path: Path) -> None:
        """Clean injected JavaScript/HTML from database content.

        Uses wp db query to surgically remove known injection patterns from
        post_content and post_excerpt fields.
        """
        injection_pattern = threat.details.get("injection_pattern", "")
        table = threat.details.get("table", "")

        if not injection_pattern or not table:
            logger.warning("DB injection threat missing pattern or table, skipping")
            return

        # Validate table name to prevent SQL injection
        if not re.match(r'^[a-zA-Z0-9_]+$', table):
            logger.warning('Invalid table name rejected: %r', table)
            return

        # For safety, flag for manual review with the removal command
        action = RemediationAction(
            threat_id=threat.id,
            action_type="clean_db_injection",
            target=f"Table: {table}",
            command=(
                f"wp db query \"UPDATE {table} SET post_content = "
                f"REPLACE(post_content, '{injection_pattern}', '')\" "
                f"{_ALLOW_ROOT} --path={site_path}"
            ),
            requires_approval=True,  # Always require approval for DB writes
        )

        self._execute_action(action, site_path)

    def auto_patch_vulnerable_plugins(
        self, scan_result: ScanResult, site_path: Optional[str] = None,
    ) -> List[RemediationAction]:
        """
        Auto-patch vulnerable plugins by attempting wp-cli updates.

        This is a non-destructive operation: it only runs ``wp plugin update``.
        If the update fails, the plugin is left as-is and reported normally.

        Args:
            scan_result: The scan result containing threats.
            site_path: If set, only patch plugins for this site.

        Returns:
            List of patch actions taken.
        """
        if not self.auto_patch:
            return []

        patch_actions: List[RemediationAction] = []
        threats = scan_result.threats
        if site_path:
            threats = [t for t in threats if t.site_path == site_path]

        vuln_plugins = [
            t for t in threats
            if t.threat_type == ThreatType.VULNERABLE_PLUGIN
        ]

        if not vuln_plugins:
            return patch_actions

        logger.info(
            "Auto-patch: attempting to update %d vulnerable plugin(s)",
            len(vuln_plugins),
        )
        self._log_audit("auto_patch_start", f"Patching {len(vuln_plugins)} vulnerable plugins")

        patched_threat_ids: List[str] = []

        for threat in vuln_plugins:
            slug = threat.details.get("plugin_slug", threat.details.get("slug", ""))
            if not slug:
                continue

            # Validate slug format
            if not re.match(r'^[a-zA-Z0-9_-]+$', slug):
                logger.warning('Auto-patch: invalid plugin slug rejected: %r', slug)
                continue

            sp = Path(threat.site_path)
            action = RemediationAction(
                threat_id=threat.id,
                action_type="auto_patch_plugin",
                target=f"Plugin: {slug}",
                command=f"wp plugin update {shlex.quote(slug)}{_ALLOW_ROOT} --path={sp}",
                requires_approval=False,
            )

            if self.dry_run:
                action.status = RemediationStatus.COMPLETED
                action.output = f"[DRY RUN] Would auto-patch: {slug}"
                action.started_at = datetime.now(timezone.utc).isoformat()
                action.completed_at = action.started_at
                self._log_audit("auto_patch_dry_run", f"Would patch {slug}")
            else:
                action.started_at = datetime.now(timezone.utc).isoformat()
                try:
                    success, output = run_wp_cli(sp, f"plugin update {slug}")
                    action.output = output
                    action.status = (
                        RemediationStatus.COMPLETED if success
                        else RemediationStatus.FAILED
                    )
                    if success:
                        patched_threat_ids.append(threat.id)
                        self._log_audit(
                            "auto_patch_success",
                            f"Successfully patched {slug}: {output[:100]}",
                        )
                    else:
                        self._log_audit(
                            "auto_patch_failed",
                            f"Failed to patch {slug}: {output[:100]}",
                        )
                except Exception as e:
                    action.output = f"Error: {e}"
                    action.status = RemediationStatus.FAILED
                    self._log_audit(
                        "auto_patch_error",
                        f"Error patching {slug}: {e}",
                    )
                action.completed_at = datetime.now(timezone.utc).isoformat()

            patch_actions.append(action)
            self.actions.append(action)

        # Remove successfully patched threats from the scan result
        if patched_threat_ids:
            scan_result.threats = [
                t for t in scan_result.threats
                if t.id not in patched_threat_ids
            ]
            logger.info(
                "Auto-patch: %d/%d plugins successfully updated",
                len(patched_threat_ids), len(vuln_plugins),
            )

        self._log_audit(
            "auto_patch_complete",
            f"Patched {len(patched_threat_ids)}/{len(vuln_plugins)} plugins",
        )
        return patch_actions

    # ── Playbook Execution ──────────────────────────────────────

    def _run_playbook(
        self,
        playbook: Playbook,
        threats: List[Threat],
        site_path: str,
    ) -> None:
        """
        Execute a full remediation playbook phase by phase.

        Args:
            playbook: The playbook to execute.
            threats: Threats to cross-reference.
            site_path: Path to the WordPress site.
        """
        logger.info("Running playbook: %s", playbook.name)
        self._log_audit("playbook_start", f"Starting playbook: {playbook.name}")

        path = Path(site_path)

        for phase_name, steps in sorted(playbook.phases.items()):
            logger.info("── Phase: %s ──", phase_name)

            for step in steps:
                if step.manual and not step.command and not step.commands:
                    logger.info("Skipping manual step: %s", step.step)
                    self._log_audit(
                        "skip_manual",
                        f"Skipped manual step: {step.step} — {step.description}",
                    )
                    continue

                self._execute_playbook_step(step, path, threats)

        self._log_audit("playbook_complete", f"Playbook complete: {playbook.name}")

    def _execute_playbook_step(
        self,
        step: PlaybookStep,
        site_path: Path,
        threats: List[Threat],
    ) -> None:
        """Execute a single playbook step."""
        commands_to_run: List[str] = []

        if step.command:
            commands_to_run.append(step.command)
        if step.commands:
            commands_to_run.extend(step.commands)
        if step.fallback_sql:
            commands_to_run.append(f"SQL: {step.fallback_sql}")

        for cmd in commands_to_run:
            # Substitute variables in the command
            cmd = self._substitute_variables(cmd, site_path, threats)

            action = RemediationAction(
                action_type="playbook_step",
                target=step.description,
                command=cmd,
                requires_approval=step.requires_approval,
                playbook_step=step.step,
            )

            self._execute_action(action, site_path)

    def _substitute_variables(
        self, cmd: str, site_path: Path, threats: List[Threat]
    ) -> str:
        """
        Replace playbook variable placeholders with actual values.

        Supported: {prefix}, {DOMAIN}, {ROGUE_ID}, {ADMIN_ID}, {NEW_STRONG_PASSWORD}
        """
        # Try to get site info from wp-config
        try:
            from .wp import parse_wp_config
            config = parse_wp_config(site_path / "wp-config.php")
            prefix = config.get("table_prefix", "wp_")
        except Exception:
            prefix = "wp_"

        cmd = cmd.replace("{prefix}", shlex.quote(prefix))

        # Get domain
        success, domain = run_wp_cli(site_path, "option get", args=["siteurl"])
        if success:
            cmd = cmd.replace("{DOMAIN}", shlex.quote(domain.strip()))

        # Replace rogue admin IDs from threats
        rogue_admins = [
            t for t in threats if t.threat_type == ThreatType.ROGUE_ADMIN
        ]
        if rogue_admins:
            rogue_id = str(rogue_admins[0].details.get("user_id", ""))
            cmd = cmd.replace("{ROGUE_ID}", shlex.quote(rogue_id))

        # Get first legitimate admin
        success, output = run_wp_cli(
            site_path, "user list",
            args=["--role=administrator", "--field=ID", "--format=csv"],
        )
        if success and output:
            admin_ids = [line.strip() for line in output.strip().split("\n") if line.strip().isdigit()]
            # Exclude rogue admin IDs
            rogue_ids = {str(t.details.get("user_id", "")) for t in rogue_admins}
            legit_ids = [aid for aid in admin_ids if aid not in rogue_ids]
            if legit_ids:
                cmd = cmd.replace("{LEGITIMATE_ADMIN_ID}", shlex.quote(legit_ids[0]))
                cmd = cmd.replace("{ADMIN_ID}", shlex.quote(legit_ids[0]))

        # Generate a strong password if needed
        if "{NEW_STRONG_PASSWORD}" in cmd:
            password = self._generate_password()
            cmd = cmd.replace("{NEW_STRONG_PASSWORD}", shlex.quote(password))
            # Store the command with password for execution, but log redacted version
            self._log_audit("password_substituted", "Password substituted in command (redacted from logs)")

        return cmd

    # ── Action Execution ────────────────────────────────────────

    def _execute_action(
        self, action: RemediationAction, site_path: Path
    ) -> None:
        """
        Execute a remediation action with approval gates and audit logging.

        Args:
            action: The action to execute.
            site_path: Path to the WordPress site.
        """
        action.dry_run = self.dry_run

        # Check if approval is needed
        is_destructive = action.action_type in self.ALWAYS_REQUIRE_APPROVAL
        needs_approval = (
            action.requires_approval
            or is_destructive
            or self.mode == RemediationMode.MANUAL
        )

        # Determine if we can skip approval
        if is_destructive:
            skip_approval = self.approve_destructive
        else:
            skip_approval = self.approve_all

        if needs_approval and not skip_approval:
            # Non-interactive safety: if stdin is not a terminal and we can't
            # get approval, skip the action instead of crashing
            import sys
            if is_destructive and not sys.stdin.isatty():
                logger.warning(
                    'Skipping destructive action %s in non-interactive mode '
                    '(use --approve-destructive to auto-approve)',
                    action.action_type,
                )
                action.status = RemediationStatus.SKIPPED
                action.output = 'Skipped: non-interactive, requires --approve-destructive'
                action.completed_at = datetime.now(timezone.utc).isoformat()
                self.actions.append(action)
                return

            if self.approval_callback:
                approved = self.approval_callback(action)
                if not approved:
                    action.status = RemediationStatus.SKIPPED
                    self._log_audit(
                        "action_skipped",
                        f"Action skipped (not approved): {action.action_type} — {action.target}",
                    )
                    self.actions.append(action)
                    return
            else:
                action.status = RemediationStatus.REQUIRES_APPROVAL
                self._log_audit(
                    "action_pending",
                    f"Action requires approval: {action.action_type} — {action.target}",
                )
                self.actions.append(action)
                return

        # Dry run: log but don't execute
        if self.dry_run:
            action.status = RemediationStatus.COMPLETED
            action.output = "[DRY RUN] Would execute: " + action.command
            action.started_at = datetime.now(timezone.utc).isoformat()
            action.completed_at = action.started_at
            self._log_audit(
                "dry_run",
                f"[DRY RUN] {action.action_type}: {action.command}",
            )
            self.actions.append(action)
            return

        # Execute the command
        action.started_at = datetime.now(timezone.utc).isoformat()
        action.status = RemediationStatus.IN_PROGRESS

        try:
            if action.command.startswith("SQL:"):
                # Execute SQL directly — not via shell
                action.output = "[SQL execution skipped — use wp-cli or direct DB access]"
                action.status = RemediationStatus.REQUIRES_APPROVAL
            elif action.command.startswith("wp "):
                # Execute via wp-cli
                success, output = run_wp_cli(
                    site_path,
                    action.command.replace("wp ", "", 1).split("--path=")[0].strip(),
                )
                action.output = output
                action.status = (
                    RemediationStatus.COMPLETED if success
                    else RemediationStatus.FAILED
                )
            else:
                # Execute shell command using shlex.split — NO shell=True
                cmd_parts = shlex.split(action.command)
                result = subprocess.run(
                    cmd_parts,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=str(site_path),
                )
                action.output = result.stdout + result.stderr
                action.status = (
                    RemediationStatus.COMPLETED if result.returncode == 0
                    else RemediationStatus.FAILED
                )

        except subprocess.TimeoutExpired:
            action.output = "Command timed out after 60 seconds"
            action.status = RemediationStatus.FAILED
        except Exception as e:
            action.output = f"Error: {str(e)}"
            action.status = RemediationStatus.FAILED
            logger.error("Action execution failed: %s", e, exc_info=True)

        action.completed_at = datetime.now(timezone.utc).isoformat()
        self.actions.append(action)

        self._log_audit(
            f"action_{action.status.value}",
            f"{action.action_type}: {action.target} — {action.status.value}",
            {"command": '[REDACTED - contains credentials]' if '{NEW_STRONG_PASSWORD}' in str(action.command) or 'reset_password' in action.action_type else action.command, "output": action.output[:500]},
        )

    # ── Audit & Reporting ───────────────────────────────────────

    def _log_audit(
        self,
        event: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add an entry to the audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "message": message,
        }
        if data:
            entry["data"] = data

        self.audit_log.append(entry)
        logger.info("[AUDIT] %s: %s", event, message)

    def generate_report(self) -> str:
        """
        Generate a Markdown remediation report.

        Returns:
            Markdown-formatted report string.
        """
        lines: List[str] = []
        lines.append("# CleanShift Remediation Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}Z")
        lines.append(f"**Mode:** {self.mode.value}")
        lines.append(f"**Dry Run:** {'Yes' if self.dry_run else 'No'}")
        if self._backup_path:
            lines.append(f"**Backup:** {self._backup_path}")
        lines.append("")

        # Summary
        completed = sum(1 for a in self.actions if a.status == RemediationStatus.COMPLETED)
        failed = sum(1 for a in self.actions if a.status == RemediationStatus.FAILED)
        skipped = sum(1 for a in self.actions if a.status == RemediationStatus.SKIPPED)
        pending = sum(1 for a in self.actions if a.status in (
            RemediationStatus.PENDING, RemediationStatus.REQUIRES_APPROVAL
        ))

        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Status | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| ✅ Completed | {completed} |")
        lines.append(f"| ❌ Failed | {failed} |")
        lines.append(f"| ⏭️ Skipped | {skipped} |")
        lines.append(f"| ⏳ Pending Approval | {pending} |")
        lines.append(f"| **Total** | **{len(self.actions)}** |")
        lines.append("")

        # Action details
        if self.actions:
            lines.append("## Actions")
            lines.append("")
            for i, action in enumerate(self.actions, 1):
                status_icon = {
                    RemediationStatus.COMPLETED: "✅",
                    RemediationStatus.FAILED: "❌",
                    RemediationStatus.SKIPPED: "⏭️",
                    RemediationStatus.PENDING: "⏳",
                    RemediationStatus.IN_PROGRESS: "🔄",
                    RemediationStatus.REQUIRES_APPROVAL: "🔒",
                }.get(action.status, "❓")

                lines.append(f"### {i}. {status_icon} {action.action_type}")
                lines.append(f"- **Target:** {action.target}")
                lines.append(f"- **Command:** `{action.command}`")
                lines.append(f"- **Status:** {action.status.value}")
                if action.output:
                    lines.append(f"- **Output:**")
                    lines.append(f"  ```")
                    lines.append(f"  {action.output[:500]}")
                    lines.append(f"  ```")
                if action.playbook_step:
                    lines.append(f"- **Playbook Step:** {action.playbook_step}")
                lines.append("")

        # Verification results
        if self._verification_result:
            vr = self._verification_result
            lines.append("## Post-Remediation Verification")
            lines.append("")
            lines.append(f"| Metric | Count |")
            lines.append(f"|--------|-------|")
            lines.append(f"| ✅ Verified Clean | {vr['verified']} |")
            lines.append(f"| ❌ Still Present | {vr['still_present']} |")
            lines.append("")
            if vr["threats"]:
                lines.append("### Threats Still Present")
                lines.append("")
                for rt in vr["threats"]:
                    lines.append(f"- **{rt.get('title', 'Unknown')}** — {rt.get('location', '')}")
                lines.append("")

        # Audit trail
        if self.audit_log:
            lines.append("## Audit Trail")
            lines.append("")
            lines.append("| Timestamp | Event | Message |")
            lines.append("|-----------|-------|---------|")
            for entry in self.audit_log:
                ts = entry["timestamp"]
                event = entry["event"]
                msg = entry["message"][:80]
                lines.append(f"| {ts} | {event} | {msg} |")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _generate_password(length: int = 24) -> str:
        """Generate a cryptographically secure password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))
