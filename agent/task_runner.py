#!/usr/bin/env python3
"""CleanShift Task Runner — polls API for remediation tasks and executes them."""

import argparse
import json
import logging
import os
import shutil
import subprocess
import time
import yaml
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_PATH = "/opt/cleanshift/config/config.yaml"
LOG_DIR = Path("/var/log/wpcleanshift")
LOG_FILE = LOG_DIR / "task-runner.log"
QUARANTINE_DIR_NAME = ".wpcleanshift-quarantine"
POLL_INTERVAL = 15  # seconds
SUBPROCESS_TIMEOUT = 120  # seconds

# Suspicious .htaccess directives that indicate compromise
HTACCESS_SUSPICIOUS_PATTERNS = [
    "RewriteRule .* https?://",      # redirects to external domains
    "php_value auto_prepend_file",    # auto-loads malicious PHP
    "php_value auto_append_file",
    "SetHandler application/x-httpd-php",  # execute non-PHP as PHP
    "<FilesMatch",                    # conditional execution blocks
    "eval(base64_decode",             # obfuscated code injection
]

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """Configure logging to file and stderr."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("cleanshift-task-runner")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler
    fh = logging.FileHandler(str(LOG_FILE))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Stderr handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


log = setup_logging()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config(path: str = CONFIG_PATH) -> dict:
    """Load agent configuration from YAML file."""
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(cfg_path, "r") as f:
        cfg = yaml.safe_load(f)

    api_cfg = cfg.get("api", {})
    api_url = api_cfg.get("url")
    api_key = api_cfg.get("key")

    if not api_url or not api_key:
        raise ValueError("Config must contain api.url and api.key")

    return {"api_url": api_url.rstrip("/"), "api_key": api_key}

# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def api_get(url: str, api_key: str) -> list:
    """GET request to the API; returns parsed JSON (expects a list)."""
    req = Request(url, method="GET")
    req.add_header("X-API-Key", api_key)
    req.add_header("Accept", "application/json")

    with urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def api_post(url: str, api_key: str, payload: dict) -> dict:
    """POST JSON to the API; returns parsed JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, method="POST")
    req.add_header("X-API-Key", api_key)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    with urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def extract_site_path(location: str) -> str:
    """Extract the WordPress site root from a full file path.

    Everything before /wp-content/ is considered the site root.
    Falls back to dirname if wp-content is not in the path.
    """
    marker = "/wp-content/"
    idx = location.find(marker)
    if idx != -1:
        return location[:idx]
    # Fallback: try wp-includes, wp-admin
    for alt in ("/wp-includes/", "/wp-admin/"):
        idx = location.find(alt)
        if idx != -1:
            return location[:idx]
    return str(Path(location).parent)


def extract_plugin_slug(location: str) -> str:
    """Extract the plugin slug from a path.

    Example: /var/www/site/wp-content/plugins/contact-form-7/readme.txt
             → contact-form-7
    If location IS the plugins directory itself, return empty string.
    """
    parts = Path(location).parts
    try:
        plugins_idx = parts.index("plugins")
        if plugins_idx + 1 < len(parts):
            return parts[plugins_idx + 1]
    except ValueError:
        pass
    # If path ends with 'plugins' or 'wp-content', it's the dir itself — no single slug
    basename = Path(location).name
    if basename in ("plugins", "wp-content", "mu-plugins"):
        return ""
    # Fallback: parent directory name
    return Path(location).parent.name

# ---------------------------------------------------------------------------
# Shell execution helper
# ---------------------------------------------------------------------------

def run_cmd(cmd: str, timeout: int = SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a shell command and return the CompletedProcess result."""
    log.debug("Executing: %s", cmd)
    result = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
    )
    if result.stdout:
        log.debug("stdout: %s", result.stdout.strip())
    if result.stderr:
        log.debug("stderr: %s", result.stderr.strip())
    return result

# ---------------------------------------------------------------------------
# Remediation handlers
# ---------------------------------------------------------------------------

def handle_vulnerable_plugin(task: dict) -> dict:
    """Update or reinstall a vulnerable plugin."""
    location = task["location"]
    slug = extract_plugin_slug(location)
    site_path = extract_site_path(location)

    # If no specific slug (location is the plugins dir), update ALL plugins
    if not slug:
        log.info("Updating ALL plugins at site '%s'", site_path)
        cmd = f"wp plugin update --all --path={site_path} --allow-root"
        result = run_cmd(cmd)
        if result.returncode == 0:
            return {
                "status": "completed",
                "action_type": "plugin_update",
                "command": cmd,
                "message": f"All plugins updated at {site_path}.",
                "output": result.stdout.strip(),
            }
        return {
            "status": "failed",
            "action_type": "plugin_update",
            "command": cmd,
            "message": f"Failed to update plugins at {site_path}.",
            "output": (result.stderr or result.stdout).strip(),
        }

    log.info("Updating plugin '%s' at site '%s'", slug, site_path)

    # Attempt update first
    cmd = f"wp plugin update {slug} --path={site_path} --allow-root"
    result = run_cmd(cmd)
    if result.returncode == 0:
        return {
            "status": "completed",
            "action_type": "plugin_update",
            "command": cmd,
            "message": f"Plugin '{slug}' updated successfully.",
            "output": result.stdout.strip(),
        }

    # Fallback: force reinstall
    log.warning("Update failed for '%s', attempting force reinstall.", slug)
    cmd2 = f"wp plugin install {slug} --force --path={site_path} --allow-root"
    result = run_cmd(cmd2)
    if result.returncode == 0:
        return {
            "status": "completed",
            "action_type": "plugin_update",
            "command": cmd2,
            "message": f"Plugin '{slug}' force-reinstalled.",
            "output": result.stdout.strip(),
        }

    return {
        "status": "failed",
        "action_type": "plugin_update",
        "command": cmd,
        "message": f"Failed to update/reinstall plugin '{slug}'.",
        "output": (result.stderr or result.stdout).strip(),
    }


def _clean_htaccess(location: str) -> dict:
    """Backup .htaccess and strip suspicious directives."""
    filepath = Path(location)
    if not filepath.exists():
        return {"status": "failed", "message": f".htaccess not found: {location}"}

    # Backup
    backup_path = filepath.with_suffix(".htaccess.bak." + datetime.now().strftime("%Y%m%d%H%M%S"))
    shutil.copy2(str(filepath), str(backup_path))
    log.info("Backed up %s → %s", filepath, backup_path)

    # Read and filter
    original_lines = filepath.read_text().splitlines(keepends=True)
    cleaned_lines = []
    removed_count = 0

    for line in original_lines:
        is_suspicious = any(pat.lower() in line.lower() for pat in HTACCESS_SUSPICIOUS_PATTERNS)
        if is_suspicious:
            removed_count += 1
            log.info("Removed suspicious .htaccess line: %s", line.strip())
        else:
            cleaned_lines.append(line)

    filepath.write_text("".join(cleaned_lines))

    return {
        "status": "completed",
        "action_type": "htaccess_clean",
        "command": f"cleanshift-task-runner: clean_htaccess {location}",
        "message": f"Cleaned .htaccess: removed {removed_count} suspicious directive(s). Backup at {backup_path}.",
    }


def _quarantine_file(location: str) -> dict:
    """Move a malicious file to quarantine directory."""
    filepath = Path(location)
    if not filepath.exists():
        return {"status": "completed", "action_type": "file_quarantine", "command": "already removed", "message": f"File already quarantined/removed: {location}"}

    quarantine_dir = filepath.parent / QUARANTINE_DIR_NAME
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    dest = quarantine_dir / f"{filepath.name}.{timestamp}"
    shutil.move(str(filepath), str(dest))
    log.info("Quarantined %s → %s", filepath, dest)

    return {
        "status": "completed",
        "action_type": "file_quarantine",
        "command": f"mv {filepath} {dest}",
        "message": f"File quarantined: {filepath.name} → {dest}",
    }


def handle_backdoor_file(task: dict) -> dict:
    """Handle backdoor_file threats."""
    location = task["location"]

    if location.endswith(".htaccess"):
        return _clean_htaccess(location)

    if location.endswith("debug.log"):
        cmd = f"rm -f {location}"
        result = run_cmd(cmd)
        if result.returncode == 0:
            return {"status": "completed", "action_type": "config_fix", "command": cmd, "message": f"Deleted debug.log: {location}"}
        return {"status": "failed", "action_type": "config_fix", "command": cmd, "message": f"Failed to delete {location}", "output": result.stderr.strip()}

    return _quarantine_file(location)


def handle_core_modified(task: dict) -> dict:
    """Handle core_modified threats — reinstall core or clean specific files."""
    location = task["location"]

    # If it's a specific file (debug.log, htaccess), handle like backdoor_file
    if location.endswith("debug.log") or location.endswith(".htaccess"):
        return handle_backdoor_file(task)

    # Core integrity failure — attempt wp core download --force
    site_path = extract_site_path(location) if "/wp-content/" in location else location
    cmd = f"wp core download --force --skip-content --allow-root --path={site_path}"
    log.info("Reinstalling WordPress core at '%s'", site_path)
    result = run_cmd(cmd)
    if result.returncode == 0:
        return {
            "status": "completed",
            "action_type": "core_reinstall",
            "command": cmd,
            "message": f"WordPress core reinstalled at {site_path}.",
            "output": result.stdout.strip(),
        }
    return {
        "status": "failed",
        "action_type": "plugin_update",
        "command": cmd,
        "message": f"Failed to reinstall core at {site_path}.",
        "output": (result.stderr or result.stdout).strip(),
    }


def handle_permission_issue(task: dict) -> dict:
    """Fix file/directory permissions or mark CleanShift files as benign."""
    location = task["location"]

    # If it's a known CleanShift file, mark as completed (benign)
    if "cleanshift" in Path(location).name.lower():
        log.info("Skipping CleanShift file (benign): %s", location)
        return {
            "status": "completed",
            "action_type": "config_fix",
            "command": "skip (benign CleanShift file)",
            "message": f"Benign CleanShift file, no action needed: {location}",
        }

    target = Path(location)
    if not target.exists():
        return {"status": "failed", "action_type": "config_fix", "message": f"Path does not exist: {location}"}

    mode = "755" if target.is_dir() else "644"
    cmd = f"chmod {mode} {location}"
    result = run_cmd(cmd)
    if result.returncode == 0:
        return {
            "status": "completed",
            "action_type": "config_fix",
            "command": cmd,
            "message": f"Permissions fixed: chmod {mode} {location}",
        }

    return {
        "status": "failed",
        "action_type": "config_fix",
        "command": cmd,
        "message": f"Failed to fix permissions on {location}",
        "output": result.stderr.strip(),
    }


def handle_rogue_admin(task: dict) -> dict:
    """Delete a rogue admin user via wp-cli."""
    location = task["location"]
    site_path = extract_site_path(location)

    username = task.get("metadata", {}).get("username", "")
    if not username:
        username = task.get("details", {}).get("username", "")

    if not username:
        return {
            "status": "failed",
            "action_type": "user_delete",
            "message": "No username found in task data for rogue_admin remediation.",
        }

    cmd = f"wp user delete {username} --reassign=1 --path={site_path} --allow-root"
    log.info("Deleting rogue admin '%s' at site '%s'", username, site_path)
    result = run_cmd(cmd)

    if result.returncode == 0:
        return {
            "status": "completed",
            "action_type": "user_delete",
            "command": cmd,
            "message": f"Rogue admin '{username}' deleted and posts reassigned.",
            "output": result.stdout.strip(),
        }

    return {
        "status": "failed",
        "action_type": "user_delete",
        "command": cmd,
        "message": f"Failed to delete rogue admin '{username}'.",
        "output": (result.stderr or result.stdout).strip(),
    }


def handle_db_marker(task: dict) -> dict:
    """DB markers require manual intervention."""
    return {
        "status": "failed",
        "action_type": "db_cleanup",
        "command": "manual DB inspection required",
        "message": "Requires manual DB intervention",
    }


def handle_script_injection(task: dict) -> dict:
    """Script injection — attempt wp-cli DB cleanup."""
    location = task["location"]
    site_path = extract_site_path(location)

    injection = task.get("metadata", {}).get("injection", "")
    if injection:
        safe_injection = injection.replace("'", "'\\''")
        cmd = f"wp search-replace '{safe_injection}' '' --all-tables --path={site_path} --allow-root"
        log.info("Attempting wp search-replace for script injection at '%s'", site_path)
        result = run_cmd(cmd)
        if result.returncode == 0:
            return {
                "status": "completed",
                "action_type": "db_cleanup",
                "command": cmd,
                "message": "Script injection cleaned via wp search-replace.",
                "output": result.stdout.strip(),
            }

    return {
        "status": "failed",
        "action_type": "db_cleanup",
        "command": "manual DB inspection required",
        "message": "Requires manual DB intervention",
    }

# ---------------------------------------------------------------------------
# PHP / MySQL / Database-level handlers
# ---------------------------------------------------------------------------

def handle_php_config_risk(task: dict) -> dict:
    """Handle dangerous PHP configuration settings."""
    evidence = task.get("evidence", {})
    if isinstance(evidence, str):
        import json as _json
        try:
            evidence = _json.loads(evidence)
        except (ValueError, TypeError):
            evidence = {}

    setting = evidence.get("setting", "")
    location = task.get("location", "")

    # For rogue .user.ini / php.ini files with auto_prepend_file
    if "auto_prepend_file" in task.get("title", "") or "auto_append_file" in task.get("title", ""):
        filepath = Path(location)
        if filepath.exists() and filepath.name in (".user.ini", "php.ini"):
            return _quarantine_file(location)

    # For server-level php.ini settings, we can't auto-fix safely
    return {
        "status": "completed",
        "action_type": "config_fix",
        "command": f"Audit required: {setting}",
        "message": f"PHP config risk flagged for review: {setting}. "
                   f"Recommended fix: {evidence.get('recommended_fix', 'see documentation')}",
        "output": f"Setting: {setting} = {evidence.get('current_value', 'unknown')}",
    }


def handle_php_outdated(task: dict) -> dict:
    """Handle EOL PHP version detection."""
    evidence = task.get("evidence", {})
    if isinstance(evidence, str):
        import json as _json
        try:
            evidence = _json.loads(evidence)
        except (ValueError, TypeError):
            evidence = {}

    php_version = evidence.get("php_version", "unknown")
    return {
        "status": "completed",
        "action_type": "manual",
        "command": f"PHP version: {php_version}",
        "message": f"PHP {php_version} is End-of-Life. Upgrade required — "
                   f"this cannot be auto-remediated. Recommended: PHP 8.2+",
        "output": f"Current: PHP {php_version}, EOL: {evidence.get('eol_date', 'N/A')}. "
                  "Contact your hosting provider or use WHM > MultiPHP Manager to upgrade.",
    }


def handle_mysql_config_risk(task: dict) -> dict:
    """Handle MySQL misconfigurations (remote root, running as root, etc.)."""
    title = task.get("title", "")

    if "remote access" in title.lower():
        # Try to revoke remote root
        cmd = "mysql -e \"DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1'); FLUSH PRIVILEGES;\" 2>&1"
        result = run_cmd(cmd)
        if result.returncode == 0:
            return {
                "status": "completed",
                "action_type": "config_fix",
                "command": cmd,
                "message": "Revoked remote root access to MySQL.",
                "output": result.stdout.strip() or "Remote root entries removed.",
            }
        return {
            "status": "failed",
            "action_type": "config_fix",
            "command": cmd,
            "message": "Failed to revoke remote root. Manual intervention required.",
            "output": (result.stderr or result.stdout).strip(),
        }

    if "test database" in title.lower():
        # SAFETY: Never auto-drop. Cross-reference against WP databases first.
        # Check if any wp-config.php uses this database name
        check = run_cmd(
            "grep -rh \"DB_NAME\" /home/*/public_html/wp-config.php "
            "/home/*/public_html/*/wp-config.php 2>/dev/null "
            "| grep -oP \"'[^']+'\""
        )
        wp_databases = set()
        if check.returncode == 0:
            wp_databases = {db.strip("'\" \n") for db in check.stdout.split("\n") if db.strip()}

        if "test" in wp_databases or "test_db" in wp_databases:
            return {
                "status": "completed",
                "action_type": "manual",
                "command": "Skipped — database in use by WordPress",
                "message": "Test database name matches a wp-config.php DB_NAME. Not safe to modify.",
                "output": f"WordPress databases found: {wp_databases}",
            }

        # Block access instead of dropping — revoke anonymous user access
        cmd = "mysql -e \"REVOKE ALL PRIVILEGES ON test.* FROM ''@'localhost'; REVOKE ALL PRIVILEGES ON test.* FROM ''@'%'; FLUSH PRIVILEGES;\" 2>&1"
        result = run_cmd(cmd)
        return {
            "status": "completed",
            "action_type": "config_fix",
            "command": cmd,
            "message": "Test database access blocked (not dropped). Review and drop manually if safe.",
            "output": result.stdout.strip() if result.returncode == 0 else "Access revocation attempted",
        }


def handle_mysql_rogue_user(task: dict) -> dict:
    """Handle rogue/anonymous MySQL users."""
    cmd = "mysql -e \"DROP USER IF EXISTS ''@'localhost'; DROP USER IF EXISTS ''@'%'; FLUSH PRIVILEGES;\" 2>&1"
    result = run_cmd(cmd)

    if result.returncode == 0:
        return {
            "status": "completed",
            "action_type": "user_delete",
            "command": cmd,
            "message": "Anonymous MySQL users removed.",
            "output": result.stdout.strip() or "Anonymous users dropped successfully.",
        }
    return {
        "status": "failed",
        "action_type": "user_delete",
        "command": cmd,
        "message": "Failed to remove anonymous MySQL users.",
        "output": (result.stderr or result.stdout).strip(),
    }


def handle_db_injection(task: dict) -> dict:
    """Handle malicious content in WordPress database tables (wp_options, wp_posts)."""
    location = task.get("location", "")
    site_path = extract_site_path(location) if "/wp-content/" in location else location
    evidence = task.get("evidence", {})
    if isinstance(evidence, str):
        import json as _json
        try:
            evidence = _json.loads(evidence)
        except (ValueError, TypeError):
            evidence = {}

    option_name = evidence.get("option_name", "")
    injection_type = evidence.get("injection_type", "unknown")

    if option_name and injection_type in ("script_injection", "redirect_malware", "hidden_iframe"):
        # For known-bad options, delete the option value
        cmd = f"wp option delete {option_name} --path={site_path} --allow-root"
        log.info("Deleting malicious wp_option '%s' at '%s'", option_name, site_path)
        result = run_cmd(cmd)

        if result.returncode == 0:
            return {
                "status": "completed",
                "action_type": "db_cleanup",
                "command": cmd,
                "message": f"Deleted malicious option '{option_name}' ({injection_type}).",
                "output": result.stdout.strip(),
            }
        return {
            "status": "failed",
            "action_type": "db_cleanup",
            "command": cmd,
            "message": f"Failed to delete option '{option_name}'.",
            "output": (result.stderr or result.stdout).strip(),
        }

    if option_name and injection_type == "seo_spam":
        # For SEO spam, try search-replace
        snippet = evidence.get("snippet", "")
        if snippet and len(snippet) > 10:
            safe_snippet = snippet[:100].replace("'", "'\\''")
            cmd = f"wp search-replace '{safe_snippet}' '' --all-tables --path={site_path} --allow-root"
            result = run_cmd(cmd)
            if result.returncode == 0:
                return {
                    "status": "completed",
                    "action_type": "db_cleanup",
                    "command": cmd,
                    "message": f"SEO spam cleaned from database.",
                    "output": result.stdout.strip(),
                }

    return {
        "status": "failed",
        "action_type": "db_cleanup",
        "command": "manual DB inspection required",
        "message": f"DB injection ({injection_type}) requires manual cleanup in option: {option_name}",
    }


def handle_wp_cron_abuse(task: dict) -> dict:
    """Handle malicious wp-cron entries."""
    location = task.get("location", "")
    site_path = extract_site_path(location) if "/wp-content/" in location else location
    evidence = task.get("evidence", {})
    if isinstance(evidence, str):
        import json as _json
        try:
            evidence = _json.loads(evidence)
        except (ValueError, TypeError):
            evidence = {}

    cron_hook = evidence.get("cron_hook", "")
    if cron_hook:
        cmd = f"wp cron event delete {cron_hook} --path={site_path} --allow-root"
        log.info("Deleting suspicious cron hook '%s' at '%s'", cron_hook, site_path)
        result = run_cmd(cmd)

        if result.returncode == 0:
            return {
                "status": "completed",
                "action_type": "db_cleanup",
                "command": cmd,
                "message": f"Malicious cron hook '{cron_hook}' deleted.",
                "output": result.stdout.strip(),
            }
        return {
            "status": "failed",
            "action_type": "db_cleanup",
            "command": cmd,
            "message": f"Failed to delete cron hook '{cron_hook}'.",
            "output": (result.stderr or result.stdout).strip(),
        }

    return {
        "status": "failed",
        "action_type": "db_cleanup",
        "command": "wp cron event list",
        "message": "No cron hook name in task data for removal.",
    }
def handle_site_restore(task: dict) -> dict:
    """Execute full site restoration — the premium cleanup feature."""
    location = task.get("location", "")
    evidence = task.get("evidence", {})
    if isinstance(evidence, str):
        import json as _json
        try:
            evidence = _json.loads(evidence)
        except (ValueError, TypeError):
            evidence = {}

    site_path = location or extract_site_path(location)
    domain = evidence.get("domain", "")
    dry_run = evidence.get("dry_run", False)

    log.info("=== SITE RESTORATION: %s (%s) ===", site_path, domain or "unknown")

    try:
        # Import and run the restoration engine
        sys_path = Path(__file__).parent / "src"
        import sys
        if str(sys_path) not in sys.path:
            sys.path.insert(0, str(sys_path))

        from restore import restore_site
        report = restore_site(site_path, domain=domain, dry_run=dry_run)

        success = report.get("success", False)
        summary = report.get("summary", {})
        duration = report.get("duration_seconds", 0)

        # Submit the full report to the API separately
        task_id = task.get("task_id", task.get("id", "unknown"))
        api_url = task.get("_api_url", "")
        api_key = task.get("_api_key", "")
        if api_url and api_key:
            try:
                api_post(f"{api_url}/remediation/restore/report", api_key, {
                    "threat_id": task_id,
                    "success": success,
                    "report": report,
                })
            except Exception as exc:
                log.warning("Failed to submit restore report: %s", exc)

        return {
            "status": "completed" if success else "failed",
            "action_type": "config_fix",
            "command": "cleanshift restore",
            "message": (
                f"Site restoration {'completed' if success else 'completed with warnings'}. "
                f"Duration: {duration:.0f}s. "
                f"Files quarantined: {summary.get('files_quarantined', 0)}. "
                f"Credentials rotated: {', '.join(summary.get('credentials_rotated', []))}. "
                f"Plugins reinstalled: {len(summary.get('plugins_reinstalled', []))}."
            ),
            "output": json.dumps(summary),
        }

    except Exception as exc:
        log.exception("Site restoration failed for %s", site_path)
        return {
            "status": "failed",
            "action_type": "config_fix",
            "command": "cleanshift restore",
            "message": f"Restoration failed: {exc}",
        }


HANDLERS = {
    "vulnerable_plugin": handle_vulnerable_plugin,
    "backdoor_file": handle_backdoor_file,
    "core_modified": handle_core_modified,
    "permission_issue": handle_permission_issue,
    "rogue_admin": handle_rogue_admin,
    "db_marker": handle_db_marker,
    "script_injection": handle_script_injection,
    # PHP-level
    "php_config_risk": handle_php_config_risk,
    "php_outdated": handle_php_outdated,
    # MySQL-level
    "mysql_config_risk": handle_mysql_config_risk,
    "mysql_rogue_user": handle_mysql_rogue_user,
    # Database-level
    "db_injection": handle_db_injection,
    "wp_cron_abuse": handle_wp_cron_abuse,
    # Full site restoration
    "site_restore": handle_site_restore,
}

# Threat types that require a working WordPress installation
WP_CLI_TYPES = {"vulnerable_plugin", "core_modified", "rogue_admin", "script_injection", "db_injection", "wp_cron_abuse"}

LOCK_DIR = Path("/tmp/cleanshift-locks")


def _lock_path(task_id: str) -> Path:
    """Return the lock file path for a given task."""
    return LOCK_DIR / f"task-{task_id}.lock"


def _acquire_lock(task_id: str) -> bool:
    """Try to acquire a lock for a task. Returns False if already locked."""
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock = _lock_path(task_id)
    if lock.exists():
        # Check age — stale locks older than 5 minutes are released
        age = time.time() - lock.stat().st_mtime
        if age < 300:
            log.debug("Task %s is locked (age=%ds), skipping.", task_id, int(age))
            return False
        log.warning("Releasing stale lock for task %s (age=%ds).", task_id, int(age))
    lock.write_text(str(os.getpid()))
    return True


def _release_lock(task_id: str) -> None:
    """Release the lock for a task."""
    lock = _lock_path(task_id)
    try:
        lock.unlink()
    except FileNotFoundError:
        pass


def preflight_check(task: dict) -> dict | None:
    """Validate preconditions before executing a handler.

    Returns an error dict if pre-flight fails, None if everything is OK.
    """
    location = task.get("location", "")
    threat_type = task.get("threat_type", "unknown")

    if not location:
        return None  # Some tasks (db_marker) may not have a location

    site_path = extract_site_path(location)

    # Check site path exists
    if not Path(site_path).exists():
        return {
            "status": "failed",
            "action_type": "manual",
            "command": f"stat {site_path}",
            "message": f"Site path does not exist: {site_path}",
        }

    # For wp-cli tasks, verify WordPress installation
    if threat_type in WP_CLI_TYPES:
        result = run_cmd(f"wp core is-installed --path={site_path} --allow-root")
        if result.returncode != 0:
            return {
                "status": "failed",
                "action_type": "db_cleanup",
                "command": f"wp core is-installed --path={site_path} --allow-root",
                "message": f"WordPress not installed at {site_path}. "
                           f"wp-cli output: {(result.stderr or result.stdout).strip()[:200]}",
            }

    return None


def verify_remediation(task: dict, handler_result: dict) -> dict:
    """Run post-remediation checks and annotate the result with verification status."""
    if handler_result.get("status") != "completed":
        return handler_result

    location = task.get("location", "")
    threat_type = task.get("threat_type", "unknown")
    site_path = extract_site_path(location)

    verification = None

    try:
        if threat_type == "backdoor_file" and location:
            # Confirm file is gone
            if Path(location).exists():
                verification = "WARN: File still exists after quarantine"
                handler_result["status"] = "failed"
                handler_result["message"] += " | Verification failed: file still present"
            else:
                verification = "OK: File confirmed absent"

        elif threat_type == "core_modified":
            # Verify core checksums
            result = run_cmd(f"wp core verify-checksums --path={site_path} --allow-root")
            if result.returncode == 0:
                verification = "OK: Core checksums verified"
            else:
                verification = f"WARN: Core checksums still failing: {result.stdout.strip()[:200]}"

        elif threat_type == "vulnerable_plugin":
            # Verify plugin is up to date
            slug = extract_plugin_slug(location)
            if slug:
                result = run_cmd(
                    f"wp plugin list --name={slug} --fields=update --format=csv "
                    f"--path={site_path} --allow-root"
                )
                if "available" in (result.stdout or "").lower():
                    verification = "WARN: Plugin still has updates available"
                else:
                    verification = "OK: Plugin up to date"

        elif threat_type == "permission_issue" and location:
            target = Path(location)
            if target.exists():
                mode = oct(target.stat().st_mode)[-3:]
                expected = "755" if target.is_dir() else "644"
                if mode == expected:
                    verification = f"OK: Permissions are {mode}"
                else:
                    verification = f"WARN: Permissions are {mode}, expected {expected}"
            else:
                verification = "OK: File absent (benign)"

    except Exception as exc:
        verification = f"Verification error: {exc}"

    if verification:
        log.info("Post-verify for %s: %s", task.get("task_id", "?"), verification)
        handler_result["output"] = (
            (handler_result.get("output") or handler_result.get("message", ""))
            + f" | Verify: {verification}"
        )

    return handler_result


def claim_task(task_id: str, api_url: str, api_key: str) -> bool:
    """Attempt to claim a task via the API. Returns True if claimed successfully."""
    try:
        api_post(f"{api_url}/remediation/claim", api_key, {"threat_id": task_id})
        log.info("Claimed task %s", task_id)
        return True
    except HTTPError as exc:
        if exc.code == 409:
            log.info("Task %s already claimed, skipping.", task_id)
            return False
        if exc.code == 404:
            log.warning("Task %s not found on API, skipping.", task_id)
            return False
        log.error("Failed to claim task %s: %s", task_id, exc)
        return False
    except URLError as exc:
        log.error("Network error claiming task %s: %s", task_id, exc)
        return False


def process_task(task: dict, api_url: str, api_key: str) -> None:
    """Dispatch a single remediation task with claim → preflight → execute → verify → report."""
    task_id = task.get("task_id", task.get("id", "unknown"))
    threat_type = task.get("threat_type", "unknown")
    location = task.get("location", "")

    log.info("Processing task %s — type=%s, location=%s", task_id, threat_type, location)

    # Step 1: Local lock (prevents same-process duplication)
    if not _acquire_lock(task_id):
        return

    try:
        # Step 2: API claim (prevents cross-agent duplication)
        if not claim_task(task_id, api_url, api_key):
            return

        # Step 3: Pre-flight checks
        preflight_error = preflight_check(task)
        if preflight_error is not None:
            log.warning("Pre-flight failed for %s: %s", task_id, preflight_error["message"])
            result = preflight_error
        else:
            # Step 4: Execute handler
            handler = HANDLERS.get(threat_type)
            if handler is None:
                log.warning("Unknown threat_type '%s' for task %s", threat_type, task_id)
                result = {
                    "status": "failed",
                    "action_type": "db_cleanup",
                    "message": f"Unknown threat type: {threat_type}",
                }
            else:
                try:
                    result = handler(task)
                    # Step 5: Post-remediation verification
                    result = verify_remediation(task, result)
                except subprocess.TimeoutExpired:
                    log.error("Task %s timed out after %ds", task_id, SUBPROCESS_TIMEOUT)
                    result = {
                        "status": "failed",
                        "action_type": "db_cleanup",
                        "message": f"Command timed out after {SUBPROCESS_TIMEOUT}s",
                    }
                except Exception as exc:
                    log.exception("Unexpected error processing task %s", task_id)
                    result = {
                        "status": "failed",
                        "action_type": "db_cleanup",
                        "message": f"Internal error: {exc}",
                    }

        # Step 6: Report result back to API
        payload = {
            "threat_id": task_id,
            "status": result.get("status", "failed"),
            "action_type": result.get("action_type", "manual"),
            "command": result.get("command", ""),
            "output": result.get("output", result.get("message", "")),
        }

        try:
            api_post(f"{api_url}/remediation/result", api_key, payload)
            log.info("Reported result for task %s: %s", task_id, payload["status"])
        except (URLError, HTTPError) as exc:
            log.error("Failed to report result for task %s: %s", task_id, exc)

    finally:
        _release_lock(task_id)

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def poll_once(api_url: str, api_key: str) -> int:
    """Poll for tasks and process them. Returns the number of tasks processed."""
    try:
        tasks = api_get(f"{api_url}/remediation/tasks", api_key)
    except (URLError, HTTPError) as exc:
        log.error("Failed to fetch tasks: %s", exc)
        return 0
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON response from API: %s", exc)
        return 0

    if not tasks:
        log.debug("No pending tasks.")
        return 0

    log.info("Received %d task(s) to process.", len(tasks))

    for task in tasks:
        process_task(task, api_url, api_key)

    return len(tasks)


def main() -> None:
    """Entry point — parse args and start polling loop."""
    parser = argparse.ArgumentParser(
        description="CleanShift Task Runner — polls API for remediation tasks and executes them.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one poll cycle and exit (for testing).",
    )
    parser.add_argument(
        "--config",
        default=CONFIG_PATH,
        help=f"Path to config YAML (default: {CONFIG_PATH}).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=POLL_INTERVAL,
        help=f"Polling interval in seconds (default: {POLL_INTERVAL}).",
    )
    args = parser.parse_args()

    log.info("CleanShift Task Runner starting up.")

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        log.critical("Configuration error: %s", exc)
        raise SystemExit(1)

    api_url = config["api_url"]
    api_key = config["api_key"]
    log.info("API endpoint: %s", api_url)

    if args.once:
        log.info("Running in --once mode (single poll).")
        count = poll_once(api_url, api_key)
        log.info("Processed %d task(s). Exiting.", count)
        return

    # Continuous polling loop
    log.info("Entering continuous polling loop (interval=%ds).", args.interval)
    while True:
        try:
            poll_once(api_url, api_key)
        except Exception:
            log.exception("Unhandled error in poll loop — will retry.")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
