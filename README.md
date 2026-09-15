# CleanShift Agent (packaging repo)

> **Monorepo source of truth:** signed install packages are published from `KamyabInfotech/wpcleanshift` (`scripts/publish_agent_package.sh`). This repo's VERSION and `agent/src/__init__.py` `__version__` track the monorepo tip for packaging alignment (synced at `1.0.0-rc.411`). Full tree sync remains deferred.

# CleanShift

> AI-powered server security platform — scan, clean, harden, protect.

## What This Is

CleanShift is a server-level security system for cPanel/WHM and Plesk that does what Imunify360, Wordfence, and Sucuri **can't**:

- **Database-level malware scanning** — wp_options injections, rogue admins, SEO spam, attack markers
- **AI-powered code analysis** — legit plugin vs backdoor, not just signature matching
- **Cross-site correlation** — if one site is infected, check all sites on the server
- **Operator-approved remediation** — backup → remediate → verify with rollback (not silent auto-clean)
- **Real-time protection** — 7 PHP security guards that block attacks before they land
- **Intelligence-driven playbooks** — CVE-specific automated cleanup procedures

## Why Not Imunify360?

Born from a real production incident: CVE-2024-28000 (LiteSpeed Cache) infected 30 of 34 WordPress sites on a cPanel server. Imunify360 caught 2 file-level backdoors but **missed ALL database-level malware** — rogue admins, wp_options injections, SEO spam markers. CleanShift found and cleaned everything.

| Feature | Imunify360 | Wordfence | CleanShift |
|---------|-----------|-----------|------------|
| Database scanning | ❌ | ❌ | ✅ |
| Cross-site correlation | ❌ | ❌ | ✅ |
| CVE-specific playbooks | ❌ | ❌ | ✅ |
| Server-level view | ✅ | ❌ | ✅ |
| WordPress depth | Shallow | Deep | Deep |
| Resource footprint | Heavy | Heavy | Light |
| Real-time guards | ✅ | ✅ | ✅ |
| Price | $$$ | $$/site | $ |

## Enterprise Deployment

CleanShift is a commercial enterprise security platform. To deploy CleanShift across your infrastructure, you must obtain a valid license key from the [CleanShift Dashboard](https://cleanshift.osg.co.in).

```bash
# Install the agent with your enterprise license key
cleanshift-installer --license-key YOUR_ENTERPRISE_KEY_HERE

# Scan the entire server
cleanshift scan --server --scan-mode deep

# Clean detected threats
cleanshift clean --server --mode auto

# Check fleet status
cleanshift status
```

## Architecture

```
┌─────────────────────────────────────┐
│  CleanShift Central (SaaS)          │
│  Dashboard + API + Intelligence DB   │
└──────────────┬──────────────────────┘
               │ WSS (outbound-only)
┌──────────────▼──────────────────────┐
│  CleanShift Agent (on server)       │
│  18 Python modules, 600KB           │
│  5 runtime deps, single-script      │
│  install                            │
├─────────────────────────────────────┤
│  CleanShift Guard (per WP site)     │
│  PHP mu-plugin, 7 security guards   │
│  Zero-config, self-healing          │
├─────────────────────────────────────┤
│  File Watcher (real-time)           │
│  inotify-based, zero-dep daemon     │
│  Telegram alerts on detection       │
└─────────────────────────────────────┘
```

## Project Structure

```
cleanshift/
├── agent/               # Server-side agent (Python)
│   ├── src/             # 18 source modules (~600KB)
│   ├── tests/           # 277 tests, 10 test files
│   └── config/          # Agent configuration
├── guard/               # Real-time WordPress protection (PHP)
│   └── cleanshift-guard/ # 7 guards + audit + overrides + admin UI
├── intelligence/        # Security intelligence pipeline
│   ├── indicators/      # IoC database (malware domains, backdoor patterns)
│   ├── playbooks/       # CVE-specific remediation playbooks
│   ├── cve-db/          # Vulnerability tracking
│   └── attack-chains/   # Attack documentation
├── api/                 # Central API (FastAPI, async)
├── dashboard/           # Visual dashboard (Next.js)
├── cpanel/              # cPanel/WHM plugin integration
├── plesk/               # Plesk extension
├── deploy/              # Deployment scripts, Docker, systemd
├── docs/                # Documentation
│   ├── installation.md  # Install guide
│   ├── configuration.md # Config reference
│   └── detections.md    # Detection capabilities
└── scripts/             # Operational scripts
```

## Detection Capabilities

### File System
- Backdoor files (IoC matching + heuristic patterns)
- PHP in uploads (shouldn't exist)
- .htaccess hijacking (6 pattern types)
- Core file integrity (wp-cli checksums)
- Suspicious file permissions

### Database (Unique)
- Rogue admin accounts
- wp_options injection (scripts, redirects, SEO spam)
- Malware persistence markers
- Custom detection SQL queries

### Network
- REST API exposure
- DNS/SSL analysis
- SSRF protection
- Cloudflare detection

### Real-Time (Guard)
- Upload filtering
- Brute-force protection
- Admin creation blocking
- Cron hijacking prevention
- API abuse prevention

## CLI Reference

```bash
cleanshift scan [--site PATH | --server] [--scan-mode quick|deep] [--tier free|paid]
cleanshift clean [--site PATH | --server] [--mode auto|manual|report-only] [--playbook NAME] [--approve-all] [--approve-destructive] [--dry-run] [--scan-mode quick|deep]
cleanshift report --scan-file PATH [--tier free|paid]
cleanshift status
cleanshift guard [disable|enable|status]
cleanshift telegram [setup|test]
cleanshift connect --api-url URL --api-key KEY
```

## Requirements

- **Python** 3.8+ (3.9+ recommended)
- **OS**: CentOS 7+, AlmaLinux 8+, Ubuntu 20.04+, CloudLinux 7+
- **Panel**: cPanel/WHM, Plesk, or standalone
- **Access**: Root SSH

## Supported Platforms

| Platform | Status | Detection | Remediation |
|----------|--------|-----------|-------------|
| **WordPress** | ✅ Full | Deep (file + DB + behavioral) | Automated playbooks |
| **Joomla** | 🔜 Planned | File-level | Basic |
| **Drupal** | 🔜 Planned | File-level | Basic |
| **Magento** | 🔜 Planned | File-level | Basic |

## Documentation

- 📖 [Full Documentation](https://cleanshift.osg.co.in/docs) — Quick start, CLI reference, architecture
- 🔒 [Security Architecture](https://cleanshift.osg.co.in/docs/security) — How the agent runs, what data it collects
- 📊 [Sample Scan Report](https://cleanshift.osg.co.in/docs/sample-report) — See what a real scan looks like
- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Detection Capabilities](docs/detections.md)
- [Backup & Recovery](docs/backups.md)
- [Privacy Policy](https://cleanshift.osg.co.in/privacy)

## Licensing & Open Source Model

WPCleanShift operates on an "Open Core + Proprietary Intelligence" model to balance transparency with sustainability.

*   **WPCleanShift Guard (WordPress Plugin):** [GNU General Public License v2.0 (GPLv2)](guard/LICENSE) — Fully free and open-source. Installable directly from the WordPress.org plugin directory.
*   **WPCleanShift Agent (Server Scanner):** [Business Source License 1.1 (BUSL 1.1)](agent/LICENSE) — Source-available for transparency and auditability. Free for non-production use and internal production use on up to 5 servers. Converting to Apache 2.0 after 4 years.
*   **API, Intelligence Feed, & Dashboard:** Proprietary software. Never distributed.

For full details, see the [LICENSING.md](LICENSING.md) file.

## Part of the Kamyab Ecosystem

- **CleanShift** — Server security platform
- **AgentPilot** — Agent supervision
- **MailOps Pro** — Email administration
- **MoveOps** — Migration cockpit
- **WHM-TG-Alerts** — Server monitoring
- **WHMCS** — Billing & licensing
