<div align="center">

# 🔍 CleanShift Agent

**Server-level WordPress security scanner. File + database deep scanning for cPanel/WHM and Plesk servers.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)
[![RAM](https://img.shields.io/badge/RAM-1.2MB-green.svg)]()

[Documentation](https://cleanshift.osg.co.in/docs) · [Sample Scan Report](https://cleanshift.osg.co.in/docs/sample-report) · [Security Architecture](https://cleanshift.osg.co.in/docs/security)

</div>

## What It Does

CleanShift Agent is a lightweight security scanner that runs on Linux servers hosting WordPress sites. Unlike file-only scanners, it scans both files AND databases to find threats that survive traditional cleanup.

**Scans for:**

- 🔍 Rogue admin accounts in wp_users
- 🔍 Malicious wp_options payloads (redirects, eval, base64)
- 🔍 SEO spam injected into wp_posts
- 🔍 PHP backdoors, web shells, and fake mu-plugins
- 🔍 Modified WordPress core files
- 🔍 Suspicious .ico/.png files containing PHP code
- 🔍 Cross-account contamination patterns
- 🔍 Stale lock files and orphaned processes

**Does NOT collect:** File contents, database row data, passwords, customer PII, SSH/SSL keys, .env files. [Full privacy details →](https://cleanshift.osg.co.in/privacy)

## Quick Start

```bash
# Install (one command, 600KB, zero dependencies)
curl -fsSL https://get.cleanshift.osg.co.in | bash -s -- --license-key YOUR_KEY

# Run a deep scan
cleanshift scan --mode deep

# View results
cleanshift report --last

# View manual fix instructions
cleanshift report --last --remediation-guide
```

## How It Works

```
┌─────────────────────────────────┐
│         Your Server             │
│                                 │
│  ┌──────────┐  ┌──────────┐    │
│  │ Scanner  │  │  Guard   │    │
│  │ (Agent)  │  │ (mu-plugin)│  │
│  │          │  │          │    │
│  │ Files ✓  │  │ Blocks   │    │
│  │ DB    ✓  │  │ attacks  │    │
│  │ Hash  ✓  │  │ in PHP   │    │
│  └────┬─────┘  └──────────┘    │
│       │ metadata only           │
│       ▼ (TLS 1.2+)             │
├─────────────────────────────────│
│  CleanShift API (optional)      │
│  ┌──────────┐  ┌──────────┐    │
│  │   IoC    │  │Dashboard │    │
│  │ Matching │  │  + Fleet │    │
│  └──────────┘  └──────────┘    │
└─────────────────────────────────┘
```

## System Requirements

| Requirement | Value |
|---|---|
| OS | Linux (any distro) |
| Python | 3.8+ |
| RAM | ~1.2MB resident |
| Disk | ~600KB binary |
| Root | Required (reads all user dirs + DB creds) |
| Network | Outbound HTTPS only (no inbound ports) |
| Control Panel | cPanel/WHM, Plesk, or standalone |

## Scan Modes

| Mode | What it scans | Speed |
|---|---|---|
| `--mode quick` | Known malware hashes only | ~30 seconds |
| `--mode standard` | Files + basic database checks | ~1–2 minutes |
| `--mode deep` | Files + full database + behavioral analysis | ~3–5 minutes |

## Free vs Paid

| Feature | Free (Open Source) | Pro ($5/mo) | Server ($12/mo) |
|---|---|---|---|
| File scanning | ✅ | ✅ | ✅ |
| Database scanning | ✅ | ✅ | ✅ |
| Threat detection | ✅ | ✅ | ✅ |
| Manual fix instructions | ✅ | ✅ | ✅ |
| Community signatures | ✅ (30-day delayed) | ✅ Real-time | ✅ Real-time |
| Telegram/email alerts | ✅ | ✅ | ✅ |
| Auto-remediation | ❌ | ✅ | ✅ |
| CVE playbooks | ❌ | ✅ | ✅ |
| Cross-site correlation | ❌ | ❌ | ✅ |
| Fleet dashboard | ❌ | ❌ | ✅ |

## Security & Trust

- The agent runs as root — [read exactly why and how we limit scope](https://cleanshift.osg.co.in/docs/security)
- All source code is open and auditable
- Agent communicates outbound-only (no inbound ports)
- Config stored at `/etc/cleanshift/config.json` with `0600` permissions
- [See a sample scan report](https://cleanshift.osg.co.in/docs/sample-report)

## Clean Uninstall

```bash
cleanshift-installer --uninstall
# Removes: agent, config, cron jobs, Guard mu-plugin
# Preserves: backups, scan history (use --purge to remove everything)
```

## WordPress Guard Plugin

For per-site real-time protection inside WordPress, install [CleanShift Guard](https://github.com/KamyabInfotech/cleanshift-guard) (GPLv2, available on WordPress.org).

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Support

- WhatsApp: [+91 845 409 4444](https://wa.me/918454094444)
- Website: [cleanshift.osg.co.in](https://cleanshift.osg.co.in)
- Issues: [GitHub Issues](https://github.com/KamyabInfotech/cleanshift-agent/issues)

---

Built by [Kamyab Infotech](https://kamyab.co.in).
