## 1.0.0-rc.516

- Tip VERSION honesty sync with wpcleanshift go-live tip.

## 1.0.0-rc.515

- Tip VERSION honesty sync with wpcleanshift go-live tip.

## 1.0.0-rc.514

- Tip VERSION honesty sync with wpcleanshift go-live tip.

## 1.0.0-rc.513

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.512

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.511

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.510

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.509

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.508

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.507

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.506

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.505

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.504

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.481

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.473

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.472

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.471

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.470

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime `__version__` + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.469

- Tip VERSION honesty sync with wpcleanshift go-live tip (runtime  + README pin; commercial Pay still operator-blocked).

## 1.0.0-rc.463

- Tip VERSION honesty sync with wpcleanshift go-live tip (commercial Pay still operator-blocked).

## 1.0.0-rc.462

- Tip VERSION honesty sync with wpcleanshift go-live tip (commercial Pay still operator-blocked).

## 1.0.0-rc.461

- Tip VERSION honesty sync with wpcleanshift go-live tip (commercial Pay still operator-blocked).

## 1.0.0-rc.460

- Tip VERSION honesty sync with wpcleanshift go-live tip (commercial Pay still operator-blocked).

# Changelog

## [1.0.0-rc.451] — 2026-09-15

### Sync
- Tip VERSION pin to monorepo `1.0.0-rc.451` (pay-secret apply helper + branded SMTP honesty).

## [1.0.0-rc.450] — 2026-09-15

### Sync
- Tip VERSION pin to monorepo `1.0.0-rc.450` (branded Stage −1 next-action pay priority + package bake).

## [1.0.0-rc.434] — 2026-09-15

### Chore
- Sync packaging VERSION to monorepo tip 1.0.0-rc.434 (marketing Protect-after-connect honesty).

## [1.0.0-rc.426] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.426` (post-checkout Protect CTA honesty).

## [1.0.0-rc.425] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.425` (schedule/threat Protect-link honesty).

## [1.0.0-rc.424] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.424` (Sites empty + New Scan protect-gate).

## [1.0.0-rc.423] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.423` (Overview Discover → Review Sites).

## [1.0.0-rc.422] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.422` (post-connect Protect handoff).

## [1.0.0-rc.421] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.421` (post-connect Protect-path + install docs honesty).

## [1.0.0-rc.420] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.420` (connect bootstrap discover-only honesty).

## [1.0.0-rc.402] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.402`.

## [1.0.0-rc.401] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.401`.

## [1.0.0-rc.400] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.400`.

## [1.0.0-rc.399] — 2026-09-15

- Align packaging VERSION with monorepo tip `1.0.0-rc.399`.

## [1.0.0-rc.398] — 2026-09-15

- Align VERSION with monorepo tip `1.0.0-rc.398` (packaging VERSION sync; monorepo remains signed-package SoT).

## [1.0.0-rc.395] — 2026-09-15

- Align VERSION with monorepo tip `1.0.0-rc.395`.
- README honesty: operator-approved remediation (not silent auto-clean); monorepo is source of truth for signed packages.

Shift — Changelog

All notable changes to this project will be documented in this file.

## [1.3.1] — 2026-06-17

### Security
- CSRF protection added to all 3 panel plugins (WHM, cPanel, Plesk) — file-based token validation for all state-changing actions
- Guard IP detection hardened — replaced unsafe `get_client_ip()` with `CleanShift_Client_IP` trait that gates proxy header trust behind `CLEANSHIFT_TRUSTED_PROXY`
- WHM "Test Connection" button fixed — was targeting non-existent `test_api` action instead of `test_api_connection`

### Fixed
- Email service wrapped in `asyncio.to_thread()` — no longer blocks the event loop during SMTP operations
- Dashboard `remediationStatusLabel` and `remediationStatusClass` now include `resolved` status
- Agent `ThreatType` enum now includes `site_restore` (15 of 15 types synced)
- Docker-compose API service now includes SMTP, DASHBOARD_URL, and full CORS env vars
- Railway website service renamed from "dashboard" to "website" to prevent deployment confusion
- Railway website HOSTNAME fixed to `0.0.0.0` (was `preserve()` which could bind to localhost)

### Documentation
- Added Documentation and Support links to website navbar, dashboard sidebar, and all 3 panel plugin footers
- Added OG image metadata for social sharing (OpenGraph + Twitter Card)
- Blog sitemap now includes individual post URLs
- Refund page now includes support email address
- Guard admin UI now shows all 10 guards (was missing payload, request, vpatch)
- WHMCS README version updated from 1.0.0 to 1.3.0
- Replaced all `cleanshift.io` references with `cleanshift.osg.co.in` across docs, legal, mock data, and READMEs
- Enhanced dashboard README with architecture links
- Blog post page: removed debug slug output, expanded truncated article content

## [1.3.0] — 2026-06-14

### Added
- Intelligence engine competitive gap closure — enhanced threat-intel coverage and edge-defense capabilities across Weeks 1 and 2
- Guard hardening pass — expanded community YARA rule library from 32 to 100 rules for broader malware family detection
- Payload-inspection and virtual-patching guards wired into the PHP runtime protection layer

### Fixed
- Resolved YARA rule duplication that could cause false-positive matches
- Null-safety fixes across guard modules to prevent crashes on malformed request data

## [1.2.0] — 2026-06-12

### Added
- Email service with transactional email support (welcome, alerts, reports)
- Forgot-password / password-reset flow with secure token lifecycle
- Notification system with in-app and email channels
- Two-factor authentication QR code provisioning in the dashboard
- Password change UI with current-password verification
- Global search across sites, threats, and audit logs
- Role management interface with granular permission controls
- Token refresh mechanism for seamless long-lived sessions
- NVD vulnerability scheduler for automated CVE feed imports

### Fixed
- Intelligence engine — resolved 5 critical issues affecting threat correlation and scoring
- 10 broken production systems fixed (P0): NVD import pipeline, remediation status tracking, IoC counters, `install.sh` bootstrap, systemd unit paths, and Railway service config
- Domain unification — consolidated API and dashboard under a single origin
- Syntax error in `restore.py` caused by f-string backslash escaping on Python 3.12+
- Dashboard component fixes for site-list rendering, chart data, and empty-state handling

### Changed
- Sprint 1+2 security hardening — tightened input validation, CSRF protections, and user-flow edge cases
- Guard API reporting improvements and N+1 query elimination for site listings
- Added `@swc/helpers` dependency to resolve Next.js SWC build compatibility

## [1.1.0] — 2026-06-11

### Added
- PHP, MySQL, and WordPress database deep-scanning — detects injected code in `wp_options`, `wp_posts`, and custom tables
- One-click site restoration from compromise — 10-step automated recovery pipeline (backup → quarantine → clean → verify → restore)
- Production-hardened restore v2 with integrity verification, partial-failure recovery, and operator feedback integration
- Reverse remediation channel — API-to-Agent command path for centrally triggered clean-up actions
- Robust remediation system with job claim/deduplication, preflight environment checks, and post-action verification
- Customer protection suite: two-factor authentication, audit logging, self-healing config monitor, and CPU throttle safeguards
- Dashboard 2FA enrollment UI and audit-log viewer
- Full dashboard overhaul — site overview, threat timeline, agent status, and deployment controls
- Railway deployment configuration (Dockerfile, `railway.toml`, environment wiring)

### Fixed
- `.htaccess` whitelist regex corrected for LiteSpeed compatibility
- `qrcode` dependency pinned to `>=8.0,<9` — version 8.26 does not exist on PyPI
- 40+ audit fixes across dashboard and API (input validation, error handling, missing RBAC checks, UI regressions)
- Unauthenticated endpoint exposure closed; webhook secret validation enforced
- bcrypt compatibility on Python 3.12 — migrated from `passlib` to direct `bcrypt` calls
- ESLint errors bypassed during production builds to unblock CI

### Security
- Sensitive data scrubbed from repository history
- 90-day automatic data purge policy implemented for PII and scan artefacts

### Infrastructure
- Dockerfile restructured with multi-stage build, Docker cache-busting, and deterministic `node` version pinning
- `HOSTNAME` binding fix for containerised FastAPI (listen on `0.0.0.0`)
- Pre-remediation backups now exclude `wp-content/uploads` and common media/image/font extensions to reduce snapshot size
- GitHub Actions workflows removed due to OAuth scope limitations
- Project rebranded from working title to **CleanShift**; deploy script updated accordingly

## [1.0.0] — 2026-06-10

### 🚀 Initial Release

**CleanShift** — AI-powered server security platform: scan, clean, harden, protect.

#### Core Engine (Python Agent)
- 15-layer WordPress scanner (file + database + behavioral + network)
- AI-powered code analysis with trust scoring and concordance engine
- Automated remediation with dry-run, approval gates, and rollback
- Real-time file watcher daemon (inotify-based)
- Telegram alerting for critical/high threats
- CLI interface: `cleanshift scan`, `cleanshift clean`, `cleanshift status`
- Intelligence pipeline with CVE-specific playbooks

#### Real-Time Protection (PHP Guard)
- 7 security guards: Upload, Login, Request, User, Cron, API, Editor/Option
- WordPress mu-plugin with zero-config deployment
- Admin UI with audit log and override management
- 48-hour learning mode for safe rollout

#### Central Platform
- FastAPI async API with JWT + API key authentication
- Next.js dashboard with dark glassmorphism theme
- WebSocket support for real-time agent communication
- SQLAlchemy ORM with Alembic migrations
- PostgreSQL (production) + SQLite (development) support

#### Panel Integrations
- cPanel/WHM plugin (admin + user + hooks)
- Plesk extension
- WHMCS provisioning module with client area dashboard

#### Deployment
- One-command deploy script with 11-phase rollback
- Docker Compose (API + Dashboard + Nginx + PostgreSQL)
- Railway deployment support
- systemd services and cron jobs

#### Test Suite
- 277 tests across 12 test files
- Scanner, cleaner, platform, trust, behavioral, concordance coverage

### Infrastructure
- Alembic database migrations
- `.env.example` with documented configuration
- Production-safe defaults (docs disabled, secrets from env)
