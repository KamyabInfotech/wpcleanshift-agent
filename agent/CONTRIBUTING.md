# Contributing to CleanShift Agent

Thank you for your interest in contributing to CleanShift Agent! This document provides guidelines for contributing.

## How to Contribute

### Reporting Bugs
- Use [GitHub Issues](https://github.com/KamyabInfotech/cleanshift-agent/issues)
- Include: Linux distro, Python version, control panel (cPanel/Plesk/none), error output
- **Do not include sensitive data** (passwords, API keys, server hostnames, client information)

### Suggesting Detection Rules
If you've found a new malware pattern that CleanShift Agent should detect:
1. Open an issue with the tag `detection-rule`
2. Include: pattern description, SHA-256 hash, file path pattern, affected CMS versions
3. **Do not submit actual malware samples** — hashes and descriptions only

### Submitting Code
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run existing tests: `pytest tests/`
5. Submit a pull request with a clear description

### Code Style
- Follow PEP 8 for Python code
- Use type hints for function signatures
- Add docstrings for public functions and classes
- Keep memory usage minimal — the agent must run in ~1.2MB RAM

## What We Accept
- Bug fixes
- New scanner detection patterns (file hashes, database patterns, behavioral indicators)
- Performance improvements (faster scanning, lower memory usage)
- Control panel support (new hosting environments)
- Documentation improvements
- Platform compatibility fixes

## What We Don't Accept
- Auto-remediation logic (this is part of the proprietary CleanShift Pro tier)
- Real-time intelligence feed integration (proprietary)
- Cross-site correlation engine (proprietary, Server tier)
- Fleet management features (proprietary, Fleet tier)
- Dependencies that increase the binary size significantly

## Architecture Notes
- `scanner.py` — Core file scanning engine
- `extended_scanners.py` — Advanced detection patterns
- `wp.py` — WordPress-specific scanning logic
- `behavioral.py` — Behavioral analysis engine
- `reporter.py` — Report generation and manual fix instructions
- `cleaner.py` — **Proprietary boundary** — remediation logic (do not modify/submit PRs)

## Security Vulnerabilities
If you discover a security vulnerability in CleanShift Agent, please **do not** open a public issue. Instead, email security@cleanshift.osg.co.in with details. We will respond within 48 hours.

## License
By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
