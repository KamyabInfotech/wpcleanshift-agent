# WPCleanShift Licensing Model

WPCleanShift uses a multi-layered licensing model that balances open-source transparency, community collaboration, and the commercial sustainability of the project.

## 1. WPCleanShift Guard (WordPress Plugin)
**License:** GNU General Public License v2.0 (GPLv2)

The WPCleanShift Guard is a WordPress mu-plugin that provides real-time protection, detects malicious activity, and offers manual fix instructions.
- It is fully free and open-source.
- You can distribute it, modify it, and run it anywhere without restrictions.
- This is intentional, as it serves as the entry-point and is compatible with the WordPress.org plugin directory.

## 2. WPCleanShift Agent (Server Scanner)
**License:** Business Source License 1.1 (BUSL 1.1)

The WPCleanShift Agent provides deep server-side scanning, heuristics, and remediation. We use the BUSL to keep the code entirely source-available for transparency while preventing commercial competitors from using our scanner to launch a competing SaaS service.
- **What you CAN do:** Read the source code, evaluate it, modify it for personal use, and run it in production internally on up to 5 servers.
- **What you CANNOT do:** Use the Agent to provide a commercial security service, offer it as a managed security offering, or run it on more than 5 servers without purchasing a commercial license.
- **Eventual Open Source:** The BUSL 1.1 license includes a "Change Date" set to 4 years from the release of each version. On that date, the license for that version automatically converts to the open-source **Apache License 2.0**.

## 3. Commercial Services
The following components are strictly proprietary and are never distributed as source code:
- The Cloud Intelligence Feed (real-time signature updates)
- The WPCleanShift API (correlation engine, cross-site intelligence)
- The WPCleanShift Dashboard (SaaS interface)
- The WHMCS Billing module integration

Access to these services requires an active paid subscription (Pro, Server, or Fleet tiers).

## Why this model?
Because security software requires deep trust. Security tools that hide what they scan or how they operate as "black boxes" are dangerous. By making the Agent source-available, you can verify exactly what it is doing on your servers while ensuring the team behind WPCleanShift is funded to continue fighting malware.
