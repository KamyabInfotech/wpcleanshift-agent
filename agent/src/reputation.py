"""
CleanShift Reputation Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checks server IPs and domain names against DNS-based blocklists
(DNSBL / SURBL) to detect if a server or its hosted sites have
been flagged for spam, malware, or phishing.

Uses only ``socket.getaddrinfo()`` — no external dependencies.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cleanshift.reputation")


@dataclass
class BlocklistResult:
    """Result of a single blocklist check."""
    blocklist: str = ""
    query: str = ""
    target: str = ""
    listed: bool = False
    return_code: str = ""
    meaning: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocklist": self.blocklist,
            "query": self.query,
            "target": self.target,
            "listed": self.listed,
            "return_code": self.return_code,
            "meaning": self.meaning,
            "error": self.error,
        }


@dataclass
class ReputationReport:
    """Aggregated reputation check results for a server."""
    server_ip: str = ""
    server_hostname: str = ""
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: List[BlocklistResult] = field(default_factory=list)
    domains_checked: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> None:
        """Compute summary statistics."""
        total = len(self.results)
        listed = sum(1 for r in self.results if r.listed)
        errors = sum(1 for r in self.results if r.error)
        self.summary = {
            "total_checks": total,
            "listings_found": listed,
            "checks_failed": errors,
            "clean": listed == 0 and errors == 0,
            "server_ip": self.server_ip,
            "domains_checked": len(self.domains_checked),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_ip": self.server_ip,
            "server_hostname": self.server_hostname,
            "checked_at": self.checked_at,
            "results": [r.to_dict() for r in self.results],
            "domains_checked": self.domains_checked,
            "summary": self.summary,
        }


class ReputationChecker:
    """Check server IPs and domains against DNSBL/SURBL lists.

    Uses ``socket.getaddrinfo()`` exclusively — no third-party DNS
    libraries required.

    Usage::

        checker = ReputationChecker()
        report = checker.check_server(domains=["example.com"])
        print(report.summary)
    """

    IP_BLOCKLISTS = [
        ("zen.spamhaus.org", {
            "127.0.0.2": "SBL (direct spam sources)",
            "127.0.0.3": "SBL CSS (spam operations)",
            "127.0.0.4": "XBL (exploits/proxies)",
            "127.0.0.9": "SBL DROP (hijacked space)",
            "127.0.0.10": "PBL (policy block)",
            "127.0.0.11": "PBL (ISP policy)",
        }),
        ("b.barracudacentral.org", {
            "127.0.0.2": "Listed as spam source",
        }),
        ("bl.spamcop.net", {
            "127.0.0.2": "Listed as spam source",
        }),
        ("dnsbl.sorbs.net", {
            "127.0.0.2": "HTTP proxy",
            "127.0.0.3": "SOCKS proxy",
            "127.0.0.4": "Misc proxy",
            "127.0.0.5": "SMTP server",
            "127.0.0.6": "Spam source",
            "127.0.0.7": "Web server vulnerability",
            "127.0.0.9": "Zombie/botnet",
            "127.0.0.10": "Dynamic IP",
        }),
    ]  # type: List[Tuple[str, Dict[str, str]]]

    DOMAIN_BLOCKLISTS = [
        ("multi.surbl.org", {
            "127.0.0.2": "SC: SpamCop data",
            "127.0.0.4": "WS: sa-blacklist data",
            "127.0.0.8": "PH: Phishing data",
            "127.0.0.16": "MW: Malware data",
            "127.0.0.32": "AB: AbuseButler data",
            "127.0.0.64": "JP: jwSpamSpy data",
        }),
        ("dbl.spamhaus.org", {
            "127.0.1.2": "Spam domain",
            "127.0.1.4": "Phishing domain",
            "127.0.1.5": "Malware domain",
            "127.0.1.6": "Botnet C&C domain",
            "127.0.1.102": "Abused legit spam domain",
            "127.0.1.103": "Abused redirector domain",
            "127.0.1.104": "Abused legit phish domain",
            "127.0.1.105": "Abused legit malware domain",
            "127.0.1.106": "Abused legit botnet C&C domain",
        }),
    ]  # type: List[Tuple[str, Dict[str, str]]]

    def __init__(self, timeout: int = 5) -> None:
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)

    def check_ip(self, ip: str) -> List[BlocklistResult]:
        """Check a single IP against all IP-based DNSBLs."""
        results = []  # type: List[BlocklistResult]
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version != 4:
                logger.info("Skipping IPv6 address (DNSBL IPv4 only): %s", ip)
                return results
            reversed_ip = ".".join(reversed(ip.split(".")))
        except ValueError:
            logger.warning("Invalid IP address: %s", ip)
            return results

        for bl_name, codes in self.IP_BLOCKLISTS:
            query = "%s.%s" % (reversed_ip, bl_name)
            result = BlocklistResult(blocklist=bl_name, query=query, target=ip)
            try:
                answers = socket.getaddrinfo(query, None, socket.AF_INET)
                if answers:
                    return_ip = answers[0][4][0]
                    result.listed = True
                    result.return_code = return_ip
                    result.meaning = codes.get(return_ip, "Listed (code: %s)" % return_ip)
                    logger.warning(
                        "LISTED: %s on %s — %s (%s)",
                        ip, bl_name, result.meaning, return_ip,
                    )
            except socket.gaierror:
                pass  # Not listed (NXDOMAIN)
            except socket.timeout:
                result.error = "DNS timeout"
                logger.debug("Timeout checking %s on %s", ip, bl_name)
            except Exception as e:
                result.error = str(e)
                logger.debug("Error checking %s on %s: %s", ip, bl_name, e)
            results.append(result)

        return results

    def check_domain(self, domain: str) -> List[BlocklistResult]:
        """Check a single domain against all domain-based SURBLs."""
        results = []  # type: List[BlocklistResult]
        domain = domain.lower().strip().rstrip(".")
        if domain.startswith("www."):
            domain = domain[4:]

        for bl_name, codes in self.DOMAIN_BLOCKLISTS:
            query = "%s.%s" % (domain, bl_name)
            result = BlocklistResult(blocklist=bl_name, query=query, target=domain)
            try:
                answers = socket.getaddrinfo(query, None, socket.AF_INET)
                if answers:
                    return_ip = answers[0][4][0]
                    result.listed = True
                    result.return_code = return_ip
                    result.meaning = codes.get(return_ip, "Listed (code: %s)" % return_ip)
                    logger.warning(
                        "LISTED: %s on %s — %s (%s)",
                        domain, bl_name, result.meaning, return_ip,
                    )
            except socket.gaierror:
                pass
            except socket.timeout:
                result.error = "DNS timeout"
            except Exception as e:
                result.error = str(e)
            results.append(result)

        return results

    def check_server(
        self, domains: Optional[List[str]] = None,
    ) -> ReputationReport:
        """Run full reputation check: server IP + optional domain list.

        Args:
            domains: Domain names to check. If ``None``, only the
                     server's own IP is checked.

        Returns:
            Aggregated ``ReputationReport``.
        """
        report = ReputationReport()

        # Get server IP
        try:
            hostname = socket.gethostname()
            report.server_hostname = hostname
            server_ip = socket.gethostbyname(hostname)
            report.server_ip = server_ip
        except socket.error as e:
            logger.error("Could not determine server IP: %s", e)
            report.server_ip = "unknown"
            report.finalize()
            return report

        # Check server IP
        logger.info("Checking server IP: %s (%s)", report.server_ip, hostname)
        ip_results = self.check_ip(report.server_ip)
        report.results.extend(ip_results)

        # Check domains
        if domains:
            report.domains_checked = list(domains)
            for domain in domains:
                logger.info("Checking domain: %s", domain)
                domain_results = self.check_domain(domain)
                report.results.extend(domain_results)

                # Also resolve domain IP and check that
                try:
                    domain_ip = socket.gethostbyname(domain)
                    if domain_ip != report.server_ip:
                        logger.info(
                            "Domain %s resolves to %s (different from server IP %s), checking...",
                            domain, domain_ip, report.server_ip,
                        )
                        domain_ip_results = self.check_ip(domain_ip)
                        report.results.extend(domain_ip_results)
                except socket.error:
                    logger.debug("Could not resolve domain: %s", domain)

        report.finalize()
        return report
