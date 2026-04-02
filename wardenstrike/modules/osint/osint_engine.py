"""
WardenStrike - OSINT Engine
Orchestrates all OSINT collection: Shodan, Google Dorks, GitHub, Breach Data,
WHOIS, Certificate Transparency, ASN, LinkedIn, Metadata extraction.
"""

import asyncio
import json
import re
import socket
import subprocess
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("osint")


@dataclass
class OSINTResult:
    source: str
    data_type: str
    value: str
    context: str = ""
    severity: str = "info"
    raw: dict = field(default_factory=dict)


class OSINTEngine:
    """
    Comprehensive OSINT engine for reconnaissance.
    Covers: Shodan, Censys, FOFA, GitHub, Google Dorks,
            Certificate Transparency, WHOIS, ASN, Breach Data.
    """

    def __init__(self, config: Config, db=None, engagement_id: int = None):
        self.config = config
        self.db = db
        self.engagement_id = engagement_id
        self.results: list[OSINTResult] = []

        # API keys from config
        self.shodan_key = config.get("osint", "shodan_api_key") or ""
        self.censys_id = config.get("osint", "censys_api_id") or ""
        self.censys_secret = config.get("osint", "censys_api_secret") or ""
        self.github_token = config.get("osint", "github_token") or ""

    def _add(self, source, data_type, value, context="", severity="info", raw=None):
        r = OSINTResult(source, data_type, value, context, severity, raw or {})
        self.results.append(r)
        if severity in ("high", "critical"):
            log.warning(f"[OSINT/{source}] {data_type}: {value}")

    # ─── Certificate Transparency ─────────────────────────────────

    async def cert_transparency(self, domain: str) -> list[str]:
        """Enumerate subdomains via crt.sh certificate transparency logs."""
        log.info(f"CT logs: querying crt.sh for {domain}...")
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            subdomains.add(name)
                            self._add("crt.sh", "subdomain", name, f"Found via CT log for {domain}")
        except Exception as e:
            log.debug(f"crt.sh error: {e}")

        return sorted(subdomains)

    # ─── Shodan ───────────────────────────────────────────────────

    async def shodan_search(self, query: str) -> list[dict]:
        """Search Shodan for hosts matching query."""
        if not self.shodan_key:
            log.warning("Shodan API key not configured. Set osint.shodan_api_key in config.")
            return []

        log.info(f"Shodan search: {query}")
        results = []

        try:
            encoded = urllib.parse.quote(query)
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query={encoded}&minify=true"
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
                for match in data.get("matches", []):
                    ip = match.get("ip_str", "")
                    port = match.get("port", "")
                    product = match.get("product", "")
                    version = match.get("version", "")
                    vulns = match.get("vulns", {})

                    result = {
                        "ip": ip,
                        "port": port,
                        "product": product,
                        "version": version,
                        "org": match.get("org", ""),
                        "country": match.get("location", {}).get("country_name", ""),
                        "vulns": list(vulns.keys()),
                    }
                    results.append(result)

                    context = f"{product} {version} on {ip}:{port}"
                    severity = "critical" if vulns else "info"
                    self._add("Shodan", "host", ip, context, severity, result)

                    # Log known CVEs
                    for cve in vulns:
                        self._add("Shodan", "cve", cve,
                                  f"Shodan reports {cve} on {ip}:{port}", "high",
                                  {"ip": ip, "port": port, "cve": cve})

        except Exception as e:
            log.debug(f"Shodan API error: {e}")

        return results

    async def shodan_ip(self, ip: str) -> dict:
        """Get detailed Shodan data for a specific IP."""
        if not self.shodan_key:
            return {}
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception:
            return {}

    # ─── GitHub Dorking ───────────────────────────────────────────

    async def github_recon(self, target: str) -> list[dict]:
        """Search GitHub for leaked credentials, API keys, internal URLs."""
        log.info(f"GitHub recon for: {target}")
        results = []

        dorks = [
            f'"{target}" password',
            f'"{target}" secret_key',
            f'"{target}" api_key',
            f'"{target}" apikey',
            f'"{target}" access_token',
            f'"{target}" private_key',
            f'"{target}" credentials',
            f'"{target}" .env',
            f'"{target}" config.yml password',
            f'"{target}" db_password',
            f'"{target}" smtp_password',
            f'"{target}" aws_secret',
            f'"{target}" connectionstring',
            f'"{target}" internal',
        ]

        if not self.github_token:
            log.warning("GitHub token not set. Rate-limiting may apply. Set osint.github_token")

        headers = {"User-Agent": "WardenStrike/1.0", "Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        for dork in dorks:
            try:
                encoded = urllib.parse.quote(dork)
                url = f"https://api.github.com/search/code?q={encoded}&per_page=10"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                    items = data.get("items", [])
                    if items:
                        for item in items[:5]:
                            result = {
                                "dork": dork,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("path", ""),
                                "url": item.get("html_url", ""),
                            }
                            results.append(result)
                            self._add("GitHub", "leaked_code", item.get("html_url", ""),
                                      f"Dork hit: {dork} | File: {item.get('path','')}",
                                      "high", result)
            except Exception as e:
                if "rate limit" in str(e).lower():
                    log.warning("GitHub rate limit hit. Use a token.")
                    break
                log.debug(f"GitHub search error: {e}")
                await asyncio.sleep(1)

        return results

    # ─── Google Dorks ─────────────────────────────────────────────

    def load_google_dorks(self, target: str) -> list[str]:
        """Generate targeted Google dorks for a domain."""
        dorks_file = Path(__file__).parent.parent.parent / "knowledge" / "dorks" / "google_dorks.txt"
        if dorks_file.exists():
            template_dorks = dorks_file.read_text().strip().split("\n")
            return [d.replace("{target}", target) for d in template_dorks if d and not d.startswith("#")]

        # Fallback built-in dorks
        return [
            f"site:{target} inurl:admin",
            f"site:{target} inurl:login",
            f"site:{target} inurl:api",
            f"site:{target} inurl:swagger",
            f"site:{target} inurl:phpinfo",
            f"site:{target} ext:sql",
            f"site:{target} ext:env",
            f"site:{target} ext:log",
            f"site:{target} ext:bak",
            f"site:{target} ext:conf",
            f"site:{target} intext:\"index of /\"",
            f"site:{target} intext:\"error\" intext:\"exception\"",
            f"site:{target} inurl:wp-admin",
            f"site:{target} inurl:phpmyadmin",
            f"site:{target} inurl:.git",
            f"site:{target} inurl:jenkins",
            f"site:{target} inurl:kibana",
            f"site:{target} inurl:grafana",
            f"site:{target} inurl:\"/.well-known\"",
            f"site:{target} intext:\"DB_PASSWORD\"",
            f"site:{target} intext:\"private key\"",
            f"site:{target} filetype:pdf confidential",
        ]

    # ─── WHOIS ────────────────────────────────────────────────────

    def whois_lookup(self, domain: str) -> dict:
        """Run WHOIS lookup on domain."""
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
            output = result.stdout

            # Extract key fields
            registrar = re.search(r"Registrar:\s*(.+)", output, re.I)
            created = re.search(r"Creation Date:\s*(.+)", output, re.I)
            expires = re.search(r"Expir(?:y|ation) Date:\s*(.+)", output, re.I)
            emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", output)

            data = {
                "registrar": registrar.group(1).strip() if registrar else "",
                "created": created.group(1).strip() if created else "",
                "expires": expires.group(1).strip() if expires else "",
                "emails": list(set(emails)),
                "raw": output[:3000],
            }

            for email in emails:
                self._add("WHOIS", "email", email, f"Found in WHOIS for {domain}")

            return data
        except Exception as e:
            log.debug(f"WHOIS error: {e}")
            return {}

    # ─── ASN / IP Range ───────────────────────────────────────────

    async def asn_lookup(self, domain: str) -> dict:
        """Get ASN and IP ranges for an organization."""
        result = {"ips": [], "asns": [], "ranges": []}

        # Resolve main IP
        try:
            ip = socket.gethostbyname(domain)
            result["ips"].append(ip)
            self._add("DNS", "ip", ip, f"Resolved {domain}")

            # BGP View API for ASN info
            url = f"https://api.bgpview.io/ip/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                prefixes = data.get("data", {}).get("prefixes", [])
                for prefix in prefixes:
                    asn_info = prefix.get("asn", {})
                    asn = asn_info.get("asn")
                    if asn and asn not in result["asns"]:
                        result["asns"].append(asn)
                        self._add("BGP", "asn", str(asn),
                                  f"ASN for {ip}: {asn_info.get('description', '')}")
                    cidr = prefix.get("prefix", "")
                    if cidr and cidr not in result["ranges"]:
                        result["ranges"].append(cidr)

        except Exception as e:
            log.debug(f"ASN lookup error: {e}")

        return result

    # ─── Email / Employee OSINT ───────────────────────────────────

    def enumerate_emails(self, domain: str) -> list[str]:
        """Try to enumerate email addresses via theHarvester if available."""
        emails = []
        try:
            result = subprocess.run(
                ["theHarvester", "-d", domain, "-b", "all", "-l", "50"],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout
            found = re.findall(r"[\w.+-]+@" + re.escape(domain), output, re.I)
            for email in set(found):
                emails.append(email)
                self._add("theHarvester", "email", email, f"Employee email for {domain}", "info")
        except FileNotFoundError:
            log.debug("theHarvester not installed, skipping email enum")
        except Exception as e:
            log.debug(f"theHarvester error: {e}")

        return emails

    # ─── Metadata extraction ──────────────────────────────────────

    def extract_metadata(self, domain: str) -> list[dict]:
        """Extract metadata from public documents (exiftool required)."""
        results = []
        try:
            result = subprocess.run(
                ["metagoofil", "-d", domain, "-t", "pdf,docx,xlsx", "-l", "10", "-n", "3", "-o", "/tmp/metagoofil"],
                capture_output=True, text=True, timeout=60
            )
            # Parse for usernames
            usernames = re.findall(r"Author:\s*(.+)", result.stdout)
            for user in set(usernames):
                self._add("Metagoofil", "username", user.strip(),
                          f"Author found in public document for {domain}", "medium")
                results.append({"type": "username", "value": user.strip()})
        except FileNotFoundError:
            log.debug("metagoofil not installed, skipping metadata extraction")
        return results

    # ─── Breach Check ─────────────────────────────────────────────

    async def check_breaches(self, domain: str) -> list[dict]:
        """Check for known breaches via HIBP (requires API key)."""
        hibp_key = self.config.get("osint", "hibp_api_key") or ""
        if not hibp_key:
            log.debug("HIBP API key not set. Skipping breach check.")
            return []

        results = []
        try:
            url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
            req = urllib.request.Request(url, headers={
                "hibp-api-key": hibp_key,
                "User-Agent": "WardenStrike/1.0"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                for breach in data:
                    self._add("HIBP", "breach", breach.get("Name", "?"),
                              f"Domain {domain} found in breach: {breach.get('Name')}",
                              "high", breach)
                    results.append(breach)
        except Exception as e:
            log.debug(f"HIBP error: {e}")

        return results

    # ─── Shodan dorks for target ──────────────────────────────────

    def get_shodan_dorks(self, target: str) -> list[str]:
        """Generate Shodan search queries for a target."""
        dorks_file = Path(__file__).parent.parent.parent / "knowledge" / "dorks" / "shodan_dorks.txt"
        if dorks_file.exists():
            lines = dorks_file.read_text().strip().split("\n")
            return [l.replace("{target}", target) for l in lines if l and not l.startswith("#")]

        return [
            f"hostname:{target}",
            f"ssl.cert.subject.cn:{target}",
            f"http.title:{target}",
            f"org:{target}",
            f"hostname:{target} port:22",
            f"hostname:{target} port:3389",
            f"hostname:{target} port:6379 country:US",
            f"hostname:{target} port:27017",
            f"hostname:{target} http.component:\"Apache Tomcat\"",
            f"hostname:{target} product:\"Jenkins\"",
            f"hostname:{target} product:\"Elasticsearch\"",
        ]

    # ─── Full OSINT run ───────────────────────────────────────────

    async def run(self, target: str, deep: bool = False) -> dict:
        """
        Full OSINT pipeline for a target domain/organization.
        """
        log.info(f"Starting OSINT collection for: {target}")
        self.results.clear()

        results = {
            "target": target,
            "subdomains_ct": await self.cert_transparency(target),
            "whois": self.whois_lookup(target),
            "asn": await self.asn_lookup(target),
            "emails": self.enumerate_emails(target),
            "google_dorks": self.load_google_dorks(target),
            "shodan_dorks": self.get_shodan_dorks(target),
        }

        if deep:
            results["github_leaks"] = await self.github_recon(target)
            results["breaches"] = await self.check_breaches(target)

            # Shodan search
            main_ip = results["asn"].get("ips", [None])[0]
            if main_ip:
                results["shodan_host"] = await self.shodan_ip(main_ip)

        # Save to DB
        if self.db and self.engagement_id:
            for r in self.results:
                if r.severity in ("high", "critical"):
                    self.db.add_finding(
                        engagement_id=self.engagement_id,
                        title=f"OSINT | {r.source} | {r.data_type}: {r.value[:80]}",
                        severity=r.severity,
                        vuln_type=f"osint_{r.data_type.lower().replace(' ', '_')}",
                        description=r.context,
                        evidence=str(r.raw),
                        tool_source=f"wardenstrike-osint-{r.source.lower()}",
                        raw_data=vars(r),
                    )

        results["raw_findings"] = [vars(r) for r in self.results]
        results["summary"] = {
            "subdomains": len(results["subdomains_ct"]),
            "emails": len(results["emails"]),
            "high_severity": sum(1 for r in self.results if r.severity in ("high", "critical")),
            "total_data_points": len(self.results),
        }

        return results
