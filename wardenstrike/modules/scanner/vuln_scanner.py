"""
WardenStrike - Vulnerability Scanner Module
Orchestrates nuclei, dalfox (XSS), sqlmap, and custom checks.
"""

import asyncio
import json
import tempfile
from pathlib import Path

from wardenstrike.config import Config
from wardenstrike.integrations.nuclei import NucleiScanner
from wardenstrike.utils.helpers import run_command, is_tool_installed
from wardenstrike.utils.logger import get_logger

log = get_logger("vuln_scanner")


class VulnScanner:
    """Multi-tool vulnerability scanning orchestrator."""

    def __init__(self, config: Config):
        self.config = config
        self.nuclei = NucleiScanner(config)

    async def run_nuclei(self, targets: list[str]) -> list[dict]:
        """Run nuclei against targets."""
        return await self.nuclei.scan(targets)

    async def run_xss_scan(self, urls: list[str]) -> list[dict]:
        """Run XSS scanning with dalfox."""
        if not is_tool_installed("dalfox"):
            log.warning("dalfox not installed, skipping XSS scan")
            return []

        findings = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            urls_file = f.name

        outfile = tempfile.mktemp(suffix=".json")
        cmd = f"dalfox file {urls_file} --silence --format json -o {outfile}"
        result = run_command(cmd, timeout=600, shell=True)

        if Path(outfile).exists():
            for line in Path(outfile).read_text().strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "title": f"XSS: {data.get('data', 'Reflected XSS')}",
                        "vuln_type": "xss",
                        "severity": self._dalfox_severity(data.get("type", "")),
                        "url": data.get("data", ""),
                        "payload": data.get("payload", ""),
                        "evidence": data.get("evidence", ""),
                        "parameter": data.get("param", ""),
                        "tool": "dalfox",
                    })
                except json.JSONDecodeError:
                    continue
            Path(outfile).unlink(missing_ok=True)

        Path(urls_file).unlink(missing_ok=True)
        log.info(f"dalfox: {len(findings)} XSS findings")
        return findings

    async def run_sqli_check(self, urls_with_params: list[str]) -> list[dict]:
        """Run basic SQL injection checks with sqlmap."""
        if not is_tool_installed("sqlmap"):
            log.warning("sqlmap not installed, skipping SQLi check")
            return []

        findings = []
        for url in urls_with_params[:20]:  # Limit to avoid very long scans
            cmd = f"sqlmap -u '{url}' --batch --level=1 --risk=1 --forms --crawl=0 --output-dir=/tmp/sqlmap_hp --answers='follow=N'"
            result = run_command(cmd, timeout=120)
            if result["success"] and "is vulnerable" in result["stdout"].lower():
                findings.append({
                    "title": f"SQL Injection",
                    "vuln_type": "sqli",
                    "severity": "high",
                    "url": url,
                    "evidence": self._extract_sqlmap_evidence(result["stdout"]),
                    "tool": "sqlmap",
                })

        log.info(f"sqlmap: {len(findings)} SQLi findings")
        return findings

    async def run_cors_check(self, urls: list[str]) -> list[dict]:
        """Check for CORS misconfigurations."""
        from wardenstrike.utils.http import HTTPClient

        findings = []
        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.com",
        ]

        async with HTTPClient(rate_limit=5, timeout=10) as client:
            for url in urls[:50]:
                for origin in test_origins:
                    resp = await client.get(url, headers={"Origin": origin})
                    acao = resp.header("access-control-allow-origin")
                    acac = resp.header("access-control-allow-credentials")

                    if acao and (acao == origin or acao == "*"):
                        severity = "high" if acac and acac.lower() == "true" else "medium"
                        if acao == "*" and not acac:
                            severity = "low"

                        findings.append({
                            "title": f"CORS Misconfiguration - reflects {origin}",
                            "vuln_type": "cors",
                            "severity": severity,
                            "url": url,
                            "evidence": f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                            "tool": "wardenstrike",
                        })
                        break

        log.info(f"CORS check: {len(findings)} findings")
        return findings

    async def run_open_redirect_check(self, urls: list[str]) -> list[dict]:
        """Check for open redirect vulnerabilities."""
        from wardenstrike.utils.http import HTTPClient

        redirect_params = ["url", "redirect", "next", "return", "returnUrl", "goto", "dest",
                          "destination", "redir", "redirect_uri", "return_to", "continue", "target"]
        payloads = ["https://evil.com", "//evil.com", "https:evil.com", "/\\evil.com"]

        findings = []
        async with HTTPClient(rate_limit=5, timeout=10) as client:
            for url in urls[:30]:
                for param in redirect_params:
                    for payload in payloads:
                        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                        resp = await client.get(test_url, follow_redirects=False)

                        location = resp.header("location")
                        if location and ("evil.com" in location):
                            findings.append({
                                "title": f"Open Redirect via {param} parameter",
                                "vuln_type": "open_redirect",
                                "severity": "medium",
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Redirects to: {location}",
                                "tool": "wardenstrike",
                            })
                            break
                    if findings and findings[-1]["url"] == url:
                        break

        log.info(f"Open redirect check: {len(findings)} findings")
        return findings

    async def run_header_checks(self, urls: list[str]) -> list[dict]:
        """Check for security header misconfigurations."""
        from wardenstrike.utils.http import HTTPClient

        findings = []
        async with HTTPClient(rate_limit=10, timeout=10) as client:
            responses = await client.multi_get(urls[:50])

            for resp in responses:
                if resp.status == 0:
                    continue

                missing = []
                if not resp.header("strict-transport-security"):
                    missing.append("Strict-Transport-Security")
                if not resp.header("content-security-policy"):
                    missing.append("Content-Security-Policy")
                if not resp.header("x-frame-options") and not "frame-ancestors" in resp.header("content-security-policy"):
                    missing.append("X-Frame-Options")
                if not resp.header("x-content-type-options"):
                    missing.append("X-Content-Type-Options")

                if missing:
                    findings.append({
                        "title": f"Missing Security Headers ({len(missing)})",
                        "vuln_type": "misconfiguration",
                        "severity": "info",
                        "url": resp.url,
                        "evidence": f"Missing: {', '.join(missing)}",
                        "tool": "wardenstrike",
                    })

        return findings

    async def run_full_scan(self, targets: list[str], urls: list[str] | None = None) -> list[dict]:
        """Run all vulnerability scanners."""
        all_findings = []

        # Run scanners in parallel
        tasks = [
            self.run_nuclei(targets),
            self.run_cors_check(targets),
            self.run_header_checks(targets),
        ]

        if urls:
            urls_with_params = [u for u in urls if "?" in u]
            tasks.append(self.run_xss_scan(urls_with_params[:100]))
            tasks.append(self.run_open_redirect_check(urls[:50]))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)

        return all_findings

    def _dalfox_severity(self, xss_type: str) -> str:
        type_map = {"G": "high", "R": "medium", "V": "medium"}
        return type_map.get(xss_type, "medium")

    def _extract_sqlmap_evidence(self, output: str) -> str:
        lines = output.split("\n")
        evidence = [l for l in lines if "injectable" in l.lower() or "vulnerable" in l.lower() or "payload" in l.lower()]
        return "\n".join(evidence[:10])
