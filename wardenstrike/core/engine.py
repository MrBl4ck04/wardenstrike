"""
WardenStrike - Core Engine
Orchestrates all modules, integrations, and AI analysis.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from wardenstrike.config import Config
from wardenstrike.core.session import SessionManager, Engagement
from wardenstrike.core.ai_engine import AIEngine
from wardenstrike.utils.logger import get_logger, console
from wardenstrike.utils.helpers import hash_finding, is_in_scope, check_tools

log = get_logger("engine")

REQUIRED_TOOLS = ["subfinder", "httpx", "nmap", "nuclei"]
OPTIONAL_TOOLS = [
    "amass", "gau", "katana", "ffuf", "dalfox", "gospider",
    "hakrawler", "waybackurls", "dnsx", "uncover", "chaos",
    "sqlmap", "feroxbuster", "arjun", "paramspider",
]


class WardenStrikeEngine:
    """Main engine that orchestrates the entire pentesting workflow."""

    def __init__(self, config: Config):
        self.config = config
        self.db = SessionManager(config.get("session", "database", default="./data/wardenstrike.db"))
        self.ai = AIEngine(config)
        self._active_engagement: Engagement | None = None
        self._tool_status: dict[str, bool] = {}

    def check_environment(self) -> dict:
        """Check all tool dependencies and return status."""
        all_tools = REQUIRED_TOOLS + OPTIONAL_TOOLS
        self._tool_status = check_tools(all_tools)

        missing_required = [t for t in REQUIRED_TOOLS if not self._tool_status.get(t)]
        missing_optional = [t for t in OPTIONAL_TOOLS if not self._tool_status.get(t)]

        return {
            "tools": self._tool_status,
            "missing_required": missing_required,
            "missing_optional": missing_optional,
            "ready": len(missing_required) == 0,
        }

    # --- Engagement Management ---

    def create_engagement(self, name: str, platform: str = "", scope: list[str] | None = None, **kwargs) -> Engagement:
        eng = self.db.create_engagement(name, platform, scope, **kwargs)
        self._active_engagement = eng
        log.success(f"Engagement created: {name} (ID: {eng.id})")
        return eng

    def load_engagement(self, engagement_id: int) -> Engagement | None:
        eng = self.db.get_engagement(engagement_id)
        if eng:
            self._active_engagement = eng
            log.info(f"Loaded engagement: {eng.name}")
        return eng

    @property
    def engagement(self) -> Engagement | None:
        if not self._active_engagement:
            self._active_engagement = self.db.get_active_engagement()
        return self._active_engagement

    def _require_engagement(self) -> Engagement:
        eng = self.engagement
        if not eng:
            raise RuntimeError("No active engagement. Create one first with 'wardenstrike engage new'")
        return eng

    # --- Recon Pipeline ---

    async def run_recon(self, target: str, quick: bool = False) -> dict:
        """Run the full reconnaissance pipeline."""
        from wardenstrike.modules.recon.subdomain import SubdomainEnum
        from wardenstrike.modules.recon.portscan import PortScanner
        from wardenstrike.modules.recon.webprobe import WebProber
        from wardenstrike.modules.recon.crawler import WebCrawler
        from wardenstrike.modules.recon.tech_detect import TechDetector
        from wardenstrike.modules.recon.js_analyzer import JSAnalyzer

        eng = self._require_engagement()
        results = {"target": target, "started_at": datetime.utcnow().isoformat()}

        log.phase("PHASE 1: Subdomain Enumeration", f"Target: {target}")
        sub_enum = SubdomainEnum(self.config)
        subdomains = await sub_enum.run(target, quick=quick)
        results["subdomains"] = subdomains
        for sd in subdomains:
            self.db.add_recon_result(eng.id, "subdomain", sd, "recon_pipeline")
        log.success(f"Found {len(subdomains)} subdomains")

        log.phase("PHASE 2: HTTP Probing", "Identifying live web servers")
        prober = WebProber(self.config)
        live_hosts = await prober.run(subdomains)
        results["live_hosts"] = live_hosts
        for host in live_hosts:
            self.db.add_target(eng.id, host["url"], status_code=host.get("status_code"),
                             title=host.get("title"), server=host.get("server"),
                             technologies=json.dumps(host.get("technologies", [])))
        log.success(f"Found {len(live_hosts)} live hosts")

        log.phase("PHASE 3: Port Scanning", "Discovering open ports and services")
        port_scanner = PortScanner(self.config)
        port_results = await port_scanner.run(target, subdomains[:50] if not quick else subdomains[:10])
        results["ports"] = port_results
        log.success(f"Scanned ports on {len(port_results)} hosts")

        log.phase("PHASE 4: Technology Detection", "Fingerprinting technologies")
        tech_detector = TechDetector(self.config)
        tech_results = await tech_detector.run([h["url"] for h in live_hosts])
        results["technologies"] = tech_results
        log.success(f"Detected technologies on {len(tech_results)} hosts")

        log.phase("PHASE 5: Web Crawling & URL Discovery", "Gathering URLs and endpoints")
        crawler = WebCrawler(self.config)
        crawl_results = await crawler.run([h["url"] for h in live_hosts[:20]], quick=quick)
        results["urls"] = crawl_results.get("urls", [])
        results["js_files"] = crawl_results.get("js_files", [])
        results["parameters"] = crawl_results.get("parameters", [])
        for url in results["urls"]:
            self.db.add_recon_result(eng.id, "url", url, "crawler")
        log.success(f"Discovered {len(results['urls'])} URLs, {len(results['js_files'])} JS files")

        if not quick:
            log.phase("PHASE 6: JavaScript Analysis", "Analyzing JS for secrets and endpoints")
            js_analyzer = JSAnalyzer(self.config, self.ai)
            js_results = await js_analyzer.run(results["js_files"][:50])
            results["js_analysis"] = js_results
            log.success(f"Analyzed {len(results['js_files'][:50])} JS files")

        # AI-powered analysis of all recon data
        log.phase("PHASE 7: AI Recon Analysis", "Correlating findings and prioritizing targets")
        ai_analysis = self.ai.analyze_recon_data(results)
        results["ai_analysis"] = ai_analysis
        log.success("AI analysis complete")

        results["finished_at"] = datetime.utcnow().isoformat()
        return results

    # --- Vulnerability Scanning ---

    async def run_scan(self, targets: list[str] | None = None, vuln_types: list[str] | None = None) -> dict:
        """Run vulnerability scanning pipeline."""
        from wardenstrike.modules.scanner.vuln_scanner import VulnScanner
        from wardenstrike.modules.scanner.fuzzer import Fuzzer

        eng = self._require_engagement()

        if not targets:
            db_targets = self.db.get_targets(eng.id, alive_only=True)
            targets = [t.domain for t in db_targets]

        if not targets:
            log.error("No targets found. Run recon first.")
            return {"error": "No targets"}

        results = {"started_at": datetime.utcnow().isoformat(), "findings": []}

        log.phase("VULN SCAN: Nuclei Templates", f"Scanning {len(targets)} targets")
        scanner = VulnScanner(self.config)
        nuclei_results = await scanner.run_nuclei(targets)
        results["nuclei"] = nuclei_results

        log.phase("VULN SCAN: Fuzzing", "Parameter and directory fuzzing")
        fuzzer = Fuzzer(self.config)
        fuzz_results = await fuzzer.run(targets[:20])
        results["fuzzing"] = fuzz_results

        # Process and store all findings
        all_raw_findings = nuclei_results + fuzz_results
        for raw in all_raw_findings:
            fhash = hash_finding(raw.get("title", ""), raw.get("url", ""), raw.get("vuln_type", ""))
            finding = self.db.add_finding(
                engagement_id=eng.id,
                finding_hash=fhash,
                title=raw.get("title", ""),
                vuln_type=raw.get("vuln_type", ""),
                severity=raw.get("severity", "info"),
                url=raw.get("url", ""),
                endpoint=raw.get("endpoint", ""),
                payload=raw.get("payload", ""),
                evidence=raw.get("evidence", ""),
                tool_source=raw.get("tool", ""),
            )
            if finding:
                results["findings"].append(raw)
                log.vuln(raw.get("severity", "info"), f"{raw.get('title', 'Unknown')} - {raw.get('url', '')}")

        log.success(f"Found {len(results['findings'])} unique findings (deduped)")
        results["finished_at"] = datetime.utcnow().isoformat()
        return results

    # --- AI Analysis Pipeline ---

    def analyze_findings(self, engagement_id: int | None = None) -> list[dict]:
        """Run AI analysis on all unanalyzed findings."""
        eng = self._require_engagement()
        eid = engagement_id or eng.id
        findings = self.db.get_findings(eid, status="new")

        log.phase("AI ANALYSIS", f"Analyzing {len(findings)} findings")
        analyzed = []

        for f in findings:
            finding_dict = {
                "title": f.title, "vuln_type": f.vuln_type, "url": f.url,
                "endpoint": f.endpoint, "method": f.method, "parameter": f.parameter,
                "payload": f.payload, "evidence": f.evidence, "tool_source": f.tool_source,
            }
            analysis = self.ai.analyze_vulnerability(finding_dict)

            self.db.update_finding_status(
                f.id,
                status="confirmed" if analysis.get("is_valid") else "false_positive",
                ai_analysis=json.dumps(analysis),
                severity=analysis.get("severity", f.severity),
                cvss_score=analysis.get("cvss_score"),
                cvss_vector=analysis.get("cvss_vector"),
                cwe_id=analysis.get("cwe_id"),
            )
            analyzed.append({"finding": finding_dict, "analysis": analysis})

            status = "[green]VALID[/green]" if analysis.get("is_valid") else "[red]FALSE POSITIVE[/red]"
            console.print(f"  {status} {f.title}")

        return analyzed

    def find_chains(self, engagement_id: int | None = None) -> dict:
        """Find exploit chains across confirmed findings."""
        eng = self._require_engagement()
        eid = engagement_id or eng.id
        findings = self.db.get_findings(eid, status="confirmed")

        if len(findings) < 2:
            log.warning("Need at least 2 confirmed findings for chain analysis")
            return {"chains": []}

        finding_dicts = [
            {"title": f.title, "vuln_type": f.vuln_type, "severity": f.severity,
             "url": f.url, "endpoint": f.endpoint}
            for f in findings
        ]

        log.phase("CHAIN ANALYSIS", f"Analyzing {len(findings)} findings for exploit chains")
        return self.ai.find_exploit_chains(finding_dicts)

    # --- Reporting ---

    def generate_report(self, finding_id: int, platform: str | None = None) -> str:
        """Generate a report for a specific finding."""
        with self.db.get_session() as session:
            from wardenstrike.core.session import Finding
            finding = session.query(Finding).get(finding_id)
            if not finding:
                raise ValueError(f"Finding {finding_id} not found")

            platform = platform or self.config.get("reporting", "platform", default="hackerone")
            finding_dict = {
                "title": finding.title, "vuln_type": finding.vuln_type,
                "severity": finding.severity, "cvss_score": finding.cvss_score,
                "cvss_vector": finding.cvss_vector, "cwe_id": finding.cwe_id,
                "url": finding.url, "endpoint": finding.endpoint,
                "method": finding.method, "parameter": finding.parameter,
                "payload": finding.payload, "evidence": finding.evidence,
                "description": finding.description, "impact": finding.impact,
                "steps_to_reproduce": finding.steps_to_reproduce,
            }
            return self.ai.generate_report(finding_dict, platform)

    # --- Integration shortcuts ---

    async def import_from_burp(self) -> list[dict]:
        """Import findings from Burp Suite."""
        from wardenstrike.integrations.burpsuite import BurpSuiteClient
        eng = self._require_engagement()
        burp = BurpSuiteClient(self.config)

        log.phase("BURP IMPORT", "Importing findings from Burp Suite")
        issues = await burp.get_issues()

        imported = []
        for issue in issues:
            fhash = hash_finding(issue["title"], issue.get("url", ""), issue.get("vuln_type", ""))
            finding = self.db.add_finding(
                engagement_id=eng.id,
                finding_hash=fhash,
                tool_source="burpsuite",
                **issue,
            )
            if finding:
                imported.append(issue)

        log.success(f"Imported {len(imported)} new findings from Burp Suite")
        return imported

    async def import_from_zap(self) -> list[dict]:
        """Import findings from OWASP ZAP."""
        from wardenstrike.integrations.zap import ZAPClient
        eng = self._require_engagement()
        zap = ZAPClient(self.config)

        log.phase("ZAP IMPORT", "Importing findings from OWASP ZAP")
        alerts = await zap.get_alerts()

        imported = []
        for alert in alerts:
            fhash = hash_finding(alert["title"], alert.get("url", ""), alert.get("vuln_type", ""))
            finding = self.db.add_finding(
                engagement_id=eng.id,
                finding_hash=fhash,
                tool_source="zap",
                **alert,
            )
            if finding:
                imported.append(alert)

        log.success(f"Imported {len(imported)} new findings from ZAP")
        return imported

    def dashboard(self, engagement_id: int | None = None) -> dict:
        """Get a summary dashboard for the current engagement."""
        eng = self._require_engagement()
        eid = engagement_id or eng.id
        stats = self.db.get_finding_stats(eid)
        targets = self.db.get_targets(eid)

        return {
            "engagement": {"id": eng.id, "name": eng.name, "platform": eng.platform, "status": eng.status},
            "targets": {"total": len(targets), "alive": sum(1 for t in targets if t.is_alive)},
            "findings": stats,
        }
