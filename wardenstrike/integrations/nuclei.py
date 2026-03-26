"""
WardenStrike - Nuclei Integration
Wrapper for ProjectDiscovery's Nuclei vulnerability scanner.
"""

import json
import tempfile
from pathlib import Path

from wardenstrike.config import Config
from wardenstrike.utils.helpers import run_command, is_tool_installed, run_command_stream
from wardenstrike.utils.logger import get_logger

log = get_logger("nuclei")

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiScanner:
    """Interface to Nuclei scanner."""

    def __init__(self, config: Config):
        self.config = config
        self.templates_dir = config.get("scanner", "nuclei", "templates_dir", default="")
        self.severity = config.get("scanner", "nuclei", "severity", default=["critical", "high", "medium"])
        self.rate_limit = config.get("scanner", "nuclei", "rate_limit", default=150)
        self.concurrency = config.get("scanner", "nuclei", "concurrency", default=25)
        self.custom_templates = config.get("scanner", "nuclei", "custom_templates", default="")

    def is_available(self) -> bool:
        return is_tool_installed("nuclei")

    def update_templates(self) -> bool:
        """Update nuclei templates."""
        result = run_command("nuclei -update-templates", timeout=120)
        if result["success"]:
            log.success("Nuclei templates updated")
        return result["success"]

    async def scan(
        self,
        targets: list[str],
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        templates: list[str] | None = None,
        output_file: str | None = None,
        extra_args: str = "",
    ) -> list[dict]:
        """Run nuclei scan against targets."""
        if not self.is_available():
            log.error("Nuclei is not installed")
            return []

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        if not output_file:
            output_file = tempfile.mktemp(suffix=".jsonl")

        severity_filter = ",".join(severity or self.severity)

        cmd_parts = [
            "nuclei",
            f"-l {targets_file}",
            f"-severity {severity_filter}",
            f"-rate-limit {self.rate_limit}",
            f"-concurrency {self.concurrency}",
            f"-jsonl -o {output_file}",
            "-silent",
            "-no-color",
        ]

        if tags:
            cmd_parts.append(f"-tags {','.join(tags)}")
        if templates:
            cmd_parts.append(f"-t {','.join(templates)}")
        if self.custom_templates and Path(self.custom_templates).exists():
            cmd_parts.append(f"-t {self.custom_templates}")
        if extra_args:
            cmd_parts.append(extra_args)

        cmd = " ".join(cmd_parts)
        log.info(f"Running: nuclei against {len(targets)} targets")

        result = run_command(cmd, timeout=600, shell=True)

        # Parse results
        findings = []
        output_path = Path(output_file)
        if output_path.exists():
            for line in output_path.read_text().strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    finding = self._parse_result(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue

        # Cleanup
        Path(targets_file).unlink(missing_ok=True)

        log.success(f"Nuclei found {len(findings)} issues")
        return findings

    async def scan_with_tags(self, targets: list[str], tags: list[str]) -> list[dict]:
        """Run nuclei with specific template tags."""
        return await self.scan(targets, tags=tags)

    async def scan_cves(self, targets: list[str], year: int | None = None) -> list[dict]:
        """Scan for known CVEs."""
        tags = ["cve"]
        if year:
            tags = [f"cve{year}"]
        return await self.scan(targets, tags=tags)

    async def scan_exposed_panels(self, targets: list[str]) -> list[dict]:
        """Scan for exposed admin panels and login pages."""
        return await self.scan(targets, tags=["panel", "login", "dashboard"], severity=["info", "low", "medium", "high"])

    async def scan_misconfigurations(self, targets: list[str]) -> list[dict]:
        """Scan for misconfigurations."""
        return await self.scan(targets, tags=["misconfig", "exposure"])

    async def scan_takeovers(self, targets: list[str]) -> list[dict]:
        """Scan for subdomain takeover vulnerabilities."""
        return await self.scan(targets, tags=["takeover"], severity=["info", "low", "medium", "high", "critical"])

    def _parse_result(self, data: dict) -> dict | None:
        """Parse a nuclei JSONL result into our finding format."""
        info = data.get("info", {})
        severity = SEVERITY_MAP.get(info.get("severity", "").lower(), "info")

        return {
            "title": info.get("name", data.get("template-id", "Unknown")),
            "vuln_type": self._classify_vuln(info, data),
            "severity": severity,
            "url": data.get("matched-at", data.get("host", "")),
            "endpoint": data.get("matched-at", ""),
            "payload": data.get("matcher-name", ""),
            "evidence": data.get("extracted-results", data.get("matcher-name", "")),
            "description": info.get("description", ""),
            "references": info.get("reference", []),
            "cwe_id": self._extract_cwe(info),
            "cvss_score": info.get("classification", {}).get("cvss-score"),
            "cvss_vector": info.get("classification", {}).get("cvss-metrics"),
            "tool": "nuclei",
            "template": data.get("template-id", ""),
            "tags": info.get("tags", []),
        }

    def _classify_vuln(self, info: dict, data: dict) -> str:
        """Classify vulnerability type from nuclei result."""
        tags = info.get("tags", [])
        template_id = data.get("template-id", "").lower()

        tag_map = {
            "xss": "xss", "sqli": "sqli", "ssrf": "ssrf", "rce": "rce",
            "lfi": "lfi", "redirect": "open_redirect", "xxe": "xxe",
            "ssti": "ssti", "idor": "idor", "csrf": "csrf",
            "cors": "cors", "injection": "injection", "takeover": "subdomain_takeover",
            "exposure": "info_disclosure", "misconfig": "misconfiguration",
            "cve": "cve", "default-login": "default_creds",
        }

        for tag in tags:
            tag_lower = tag.lower()
            for key, vtype in tag_map.items():
                if key in tag_lower:
                    return vtype

        for key, vtype in tag_map.items():
            if key in template_id:
                return vtype

        return "other"

    def _extract_cwe(self, info: dict) -> str:
        classification = info.get("classification", {})
        cwe_ids = classification.get("cwe-id", [])
        if cwe_ids:
            return cwe_ids[0] if isinstance(cwe_ids, list) else str(cwe_ids)
        return ""
