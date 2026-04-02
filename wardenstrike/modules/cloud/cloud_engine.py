"""
WardenStrike - Cloud Engine
Orchestrates multi-cloud security assessment across AWS, GCP, and Azure.
"""

import asyncio
from typing import Any

from wardenstrike.config import Config
from wardenstrike.core.session import DatabaseManager
from wardenstrike.utils.logger import get_logger
from .aws import AWSEnumerator
from .gcp import GCPEnumerator
from .azure import AzureEnumerator

log = get_logger("cloud_engine")


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class CloudEngine:
    """
    Orchestrates cloud security assessments.
    Saves findings to the WardenStrike DB for unified reporting.
    """

    def __init__(self, config: Config, db: DatabaseManager, engagement_id: int):
        self.config = config
        self.db = db
        self.engagement_id = engagement_id

    def _save_findings(self, findings: list[dict], provider: str):
        """Persist cloud findings into the central findings DB."""
        saved = 0
        for f in findings:
            title = f"{provider.upper()} | {f.get('service', '?')} | {f.get('issue', '?')}"
            self.db.add_finding(
                engagement_id=self.engagement_id,
                title=title,
                severity=f.get("severity", "medium"),
                vuln_type=f"cloud_{provider.lower()}_{f.get('service', 'misc').lower()}",
                url=f.get("resource", ""),
                description=f.get("issue", ""),
                evidence=str(f.get("details", {})),
                remediation=f.get("remediation", ""),
                tool_source=f"wardenstrike-cloud-{provider.lower()}",
                raw_data=f,
            )
            saved += 1
        log.info(f"Saved {saved} {provider} findings to DB")

    # ─── AWS ──────────────────────────────────────────────────────

    async def scan_aws(self, profile: str = "default", region: str = "us-east-1") -> dict:
        """Run full AWS security assessment."""
        log.info(f"Starting AWS scan (profile={profile}, region={region})")
        aws = AWSEnumerator(self.config, profile=profile, region=region)
        results = await aws.run_full_scan()

        if "error" not in results:
            self._save_findings(results.get("findings", []), "AWS")

        return results

    # ─── GCP ──────────────────────────────────────────────────────

    async def scan_gcp(self, project: str = None) -> dict:
        """Run full GCP security assessment."""
        log.info(f"Starting GCP scan (project={project})")
        gcp = GCPEnumerator(self.config, project=project)
        results = await gcp.run_full_scan(project)

        if "error" not in results:
            self._save_findings(results.get("findings", []), "GCP")

        return results

    # ─── Azure ────────────────────────────────────────────────────

    async def scan_azure(self, subscription: str = None) -> dict:
        """Run full Azure security assessment."""
        log.info(f"Starting Azure scan (subscription={subscription})")
        azure = AzureEnumerator(self.config, subscription=subscription)
        results = await azure.run_full_scan(subscription)

        if "error" not in results:
            self._save_findings(results.get("findings", []), "Azure")

        return results

    # ─── Multi-cloud ──────────────────────────────────────────────

    async def scan_all(self, aws_profile: str = "default", aws_region: str = "us-east-1",
                       gcp_project: str = None, azure_subscription: str = None) -> dict:
        """Run all cloud providers in parallel."""
        log.info("Starting multi-cloud scan...")

        tasks = {
            "aws": self.scan_aws(aws_profile, aws_region),
            "gcp": self.scan_gcp(gcp_project),
            "azure": self.scan_azure(azure_subscription),
        }

        results = {}
        for provider, coro in tasks.items():
            try:
                results[provider] = await coro
            except Exception as e:
                log.error(f"{provider} scan failed: {e}")
                results[provider] = {"error": str(e)}

        # Combined summary
        total_findings = sum(
            len(r.get("findings", []))
            for r in results.values()
            if "error" not in r
        )

        results["combined_summary"] = {
            "total_findings": total_findings,
            "providers_scanned": [p for p, r in results.items() if "error" not in r],
            "providers_failed": [p for p, r in results.items() if "error" in r],
        }

        return results
