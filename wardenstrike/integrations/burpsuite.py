"""
WardenStrike - Burp Suite REST API Integration
Full integration with Burp Suite Professional/Enterprise via REST API.

Supports:
- Importing/exporting scan results
- Launching active and passive scans
- Managing scan configurations
- Proxy traffic analysis
- Sitemap extraction
- Issue management
"""

import json
import time
from typing import Any
from urllib.parse import urljoin

import requests

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("burpsuite")


BURP_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
}

BURP_CONFIDENCE_MAP = {
    "certain": "high",
    "firm": "high",
    "tentative": "medium",
}


class BurpSuiteClient:
    """Client for Burp Suite REST API (Professional Edition 2.x+ / Enterprise)."""

    def __init__(self, config: Config):
        self.base_url = config.get("burpsuite", "api_url", default="http://127.0.0.1:1337")
        self.api_key = config.get("burpsuite", "api_key", default="")
        self.proxy_host = config.get("burpsuite", "proxy_host", default="127.0.0.1")
        self.proxy_port = config.get("burpsuite", "proxy_port", default=8080)
        self.timeout = 30
        self._session = requests.Session()
        if self.api_key:
            self._session.headers["Authorization"] = f"Bearer {self.api_key}"

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    def _request(self, method: str, path: str, **kwargs) -> dict | list | None:
        try:
            resp = self._session.request(method, self._url(path), timeout=self.timeout, **kwargs)
            resp.raise_for_status()
            if resp.content:
                return resp.json()
            return None
        except requests.ConnectionError:
            log.error(f"Cannot connect to Burp Suite at {self.base_url}. Is it running with REST API enabled?")
            return None
        except requests.HTTPError as e:
            log.error(f"Burp Suite API error: {e}")
            return None
        except json.JSONDecodeError:
            return None

    # --- Connection Test ---

    def is_connected(self) -> bool:
        """Test if Burp Suite API is reachable."""
        try:
            resp = self._session.get(self._url("/v0.1/"), timeout=5)
            return resp.status_code < 500
        except Exception:
            return False

    def get_version(self) -> dict | None:
        """Get Burp Suite version info."""
        return self._request("GET", "/v0.1/")

    # --- Scanning ---

    def launch_scan(self, urls: list[str], scan_config: str | None = None, credentials: dict | None = None) -> str | None:
        """Launch an active scan against target URLs.

        Returns: scan task ID or None on failure.
        """
        payload: dict[str, Any] = {
            "urls": urls,
        }

        if scan_config:
            payload["scan_configurations"] = [{"name": scan_config, "type": "NamedConfiguration"}]

        if credentials:
            payload["application_logins"] = [credentials]

        result = self._request("POST", "/v0.1/scan", json=payload)
        if result and "task_id" in result:
            task_id = result["task_id"]
            log.success(f"Scan launched: task_id={task_id}")
            return task_id
        # Some versions return the task ID in the Location header
        return None

    def get_scan_status(self, task_id: str) -> dict | None:
        """Get the status of a running scan."""
        return self._request("GET", f"/v0.1/scan/{task_id}")

    def wait_for_scan(self, task_id: str, poll_interval: int = 10, max_wait: int = 3600) -> dict | None:
        """Wait for a scan to complete, polling periodically."""
        elapsed = 0
        while elapsed < max_wait:
            status = self.get_scan_status(task_id)
            if not status:
                return None

            scan_status = status.get("scan_status", "")
            log.info(f"Scan {task_id}: {scan_status} ({elapsed}s elapsed)")

            if scan_status in ("succeeded", "failed", "cancelled"):
                return status

            time.sleep(poll_interval)
            elapsed += poll_interval

        log.warning(f"Scan {task_id} timed out after {max_wait}s")
        return None

    def cancel_scan(self, task_id: str) -> bool:
        """Cancel a running scan."""
        result = self._request("DELETE", f"/v0.1/scan/{task_id}")
        return result is not None

    # --- Issues / Findings ---

    async def get_issues(self, task_id: str | None = None) -> list[dict]:
        """Get all issues from Burp Suite (from a specific scan or all)."""
        if task_id:
            status = self.get_scan_status(task_id)
            if not status:
                return []
            raw_issues = status.get("issue_events", [])
        else:
            result = self._request("GET", "/v0.1/knowledge_base/issue_definitions")
            raw_issues = result if isinstance(result, list) else []

        findings = []
        for issue in raw_issues:
            issue_data = issue.get("issue", issue)
            finding = {
                "title": issue_data.get("name", "Unknown Issue"),
                "vuln_type": self._map_issue_type(issue_data.get("type_index", "")),
                "severity": BURP_SEVERITY_MAP.get(issue_data.get("severity", "").lower(), "info"),
                "confidence": BURP_CONFIDENCE_MAP.get(issue_data.get("confidence", "").lower(), "medium"),
                "url": issue_data.get("origin", "") + issue_data.get("path", ""),
                "description": issue_data.get("issue_background", ""),
                "evidence": issue_data.get("issue_detail", ""),
                "remediation": issue_data.get("remediation_background", ""),
                "request": self._extract_request(issue_data),
                "response": self._extract_response(issue_data),
            }
            findings.append(finding)

        return findings

    def get_sitemap(self, url_prefix: str = "") -> list[dict]:
        """Get the Burp sitemap entries."""
        params = {}
        if url_prefix:
            params["urlPrefix"] = url_prefix
        result = self._request("GET", "/v0.1/sitemap", params=params)
        return result if isinstance(result, list) else []

    def get_proxy_history(self, limit: int = 100) -> list[dict]:
        """Get recent proxy history entries."""
        result = self._request("GET", "/v0.1/proxy/history", params={"limit": limit})
        return result if isinstance(result, list) else []

    # --- Scope Management ---

    def get_scope(self) -> dict | None:
        """Get the current Burp target scope."""
        return self._request("GET", "/v0.1/target/scope")

    def add_to_scope(self, url: str) -> bool:
        """Add a URL to Burp's target scope."""
        result = self._request("PUT", "/v0.1/target/scope", params={"url": url})
        return True

    def remove_from_scope(self, url: str) -> bool:
        """Remove a URL from Burp's target scope."""
        result = self._request("DELETE", "/v0.1/target/scope", params={"url": url})
        return True

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in Burp's scope."""
        result = self._request("GET", "/v0.1/target/scope/check", params={"url": url})
        return bool(result and result.get("in_scope"))

    # --- Configuration ---

    def get_scan_configs(self) -> list[dict]:
        """List available scan configurations."""
        result = self._request("GET", "/v0.1/scan/configurations")
        return result if isinstance(result, list) else []

    # --- Export ---

    def export_issues_json(self, task_id: str | None = None) -> str:
        """Export issues as JSON string."""
        import asyncio
        issues = asyncio.get_event_loop().run_until_complete(self.get_issues(task_id))
        return json.dumps(issues, indent=2, default=str)

    # --- Helpers ---

    @property
    def proxy_url(self) -> str:
        """Get the proxy URL for routing traffic through Burp."""
        return f"http://{self.proxy_host}:{self.proxy_port}"

    def _map_issue_type(self, type_index: str) -> str:
        """Map Burp issue type index to our vulnerability categories."""
        type_map = {
            "1048832": "xss", "1049088": "xss", "1049344": "xss",  # XSS variants
            "1049600": "sqli", "1049856": "sqli",  # SQL injection
            "1050112": "command_injection", "1050368": "path_traversal",
            "1050624": "lfi", "1050880": "xxe", "1051136": "ssrf",
            "1051392": "ssti", "1051648": "open_redirect",
            "1051904": "cors", "1052160": "csrf",
            "2097408": "info",  # Information disclosure
            "5244416": "deserialization",
            "5245952": "jwt",
        }
        return type_map.get(str(type_index), "other")

    def _extract_request(self, issue: dict) -> str:
        """Extract HTTP request from issue evidence."""
        evidence = issue.get("evidence", [])
        if isinstance(evidence, list):
            for ev in evidence:
                if isinstance(ev, dict) and "request" in ev:
                    return ev["request"]
        return ""

    def _extract_response(self, issue: dict) -> str:
        """Extract HTTP response from issue evidence (truncated)."""
        evidence = issue.get("evidence", [])
        if isinstance(evidence, list):
            for ev in evidence:
                if isinstance(ev, dict) and "response" in ev:
                    resp = ev["response"]
                    return resp[:5000] if len(resp) > 5000 else resp
        return ""


class BurpCollaborator:
    """Burp Collaborator client for out-of-band interaction detection."""

    def __init__(self, collaborator_server: str = ""):
        self.server = collaborator_server
        self._interactions = []

    def generate_payload(self, interaction_type: str = "dns") -> str:
        """Generate a Collaborator payload URL.
        Note: Requires Burp Suite Professional with Collaborator configured.
        """
        # This would typically use Burp's Collaborator API
        # Placeholder for custom collaborator integration
        if self.server:
            import secrets
            token = secrets.token_hex(8)
            return f"{token}.{self.server}"
        return ""

    def poll_interactions(self) -> list[dict]:
        """Poll for out-of-band interactions."""
        # Would integrate with Burp Collaborator polling API
        return self._interactions
