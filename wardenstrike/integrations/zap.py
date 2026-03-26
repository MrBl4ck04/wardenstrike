"""
WardenStrike - OWASP ZAP API Integration
Full integration with OWASP ZAP via its REST API.

Supports:
- Spider/Ajax spider crawling
- Active/passive scanning
- Alert management & import
- Context and scope management
- Authentication configuration
- Report generation
"""

import time
from typing import Any

import requests

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("zap")

ZAP_RISK_MAP = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}

ZAP_CONFIDENCE_MAP = {
    "0": "false_positive",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "confirmed",
}


class ZAPClient:
    """Client for OWASP ZAP REST API."""

    def __init__(self, config: Config):
        self.base_url = config.get("zap", "api_url", default="http://127.0.0.1:8081")
        self.api_key = config.get("zap", "api_key", default="")
        self.timeout = 30

    def _url(self, component: str, operation: str, view_or_action: str = "view") -> str:
        return f"{self.base_url}/JSON/{component}/{view_or_action}/{operation}/"

    def _params(self, **kwargs) -> dict:
        params = {"apikey": self.api_key} if self.api_key else {}
        params.update({k: v for k, v in kwargs.items() if v is not None})
        return params

    def _get(self, component: str, operation: str, view_or_action: str = "view", **kwargs) -> dict | None:
        try:
            resp = requests.get(
                self._url(component, operation, view_or_action),
                params=self._params(**kwargs),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError:
            log.error(f"Cannot connect to ZAP at {self.base_url}")
            return None
        except Exception as e:
            log.error(f"ZAP API error: {e}")
            return None

    # --- Connection ---

    def is_connected(self) -> bool:
        result = self._get("core", "version")
        return result is not None

    def get_version(self) -> str:
        result = self._get("core", "version")
        return result.get("version", "unknown") if result else "not connected"

    # --- Spider ---

    def spider_scan(self, url: str, max_depth: int = 5, subtree_only: bool = True) -> str | None:
        """Start a spider scan. Returns scan ID."""
        result = self._get("spider", "scan", "action",
                          url=url, maxChildren=str(max_depth),
                          subtreeOnly=str(subtree_only).lower())
        if result:
            scan_id = result.get("scan")
            log.info(f"Spider scan started: {scan_id}")
            return scan_id
        return None

    def spider_status(self, scan_id: str) -> int:
        """Get spider scan progress (0-100)."""
        result = self._get("spider", "status", scanId=scan_id)
        return int(result.get("status", 0)) if result else 0

    def spider_results(self, scan_id: str) -> list[str]:
        """Get URLs found by spider."""
        result = self._get("spider", "results", scanId=scan_id)
        return result.get("results", []) if result else []

    def ajax_spider_scan(self, url: str, in_scope: bool = True) -> str | None:
        """Start an Ajax spider scan for JS-heavy apps."""
        result = self._get("ajaxSpider", "scan", "action",
                          url=url, inScope=str(in_scope).lower())
        if result and result.get("Result") == "OK":
            log.info("Ajax spider started")
            return "running"
        return None

    def ajax_spider_status(self) -> str:
        result = self._get("ajaxSpider", "status")
        return result.get("status", "stopped") if result else "stopped"

    # --- Active Scan ---

    def active_scan(self, url: str, recurse: bool = True, scan_policy: str | None = None) -> str | None:
        """Start an active scan. Returns scan ID."""
        kwargs: dict[str, Any] = {"url": url, "recurse": str(recurse).lower()}
        if scan_policy:
            kwargs["scanPolicyName"] = scan_policy
        result = self._get("ascan", "scan", "action", **kwargs)
        if result:
            scan_id = result.get("scan")
            log.info(f"Active scan started: {scan_id}")
            return scan_id
        return None

    def active_scan_status(self, scan_id: str) -> int:
        """Get active scan progress (0-100)."""
        result = self._get("ascan", "status", scanId=scan_id)
        return int(result.get("status", 0)) if result else 0

    def wait_for_active_scan(self, scan_id: str, poll_interval: int = 10, max_wait: int = 3600) -> bool:
        """Wait for active scan to complete."""
        elapsed = 0
        while elapsed < max_wait:
            progress = self.active_scan_status(scan_id)
            log.info(f"Active scan {scan_id}: {progress}% ({elapsed}s)")
            if progress >= 100:
                return True
            time.sleep(poll_interval)
            elapsed += poll_interval
        return False

    def stop_active_scan(self, scan_id: str):
        self._get("ascan", "stop", "action", scanId=scan_id)

    # --- Alerts / Findings ---

    async def get_alerts(self, base_url: str = "", risk: str = "") -> list[dict]:
        """Get all alerts, optionally filtered by URL and risk level."""
        kwargs = {}
        if base_url:
            kwargs["baseurl"] = base_url
        if risk:
            kwargs["riskId"] = risk

        result = self._get("core", "alerts", **kwargs)
        if not result:
            return []

        alerts = []
        for alert in result.get("alerts", []):
            alerts.append({
                "title": alert.get("name", "Unknown"),
                "vuln_type": self._map_alert_type(alert.get("cweid", ""), alert.get("name", "")),
                "severity": ZAP_RISK_MAP.get(str(alert.get("riskcode", 0)), "info"),
                "confidence": ZAP_CONFIDENCE_MAP.get(str(alert.get("confidence", 0)), "medium"),
                "url": alert.get("url", ""),
                "method": alert.get("method", ""),
                "parameter": alert.get("param", ""),
                "payload": alert.get("attack", ""),
                "evidence": alert.get("evidence", ""),
                "description": alert.get("description", ""),
                "remediation": alert.get("solution", ""),
                "cwe_id": f"CWE-{alert.get('cweid', '')}" if alert.get("cweid") else "",
                "references": alert.get("reference", ""),
            })

        return alerts

    def get_alert_count(self) -> dict:
        """Get alert count by risk level."""
        result = self._get("alert", "alertsSummary")
        return result.get("alertsSummary", {}) if result else {}

    # --- Context & Scope ---

    def create_context(self, name: str) -> str | None:
        """Create a new context."""
        result = self._get("context", "newContext", "action", contextName=name)
        return result.get("contextId") if result else None

    def include_in_context(self, context_name: str, regex: str):
        """Add URL regex pattern to context scope."""
        self._get("context", "includeInContext", "action",
                  contextName=context_name, regex=regex)

    def exclude_from_context(self, context_name: str, regex: str):
        """Exclude URL regex from context scope."""
        self._get("context", "excludeFromContext", "action",
                  contextName=context_name, regex=regex)

    # --- Authentication ---

    def set_form_auth(self, context_id: str, login_url: str, login_body: str,
                      username_param: str = "username", password_param: str = "password"):
        """Configure form-based authentication."""
        auth_params = (
            f"loginUrl={login_url}&loginRequestData={login_body}"
            f"&usernameParameter={username_param}&passwordParameter={password_param}"
        )
        self._get("authentication", "setAuthenticationMethod", "action",
                  contextId=context_id, authMethodName="formBasedAuthentication",
                  authMethodConfigParams=auth_params)

    def add_user(self, context_id: str, username: str, password: str) -> str | None:
        """Add a user to a context."""
        result = self._get("users", "newUser", "action",
                          contextId=context_id, name=username)
        if result:
            user_id = result.get("userId")
            if user_id:
                creds = f"username={username}&password={password}"
                self._get("users", "setAuthenticationCredentials", "action",
                          contextId=context_id, userId=user_id,
                          authCredentialsConfigParams=creds)
                self._get("users", "setUserEnabled", "action",
                          contextId=context_id, userId=user_id, enabled="true")
                return user_id
        return None

    # --- Full Scan Workflow ---

    def full_scan(self, target_url: str, scan_policy: str | None = None) -> dict:
        """Run a complete ZAP scan: spider + active scan."""
        results = {"target": target_url, "spider_urls": [], "alerts": []}

        # Spider
        spider_id = self.spider_scan(target_url)
        if spider_id:
            elapsed = 0
            while elapsed < 600:
                progress = self.spider_status(spider_id)
                if progress >= 100:
                    break
                time.sleep(5)
                elapsed += 5
            results["spider_urls"] = self.spider_results(spider_id)
            log.success(f"Spider found {len(results['spider_urls'])} URLs")

        # Active scan
        scan_id = self.active_scan(target_url, scan_policy=scan_policy)
        if scan_id:
            self.wait_for_active_scan(scan_id)

        import asyncio
        results["alerts"] = asyncio.get_event_loop().run_until_complete(self.get_alerts(target_url))
        log.success(f"Found {len(results['alerts'])} alerts")

        return results

    # --- Helpers ---

    def _map_alert_type(self, cwe_id: str, name: str) -> str:
        """Map CWE ID or alert name to our vulnerability categories."""
        cwe_map = {
            "79": "xss", "89": "sqli", "918": "ssrf", "22": "path_traversal",
            "78": "command_injection", "611": "xxe", "352": "csrf",
            "601": "open_redirect", "94": "ssti", "502": "deserialization",
            "943": "nosql_injection", "639": "idor", "287": "auth_bypass",
            "798": "hardcoded_creds", "200": "info_disclosure",
            "16": "misconfiguration", "693": "cors",
        }

        if cwe_id and str(cwe_id) in cwe_map:
            return cwe_map[str(cwe_id)]

        name_lower = name.lower()
        for keyword, vtype in [("xss", "xss"), ("sql", "sqli"), ("ssrf", "ssrf"),
                                ("redirect", "open_redirect"), ("csrf", "csrf"),
                                ("cors", "cors"), ("injection", "injection")]:
            if keyword in name_lower:
                return vtype

        return "other"
