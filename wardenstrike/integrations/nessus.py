"""
WardenStrike - Nessus / Tenable Integration
Import Nessus scan results, correlate with WardenStrike findings,
and trigger scans via Nessus REST API.
"""

import json
import time
import urllib.request
import urllib.error
import urllib.parse
import ssl
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("nessus")


class NessusClient:
    """
    Interface to Nessus / Tenable.io REST API.
    Handles: authentication, scan management, result import.
    """

    def __init__(self, config: Config):
        self.config = config
        nessus_cfg = config.section("nessus")
        self.base_url = nessus_cfg.get("url", "https://localhost:8834").rstrip("/")
        self.access_key = nessus_cfg.get("access_key", "")
        self.secret_key = nessus_cfg.get("secret_key", "")
        self.username = nessus_cfg.get("username", "")
        self.password = nessus_cfg.get("password", "")
        self.token = ""
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, data: dict = None,
                  extra_headers: dict = None) -> dict | None:
        """Make authenticated request to Nessus API."""
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "WardenStrike/1.0",
        }

        # API key auth (preferred) or session token
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key}; secretKey={self.secret_key}"
        elif self.token:
            headers["X-Cookie"] = f"token={self.token}"

        if extra_headers:
            headers.update(extra_headers)

        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ssl_ctx)
            )
            with opener.open(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read())
            except Exception:
                log.debug(f"Nessus {method} {path}: HTTP {e.code}")
                return None
        except Exception as e:
            log.debug(f"Nessus request error: {e}")
            return None

    def login(self) -> bool:
        """Authenticate with Nessus using username/password."""
        if self.access_key:
            return True  # API key doesn't need login

        resp = self._request("POST", "/session", {
            "username": self.username,
            "password": self.password
        })
        if resp and "token" in resp:
            self.token = resp["token"]
            log.info("Nessus authentication successful")
            return True

        log.error("Nessus authentication failed")
        return False

    def is_connected(self) -> bool:
        resp = self._request("GET", "/server/status")
        return resp is not None and resp.get("status") == "ready"

    def get_server_info(self) -> dict:
        return self._request("GET", "/server/properties") or {}

    # ─── Scans ────────────────────────────────────────────────────

    def list_scans(self) -> list[dict]:
        resp = self._request("GET", "/scans")
        return (resp or {}).get("scans", [])

    def get_scan(self, scan_id: int) -> dict:
        return self._request("GET", f"/scans/{scan_id}") or {}

    def create_scan(self, name: str, targets: list[str],
                     policy_id: int = None, template: str = "basic") -> dict | None:
        """Create a new Nessus scan."""
        settings = {
            "name": name,
            "text_targets": "\n".join(targets),
            "enabled": True,
        }
        if policy_id:
            settings["policy_id"] = policy_id

        payload = {
            "uuid": self._get_template_uuid(template),
            "settings": settings,
        }
        return self._request("POST", "/scans", payload)

    def _get_template_uuid(self, template_name: str) -> str:
        """Get scan template UUID by name."""
        templates = (self._request("GET", "/editor/scan/templates") or {}).get("templates", [])
        for t in templates:
            if t.get("name") == template_name or t.get("title", "").lower() == template_name.lower():
                return t.get("uuid", "")
        # Return basic network scan UUID as fallback
        return "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658"

    def launch_scan(self, scan_id: int) -> str | None:
        """Launch an existing scan."""
        resp = self._request("POST", f"/scans/{scan_id}/launch")
        return (resp or {}).get("scan_uuid")

    def get_scan_status(self, scan_id: int) -> str:
        scan = self.get_scan(scan_id)
        return scan.get("info", {}).get("status", "unknown")

    def wait_for_scan(self, scan_id: int, timeout: int = 3600) -> dict:
        """Wait for scan to complete."""
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_scan_status(scan_id)
            if status in ("completed", "aborted", "canceled"):
                return self.get_scan(scan_id)
            log.info(f"Nessus scan {scan_id} status: {status}")
            time.sleep(30)
        return {}

    # ─── Results / Vulnerabilities ────────────────────────────────

    def get_vulnerabilities(self, scan_id: int) -> list[dict]:
        """Get vulnerability findings from a scan."""
        scan = self.get_scan(scan_id)
        vulns = []

        for host in scan.get("hosts", []):
            host_id = host.get("host_id")
            host_ip = host.get("hostname", "")

            host_detail = self._request("GET", f"/scans/{scan_id}/hosts/{host_id}")
            if not host_detail:
                continue

            for vuln in host_detail.get("vulnerabilities", []):
                plugin_id = vuln.get("plugin_id")
                detail = self._request("GET", f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")

                vuln_data = {
                    "host": host_ip,
                    "plugin_id": plugin_id,
                    "plugin_name": vuln.get("plugin_name", ""),
                    "severity": self._map_severity(vuln.get("severity", 0)),
                    "port": vuln.get("port", ""),
                    "protocol": vuln.get("protocol", ""),
                }

                if detail:
                    outputs = detail.get("outputs", [{}])
                    plugin_info = outputs[0] if outputs else {}
                    vuln_data["description"] = plugin_info.get("plugin_output", "")
                    vuln_data["cvss_score"] = plugin_info.get("cvss_base_score", "")
                    vuln_data["cve"] = plugin_info.get("cve", [])
                    vuln_data["solution"] = plugin_info.get("solution", "")

                vulns.append(vuln_data)

        return vulns

    @staticmethod
    def _map_severity(severity_int: int) -> str:
        return {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(severity_int, "info")

    # ─── Import to WardenStrike ────────────────────────────────────

    def import_to_wardenstrike(self, scan_id: int, db, engagement_id: int) -> list[dict]:
        """Import Nessus findings into WardenStrike database."""
        vulns = self.get_vulnerabilities(scan_id)
        imported = []

        for vuln in vulns:
            if vuln["severity"] == "info":
                continue  # Skip info-level

            title = f"Nessus: {vuln['plugin_name']} on {vuln['host']}:{vuln['port']}"
            db.add_finding(
                engagement_id=engagement_id,
                title=title,
                severity=vuln["severity"],
                vuln_type=f"nessus_{vuln.get('plugin_id', 'unknown')}",
                url=f"{vuln['host']}:{vuln['port']}",
                description=vuln.get("description", ""),
                evidence=f"Plugin ID: {vuln['plugin_id']}\nCVEs: {', '.join(vuln.get('cve', []))}",
                remediation=vuln.get("solution", ""),
                tool_source="nessus",
                raw_data=vuln,
            )
            imported.append(vuln)

        log.info(f"Imported {len(imported)} Nessus findings")
        return imported

    # ─── Export ───────────────────────────────────────────────────

    def export_scan(self, scan_id: int, format: str = "nessus") -> bytes | None:
        """Export scan results in specified format (nessus, pdf, csv, html)."""
        # Request export
        resp = self._request("POST", f"/scans/{scan_id}/export",
                              {"format": format})
        if not resp:
            return None

        file_id = resp.get("file")
        if not file_id:
            return None

        # Wait for export
        for _ in range(30):
            status = self._request("GET", f"/scans/{scan_id}/export/{file_id}/status")
            if (status or {}).get("status") == "ready":
                break
            time.sleep(2)

        # Download
        url = f"{self.base_url}/scans/{scan_id}/export/{file_id}/download"
        try:
            headers = {}
            if self.access_key:
                headers["X-ApiKeys"] = f"accessKey={self.access_key}; secretKey={self.secret_key}"
            req = urllib.request.Request(url, headers=headers)
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ssl_ctx)
            )
            with opener.open(req, timeout=60) as resp:
                return resp.read()
        except Exception as e:
            log.error(f"Export download failed: {e}")
            return None
