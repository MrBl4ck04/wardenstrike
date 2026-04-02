"""
WardenStrike - Metasploit Framework Integration
Connects to Metasploit via MSFRPC to run modules, manage sessions,
and correlate findings with exploit availability.
"""

import json
import time
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("metasploit")


class MetasploitClient:
    """
    Interface to Metasploit Framework via MSFRPC (msgpack-rpc).
    Requires: metasploit-framework, python3-msgpack, pymetasploit3
    Install: pip install pymetasploit3
    """

    def __init__(self, config: Config):
        self.config = config
        msf_cfg = config.section("metasploit")
        self.host = msf_cfg.get("host", "127.0.0.1")
        self.port = int(msf_cfg.get("port", 55553))
        self.password = msf_cfg.get("password", "msfrpc_password")
        self.ssl = msf_cfg.get("ssl", True)
        self.client = None

    def connect(self) -> bool:
        """Connect to Metasploit MSFRPC server."""
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            self.client = MsfRpcClient(
                self.password,
                server=self.host,
                port=self.port,
                ssl=self.ssl
            )
            log.info(f"Connected to Metasploit: {self.host}:{self.port}")
            return True
        except ImportError:
            log.error("pymetasploit3 not installed. Run: pip install pymetasploit3")
            return False
        except Exception as e:
            log.error(f"Metasploit connection failed: {e}")
            return False

    def is_connected(self) -> bool:
        try:
            return self.client is not None and self.client.core.version() is not None
        except Exception:
            return False

    def get_version(self) -> str:
        if not self.is_connected():
            return ""
        try:
            v = self.client.core.version()
            return v.get("version", "")
        except Exception:
            return ""

    # ─── Module search ────────────────────────────────────────────

    def search_modules(self, query: str, module_type: str = None) -> list[dict]:
        """Search Metasploit modules for a given vulnerability/CVE."""
        if not self.is_connected():
            return []
        try:
            modules = self.client.modules.search(query)
            results = []
            for m in modules:
                if module_type and not m.get("type", "").startswith(module_type):
                    continue
                results.append({
                    "fullname": m.get("fullname", ""),
                    "type": m.get("type", ""),
                    "name": m.get("name", ""),
                    "rank": m.get("rank", ""),
                    "disclosure_date": m.get("disclosure_date", ""),
                })
            return results
        except Exception as e:
            log.debug(f"Module search error: {e}")
            return []

    def find_exploits_for_cve(self, cve: str) -> list[dict]:
        """Find Metasploit exploits for a specific CVE."""
        return self.search_modules(cve, module_type="exploit")

    def find_exploits_for_service(self, service: str, version: str = "") -> list[dict]:
        """Find exploits for a service/product."""
        query = f"{service} {version}".strip()
        return self.search_modules(query, module_type="exploit")

    # ─── Session management ───────────────────────────────────────

    def list_sessions(self) -> dict:
        """List all active Metasploit sessions."""
        if not self.is_connected():
            return {}
        try:
            return self.client.sessions.list
        except Exception:
            return {}

    def run_module(self, module_path: str, options: dict,
                    module_type: str = "exploit",
                    payload: str = "generic/shell_reverse_tcp") -> dict:
        """
        Run a Metasploit module with given options.
        Returns job/session info.
        """
        if not self.is_connected():
            return {"error": "Not connected to Metasploit"}

        try:
            module = self.client.modules.use(module_type, module_path)
            for key, value in options.items():
                module[key] = value

            if module_type == "exploit":
                module["PAYLOAD"] = payload
                result = module.execute(payload=self.client.modules.use("payload", payload))
            else:
                result = module.execute()

            return {"job_id": result.get("job_id"), "uuid": result.get("uuid")}
        except Exception as e:
            log.error(f"Module execution error: {e}")
            return {"error": str(e)}

    def run_auxiliary(self, module_path: str, options: dict) -> dict:
        """Run an auxiliary module (scanner, recon, etc)."""
        return self.run_module(module_path, options, module_type="auxiliary")

    # ─── Post-exploitation ────────────────────────────────────────

    def run_post_module(self, session_id: str, module_path: str,
                         options: dict = None) -> dict:
        """Run a post-exploitation module on an active session."""
        if not self.is_connected():
            return {"error": "Not connected"}
        try:
            module = self.client.modules.use("post", module_path)
            module["SESSION"] = session_id
            if options:
                for k, v in options.items():
                    module[k] = v
            result = module.execute()
            return result
        except Exception as e:
            return {"error": str(e)}

    # ─── Common recon auxiliaries ─────────────────────────────────

    def run_smb_enum(self, rhosts: str) -> dict:
        return self.run_auxiliary("scanner/smb/smb_enumshares", {"RHOSTS": rhosts})

    def run_ms17_010_check(self, rhosts: str) -> dict:
        return self.run_auxiliary("scanner/smb/smb_ms17_010", {"RHOSTS": rhosts})

    def run_http_version(self, rhosts: str, rport: int = 80) -> dict:
        return self.run_auxiliary("scanner/http/http_version", {"RHOSTS": rhosts, "RPORT": rport})

    def run_ftp_anon(self, rhosts: str) -> dict:
        return self.run_auxiliary("scanner/ftp/anonymous", {"RHOSTS": rhosts})

    # ─── Correlate with WardenStrike findings ─────────────────────

    def correlate_findings(self, findings: list[dict]) -> list[dict]:
        """
        For each finding, search for Metasploit exploits.
        Returns enriched findings with exploit availability.
        """
        enriched = []
        for finding in findings:
            result = dict(finding)
            result["msf_modules"] = []

            # Search by CVE if available
            cves = finding.get("cves", []) or []
            for cve in cves:
                modules = self.find_exploits_for_cve(cve)
                result["msf_modules"].extend(modules)

            # Search by vuln type
            vuln_type = finding.get("vuln_type", "")
            if vuln_type and not result["msf_modules"]:
                modules = self.search_modules(vuln_type)
                result["msf_modules"].extend(modules[:3])

            if result["msf_modules"]:
                result["exploitable"] = True
                result["exploit_count"] = len(result["msf_modules"])
                log.info(f"Found {len(result['msf_modules'])} MSF modules for: {finding.get('title', '?')}")

            enriched.append(result)

        return enriched
