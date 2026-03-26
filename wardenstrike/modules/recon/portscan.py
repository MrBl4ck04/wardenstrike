"""
WardenStrike - Port Scanning Module
Nmap-based port scanning with service/version detection.
"""

import json
import tempfile
from pathlib import Path

from wardenstrike.config import Config
from wardenstrike.utils.helpers import run_command, is_tool_installed
from wardenstrike.utils.logger import get_logger

log = get_logger("portscan")


class PortScanner:
    """Port scanning using nmap."""

    def __init__(self, config: Config):
        self.config = config
        self.ports = config.get("recon", "portscan", "ports", default="top-1000")
        self.timing = config.get("recon", "portscan", "timing", default=4)
        self.scripts = config.get("recon", "portscan", "scripts", default=["default"])

    async def run(self, primary_target: str, subdomains: list[str] | None = None) -> dict:
        """Scan ports on primary target and optionally subdomains."""
        if not is_tool_installed("nmap"):
            log.warning("nmap not installed, skipping port scan")
            return {}

        results = {}

        # Scan primary target with full options
        log.info(f"Scanning primary target: {primary_target}")
        primary_result = self._scan_host(primary_target, full=True)
        if primary_result:
            results[primary_target] = primary_result

        # Quick scan on subdomains
        if subdomains:
            log.info(f"Quick scanning {len(subdomains)} subdomains")
            for sub in subdomains:
                sub_result = self._scan_host(sub, full=False)
                if sub_result and sub_result.get("ports"):
                    results[sub] = sub_result

        return results

    def _scan_host(self, target: str, full: bool = False) -> dict | None:
        """Scan a single host."""
        port_spec = self.ports if self.ports != "top-1000" else "--top-ports 1000"
        if self.ports == "top-1000":
            port_spec = "--top-ports 1000"
        else:
            port_spec = f"-p {self.ports}"

        cmd_parts = [
            "nmap",
            f"-T{self.timing}",
            port_spec,
            "-sV" if full else "-sS",
            "--open",
            "-oX -",  # XML output to stdout
        ]

        if full and self.scripts:
            cmd_parts.append(f"--script={','.join(self.scripts)}")

        cmd_parts.append(target)
        cmd = " ".join(cmd_parts)

        result = run_command(cmd, timeout=300, shell=True)
        if not result["success"]:
            log.debug(f"nmap failed for {target}: {result['stderr']}")
            return None

        return self._parse_xml(result["stdout"], target)

    def _parse_xml(self, xml_output: str, target: str) -> dict | None:
        """Parse nmap XML output."""
        try:
            import xmltodict
            data = xmltodict.parse(xml_output)
        except Exception:
            return None

        nmaprun = data.get("nmaprun", {})
        host = nmaprun.get("host")
        if not host:
            return None

        # Handle single host vs list
        if isinstance(host, list):
            host = host[0]

        result = {"target": target, "ports": [], "os": None}

        # Parse addresses
        addresses = host.get("address", [])
        if isinstance(addresses, dict):
            addresses = [addresses]
        for addr in addresses:
            if addr.get("@addrtype") == "ipv4":
                result["ip"] = addr.get("@addr")

        # Parse ports
        ports_data = host.get("ports", {}).get("port", [])
        if isinstance(ports_data, dict):
            ports_data = [ports_data]

        for port in ports_data:
            state = port.get("state", {})
            if state.get("@state") != "open":
                continue

            service = port.get("service", {})
            port_info = {
                "port": int(port.get("@portid", 0)),
                "protocol": port.get("@protocol", "tcp"),
                "state": "open",
                "service": service.get("@name", ""),
                "product": service.get("@product", ""),
                "version": service.get("@version", ""),
                "extra_info": service.get("@extrainfo", ""),
            }

            # Parse script results
            scripts = port.get("script", [])
            if isinstance(scripts, dict):
                scripts = [scripts]
            port_info["scripts"] = {
                s.get("@id", ""): s.get("@output", "")
                for s in scripts
            }

            result["ports"].append(port_info)

        # Parse OS detection
        os_data = host.get("os", {}).get("osmatch", [])
        if isinstance(os_data, dict):
            os_data = [os_data]
        if os_data:
            result["os"] = os_data[0].get("@name", "")

        return result

    async def quick_scan(self, targets: list[str]) -> dict:
        """Quick top-100 port scan on multiple targets."""
        results = {}
        for target in targets:
            cmd = f"nmap -T4 --top-ports 100 -sS --open -oX - {target}"
            result = run_command(cmd, timeout=120, shell=True)
            if result["success"]:
                parsed = self._parse_xml(result["stdout"], target)
                if parsed and parsed.get("ports"):
                    results[target] = parsed
        return results
