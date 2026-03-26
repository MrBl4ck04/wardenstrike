"""
WardenStrike - Fuzzer Module
Directory and parameter fuzzing using ffuf and arjun.
"""

import json
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from wardenstrike.config import Config
from wardenstrike.utils.helpers import run_command, is_tool_installed
from wardenstrike.utils.logger import get_logger

log = get_logger("fuzzer")


class Fuzzer:
    """Directory and parameter fuzzing."""

    def __init__(self, config: Config):
        self.config = config
        self.wordlist = config.get("recon", "fuzzing", "wordlist", default="/usr/share/wordlists/dirb/common.txt")
        self.extensions = config.get("recon", "fuzzing", "extensions", default=[".php", ".html", ".js"])
        self.threads = config.get("recon", "fuzzing", "threads", default=40)
        self.rate_limit = config.get("recon", "fuzzing", "rate_limit", default=0)

    async def run(self, targets: list[str]) -> list[dict]:
        """Run directory fuzzing on targets."""
        findings = []
        for target in targets:
            result = await self.fuzz_directories(target)
            findings.extend(result)
        return findings

    async def fuzz_directories(self, target_url: str) -> list[dict]:
        """Fuzz directories on a target URL."""
        if not is_tool_installed("ffuf"):
            log.warning("ffuf not installed, skipping directory fuzzing")
            return []

        if not Path(self.wordlist).exists():
            log.warning(f"Wordlist not found: {self.wordlist}")
            return []

        base_url = target_url.rstrip("/")
        outfile = tempfile.mktemp(suffix=".json")

        ext_str = ",".join(self.extensions)
        cmd_parts = [
            "ffuf",
            f"-u {base_url}/FUZZ",
            f"-w {self.wordlist}",
            f"-e {ext_str}",
            f"-t {self.threads}",
            "-mc 200,201,301,302,307,401,403,405,500",
            "-fc 404",
            "-ac",  # Auto-calibrate filtering
            "-sf",  # Stop on spurious results
            f"-o {outfile}",
            "-of json",
            "-s",  # Silent
        ]

        if self.rate_limit > 0:
            cmd_parts.append(f"-rate {self.rate_limit}")

        proxy = self.config.get("general", "proxy")
        if proxy:
            cmd_parts.append(f"-x {proxy}")

        cmd = " ".join(cmd_parts)
        log.info(f"Fuzzing: {base_url}")
        run_command(cmd, timeout=300, shell=True)

        findings = []
        if Path(outfile).exists():
            try:
                data = json.loads(Path(outfile).read_text())
                for result in data.get("results", []):
                    status = result.get("status", 0)
                    url = result.get("url", "")
                    length = result.get("length", 0)

                    finding = {
                        "title": f"Directory/File Found: {result.get('input', {}).get('FUZZ', '')}",
                        "vuln_type": self._classify_finding(url, status),
                        "severity": self._rate_severity(url, status),
                        "url": url,
                        "evidence": f"Status: {status}, Size: {length}",
                        "tool": "ffuf",
                    }
                    findings.append(finding)
            except (json.JSONDecodeError, KeyError):
                pass
            Path(outfile).unlink(missing_ok=True)

        log.info(f"ffuf ({base_url}): {len(findings)} results")
        return findings

    async def fuzz_parameters(self, target_url: str) -> list[str]:
        """Discover hidden parameters using arjun."""
        if not is_tool_installed("arjun"):
            log.warning("arjun not installed, skipping parameter discovery")
            return []

        outfile = tempfile.mktemp(suffix=".json")
        cmd = f"arjun -u {target_url} -oJ {outfile} -q"
        run_command(cmd, timeout=120)

        params = []
        if Path(outfile).exists():
            try:
                data = json.loads(Path(outfile).read_text())
                for url_data in data.values():
                    if isinstance(url_data, dict):
                        params.extend(url_data.get("params", []))
                    elif isinstance(url_data, list):
                        params.extend(url_data)
            except (json.JSONDecodeError, KeyError):
                pass
            Path(outfile).unlink(missing_ok=True)

        log.info(f"arjun ({target_url}): {len(params)} parameters found")
        return params

    async def fuzz_vhosts(self, target_ip: str, domain: str) -> list[dict]:
        """Fuzz virtual hosts."""
        if not is_tool_installed("ffuf"):
            return []

        if not Path(self.wordlist).exists():
            return []

        outfile = tempfile.mktemp(suffix=".json")
        cmd = (
            f"ffuf -u http://{target_ip} -H 'Host: FUZZ.{domain}' "
            f"-w {self.wordlist} -t {self.threads} -ac -sf "
            f"-o {outfile} -of json -s"
        )
        run_command(cmd, timeout=300, shell=True)

        findings = []
        if Path(outfile).exists():
            try:
                data = json.loads(Path(outfile).read_text())
                for result in data.get("results", []):
                    vhost = f"{result.get('input', {}).get('FUZZ', '')}.{domain}"
                    findings.append({
                        "title": f"Virtual Host Found: {vhost}",
                        "vuln_type": "info_disclosure",
                        "severity": "info",
                        "url": f"http://{vhost}",
                        "evidence": f"Status: {result.get('status')}, Size: {result.get('length')}",
                        "tool": "ffuf",
                    })
            except (json.JSONDecodeError, KeyError):
                pass
            Path(outfile).unlink(missing_ok=True)

        return findings

    def _classify_finding(self, url: str, status: int) -> str:
        url_lower = url.lower()
        sensitive = [".env", ".git", "config", "backup", ".sql", ".bak", "admin",
                     "phpmyadmin", "wp-admin", "debug", ".htaccess", "web.config"]

        if any(s in url_lower for s in sensitive):
            return "info_disclosure"
        if status == 403:
            return "access_control"
        if status == 500:
            return "misconfiguration"
        return "info_disclosure"

    def _rate_severity(self, url: str, status: int) -> str:
        url_lower = url.lower()

        critical_patterns = [".env", ".git/config", "credentials", "secret"]
        high_patterns = [".sql", ".bak", "backup", "dump", "phpmyadmin", "adminer"]
        medium_patterns = ["admin", "debug", "config", ".htaccess", "web.config"]

        if any(p in url_lower for p in critical_patterns):
            return "high"
        if any(p in url_lower for p in high_patterns):
            return "medium"
        if any(p in url_lower for p in medium_patterns):
            return "low"
        if status in (401, 403):
            return "info"
        return "info"
