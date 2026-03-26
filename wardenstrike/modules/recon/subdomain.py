"""
WardenStrike - Subdomain Enumeration Module
Combines multiple tools: subfinder, amass, crt.sh, wayback, chaos.
"""

import asyncio
import json
import tempfile
from pathlib import Path

import aiohttp

from wardenstrike.config import Config
from wardenstrike.utils.helpers import run_command, is_tool_installed, dedup_list
from wardenstrike.utils.logger import get_logger

log = get_logger("subdomain")


class SubdomainEnum:
    """Multi-source subdomain enumeration."""

    def __init__(self, config: Config):
        self.config = config
        self.resolvers = config.get("recon", "subdomain", "resolvers")
        self.recursive = config.get("recon", "subdomain", "recursive", default=True)

    async def run(self, target: str, quick: bool = False) -> list[str]:
        """Run all subdomain enumeration sources and merge results."""
        tasks = [
            self._subfinder(target),
            self._crtsh(target),
        ]

        if not quick:
            tasks.extend([
                self._amass(target),
                self._wayback(target),
                self._chaos(target),
            ])

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_subdomains = []
        for result in results:
            if isinstance(result, list):
                all_subdomains.extend(result)
            elif isinstance(result, Exception):
                log.debug(f"Source failed: {result}")

        # Deduplicate and sort
        unique = dedup_list([s.strip().lower() for s in all_subdomains if s.strip()])
        # Filter to only subdomains of target
        filtered = [s for s in unique if s.endswith(f".{target}") or s == target]

        log.info(f"Total unique subdomains: {len(filtered)}")
        return sorted(filtered)

    async def _subfinder(self, target: str) -> list[str]:
        if not is_tool_installed("subfinder"):
            log.debug("subfinder not installed, skipping")
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            outfile = f.name

        cmd = f"subfinder -d {target} -silent -o {outfile}"
        if self.resolvers and Path(self.resolvers).exists():
            cmd += f" -rL {self.resolvers}"

        result = run_command(cmd, timeout=300)
        subs = []
        if Path(outfile).exists():
            subs = Path(outfile).read_text().strip().split("\n")
            Path(outfile).unlink(missing_ok=True)

        log.info(f"subfinder: {len(subs)} subdomains")
        return [s for s in subs if s.strip()]

    async def _amass(self, target: str) -> list[str]:
        if not is_tool_installed("amass"):
            log.debug("amass not installed, skipping")
            return []

        result = run_command(f"amass enum -passive -d {target} -silent", timeout=600)
        subs = result["stdout"].split("\n") if result["success"] else []
        log.info(f"amass: {len(subs)} subdomains")
        return [s for s in subs if s.strip()]

    async def _crtsh(self, target: str) -> list[str]:
        """Query crt.sh certificate transparency logs."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{target}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)
                    subs = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for line in name.split("\n"):
                            line = line.strip().lower()
                            if line and "*" not in line:
                                subs.add(line)
                    log.info(f"crt.sh: {len(subs)} subdomains")
                    return list(subs)
        except Exception as e:
            log.debug(f"crt.sh error: {e}")
            return []

    async def _wayback(self, target: str) -> list[str]:
        """Extract subdomains from Wayback Machine."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=5000"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)
                    subs = set()
                    for entry in data[1:]:  # Skip header row
                        if entry:
                            from urllib.parse import urlparse
                            parsed = urlparse(entry[0])
                            if parsed.hostname:
                                subs.add(parsed.hostname.lower())
                    log.info(f"wayback: {len(subs)} subdomains")
                    return list(subs)
        except Exception as e:
            log.debug(f"wayback error: {e}")
            return []

    async def _chaos(self, target: str) -> list[str]:
        """Query ProjectDiscovery Chaos API."""
        api_key = self.config.get("api_keys", "chaos", default="")
        if not api_key:
            return []
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": api_key}
                url = f"https://dns.projectdiscovery.io/dns/{target}/subdomains"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()
                    subs = [f"{s}.{target}" for s in data.get("subdomains", [])]
                    log.info(f"chaos: {len(subs)} subdomains")
                    return subs
        except Exception as e:
            log.debug(f"chaos error: {e}")
            return []
