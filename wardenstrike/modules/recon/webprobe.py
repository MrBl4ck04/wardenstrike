"""
WardenStrike - Web Probing Module
Uses httpx to identify live web servers and gather initial info.
"""

import json
import tempfile
from pathlib import Path

from wardenstrike.config import Config
from wardenstrike.utils.helpers import run_command, is_tool_installed
from wardenstrike.utils.logger import get_logger

log = get_logger("webprobe")


class WebProber:
    """HTTP probing using httpx."""

    def __init__(self, config: Config):
        self.config = config
        self.threads = config.get("recon", "webprobe", "threads", default=50)
        self.follow_redirects = config.get("recon", "webprobe", "follow_redirects", default=True)
        self.tech_detect = config.get("recon", "webprobe", "tech_detect", default=True)

    async def run(self, targets: list[str]) -> list[dict]:
        """Probe a list of targets for live HTTP services."""
        if not is_tool_installed("httpx"):
            log.warning("httpx not installed, using fallback probing")
            return await self._fallback_probe(targets)

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            # Ensure targets have protocol
            for t in targets:
                if not t.startswith(("http://", "https://")):
                    f.write(f"{t}\n")
                else:
                    f.write(f"{t}\n")
            targets_file = f.name

        outfile = tempfile.mktemp(suffix=".json")

        cmd_parts = [
            "httpx",
            f"-l {targets_file}",
            f"-threads {self.threads}",
            "-json",
            f"-o {outfile}",
            "-silent",
            "-no-color",
            "-status-code",
            "-title",
            "-server",
            "-content-length",
            "-content-type",
            "-cdn",
            "-ip",
        ]

        if self.follow_redirects:
            cmd_parts.append("-follow-redirects")
        if self.tech_detect:
            cmd_parts.append("-tech-detect")

        cmd = " ".join(cmd_parts)
        log.info(f"Probing {len(targets)} targets with httpx")
        run_command(cmd, timeout=300, shell=True)

        results = []
        if Path(outfile).exists():
            for line in Path(outfile).read_text().strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    host = {
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "server": data.get("webserver", ""),
                        "content_length": data.get("content_length", 0),
                        "content_type": data.get("content_type", ""),
                        "ip": data.get("host", ""),
                        "cdn": data.get("cdn_name", ""),
                        "technologies": data.get("tech", []),
                        "tls": data.get("tls", {}),
                        "redirect_url": data.get("final_url", ""),
                        "response_time": data.get("response_time", ""),
                    }
                    results.append(host)
                except json.JSONDecodeError:
                    continue
            Path(outfile).unlink(missing_ok=True)

        Path(targets_file).unlink(missing_ok=True)
        log.info(f"Found {len(results)} live hosts")
        return results

    async def _fallback_probe(self, targets: list[str]) -> list[dict]:
        """Fallback probing using our HTTP client when httpx isn't available."""
        from wardenstrike.utils.http import HTTPClient

        results = []
        async with HTTPClient(rate_limit=20, timeout=10) as client:
            for target in targets:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{target}" if not target.startswith("http") else target
                    resp = await client.get(url)
                    if resp.status > 0:
                        results.append({
                            "url": resp.url,
                            "status_code": resp.status,
                            "title": self._extract_title(resp.body),
                            "server": resp.header("server"),
                            "content_length": resp.size,
                            "content_type": resp.content_type,
                            "technologies": [],
                        })
                        break  # First successful scheme wins
        return results

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML."""
        import re
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""
