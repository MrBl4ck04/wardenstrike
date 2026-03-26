"""
WardenStrike - Web Crawler Module
Combines katana, gospider, gau, and waybackurls for comprehensive URL discovery.
"""

import asyncio
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from wardenstrike.config import Config
from wardenstrike.utils.helpers import run_command, is_tool_installed, dedup_list
from wardenstrike.utils.logger import get_logger

log = get_logger("crawler")


class WebCrawler:
    """Multi-tool web crawling and URL discovery."""

    def __init__(self, config: Config):
        self.config = config
        self.depth = config.get("recon", "crawler", "depth", default=3)
        self.js_analysis = config.get("recon", "crawler", "js_analysis", default=True)
        self.scope_strict = config.get("recon", "crawler", "scope_strict", default=True)

    async def run(self, targets: list[str], quick: bool = False) -> dict:
        """Run all crawlers and aggregate results."""
        tasks = [self._katana(targets)]

        if not quick:
            tasks.extend([
                self._gau(targets),
                self._gospider(targets),
                self._waybackurls(targets),
            ])

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_urls = []
        for result in results:
            if isinstance(result, list):
                all_urls.extend(result)

        unique_urls = dedup_list(all_urls)

        # Classify URLs
        js_files = [u for u in unique_urls if self._is_js_file(u)]
        api_endpoints = [u for u in unique_urls if self._is_api_endpoint(u)]
        parameters = self._extract_parameters(unique_urls)
        interesting = [u for u in unique_urls if self._is_interesting(u)]

        log.info(f"URLs: {len(unique_urls)} | JS: {len(js_files)} | API: {len(api_endpoints)} | Params: {len(parameters)}")

        return {
            "urls": unique_urls,
            "js_files": js_files,
            "api_endpoints": api_endpoints,
            "parameters": parameters,
            "interesting_urls": interesting,
        }

    async def _katana(self, targets: list[str]) -> list[str]:
        if not is_tool_installed("katana"):
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        outfile = tempfile.mktemp(suffix=".txt")
        cmd = f"katana -list {targets_file} -d {self.depth} -jc -kf all -ef css,png,jpg,gif,svg,woff,woff2,ttf,eot,ico -silent -o {outfile}"

        run_command(cmd, timeout=600, shell=True)
        urls = []
        if Path(outfile).exists():
            urls = [u.strip() for u in Path(outfile).read_text().split("\n") if u.strip()]
            Path(outfile).unlink(missing_ok=True)
        Path(targets_file).unlink(missing_ok=True)

        log.info(f"katana: {len(urls)} URLs")
        return urls

    async def _gau(self, targets: list[str]) -> list[str]:
        if not is_tool_installed("gau"):
            return []

        all_urls = []
        for target in targets[:10]:
            domain = urlparse(target).hostname or target
            result = run_command(f"gau --threads 5 --subs {domain}", timeout=120)
            if result["success"]:
                urls = [u.strip() for u in result["stdout"].split("\n") if u.strip()]
                all_urls.extend(urls)

        log.info(f"gau: {len(all_urls)} URLs")
        return all_urls

    async def _gospider(self, targets: list[str]) -> list[str]:
        if not is_tool_installed("gospider"):
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        result = run_command(f"gospider -S {targets_file} -d 2 -c 5 --sitemap --robots --js -q", timeout=300)
        urls = []
        if result["success"]:
            for line in result["stdout"].split("\n"):
                # gospider outputs formatted lines like [source] URL
                url_match = re.search(r'(https?://\S+)', line)
                if url_match:
                    urls.append(url_match.group(1))

        Path(targets_file).unlink(missing_ok=True)
        log.info(f"gospider: {len(urls)} URLs")
        return urls

    async def _waybackurls(self, targets: list[str]) -> list[str]:
        if not is_tool_installed("waybackurls"):
            return []

        all_urls = []
        for target in targets[:10]:
            domain = urlparse(target).hostname or target
            result = run_command(f"echo {domain} | waybackurls", timeout=60, shell=True)
            if result["success"]:
                urls = [u.strip() for u in result["stdout"].split("\n") if u.strip()]
                all_urls.extend(urls)

        log.info(f"waybackurls: {len(all_urls)} URLs")
        return all_urls

    def _is_js_file(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.path.endswith((".js", ".mjs", ".jsx", ".ts", ".tsx"))

    def _is_api_endpoint(self, url: str) -> bool:
        parsed = urlparse(url)
        api_patterns = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql", "/rest/", "/rpc/"]
        return any(p in parsed.path.lower() for p in api_patterns)

    def _is_interesting(self, url: str) -> bool:
        patterns = [
            ".env", ".git", ".svn", "config", "admin", "debug", "test",
            "backup", ".bak", ".old", ".sql", ".xml", ".json", ".yaml",
            "swagger", "api-doc", "phpinfo", "wp-admin", "wp-login",
            "server-status", ".htaccess", "web.config", "crossdomain.xml",
            "robots.txt", "sitemap.xml", "/.well-known",
            "graphql", "graphiql", "playground",
        ]
        url_lower = url.lower()
        return any(p in url_lower for p in patterns)

    def _extract_parameters(self, urls: list[str]) -> list[str]:
        """Extract unique parameter names from URLs."""
        params = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                for part in parsed.query.split("&"):
                    if "=" in part:
                        param_name = part.split("=", 1)[0]
                        if param_name:
                            params.add(param_name)
        return sorted(params)
