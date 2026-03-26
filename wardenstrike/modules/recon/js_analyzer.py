"""
WardenStrike - JavaScript Analysis Module
AI-powered JavaScript analysis for endpoint discovery, secret detection, and vulnerability hunting.
Inspired by SecEngAI's methodology for AI-assisted JS analysis.
"""

import asyncio
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from wardenstrike.config import Config
from wardenstrike.core.ai_engine import AIEngine
from wardenstrike.utils.http import HTTPClient
from wardenstrike.utils.helpers import extract_endpoints_from_js, save_json
from wardenstrike.utils.logger import get_logger

log = get_logger("js_analyzer")


# Patterns for static analysis (fast, no AI needed)
STATIC_PATTERNS = {
    "api_endpoints": [
        r'["\'](/api/v?\d*/[^\s"\']+)["\']',
        r'["\'](/graphql[^\s"\']*)["\']',
        r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
        r'axios\.[a-z]+\s*\(\s*[`"\']([^`"\']+)[`"\']',
        r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*[`"\']([^`"\']*api[^`"\']*)[`"\']',
        r'endpoint\s*[:=]\s*[`"\']([^`"\']+)[`"\']',
        r'baseURL\s*[:=]\s*[`"\']([^`"\']+)[`"\']',
    ],
    "secrets": [
        (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})["\']', "API Key"),
        (r'(?:secret|password|passwd|token)\s*[=:]\s*["\']([^"\']{8,})["\']', "Secret/Token"),
        (r'(?:AWS|aws)[_-]?(?:ACCESS|access)[_-]?(?:KEY|key).*?["\']([A-Z0-9]{16,})["\']', "AWS Access Key"),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Token"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe Key"),
        (r'xox[bpras]-[0-9a-zA-Z-]{10,}', "Slack Token"),
        (r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', "JWT Token"),
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
        (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
        (r'ya29\.[0-9A-Za-z_-]+', "Google OAuth Token"),
        (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', "Firebase Cloud Messaging"),
        (r'sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}', "Square Token"),
        (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Key"),
        (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Publishable Key"),
    ],
    "sensitive_paths": [
        (r'["\'](/admin[^\s"\']*)["\']', "Admin Path"),
        (r'["\'](/internal[^\s"\']*)["\']', "Internal Path"),
        (r'["\'](/debug[^\s"\']*)["\']', "Debug Path"),
        (r'["\'](/config[^\s"\']*)["\']', "Config Path"),
        (r'["\'](/backup[^\s"\']*)["\']', "Backup Path"),
        (r'["\'](/test[^\s"\']*)["\']', "Test Path"),
        (r'["\'](/staging[^\s"\']*)["\']', "Staging Path"),
        (r'["\'](/dev[^\s"\']*)["\']', "Dev Path"),
    ],
    "auth_patterns": [
        (r'(?:isAdmin|is_admin|isAuthenticated|isLoggedIn|hasPermission|hasRole)\s*[=:(]', "Auth Check"),
        (r'role\s*[=!]==?\s*["\'](?:admin|superadmin|root|moderator)["\']', "Role Check"),
        (r'localStorage\.(?:get|set)Item\s*\(\s*["\'](?:token|auth|session|jwt|user)["\']', "Client-side Auth Storage"),
        (r'document\.cookie\s*=.*(?:token|session|auth)', "Cookie Manipulation"),
        (r'Bearer\s+', "Bearer Token Usage"),
    ],
    "dangerous_functions": [
        (r'eval\s*\(', "eval() Usage"),
        (r'innerHTML\s*=', "innerHTML Assignment (potential XSS)"),
        (r'document\.write\s*\(', "document.write (potential XSS)"),
        (r'\.html\s*\(', "jQuery .html() (potential XSS)"),
        (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        (r'v-html\s*=', "Vue v-html (potential XSS)"),
        (r'bypassSecurityTrust', "Angular bypass security"),
        (r'postMessage\s*\(', "postMessage (potential XSS)"),
        (r'window\.open\s*\(', "window.open (potential redirect)"),
    ],
    "source_maps": [
        (r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', "Source Map URL"),
        (r'["\']([\w./]+\.map)["\']', "Map File Reference"),
    ],
}


class JSAnalyzer:
    """Combined static + AI-powered JavaScript analysis."""

    def __init__(self, config: Config, ai_engine: AIEngine | None = None):
        self.config = config
        self.ai = ai_engine
        self._cache: dict[str, dict] = {}  # Hash -> results cache

    async def run(self, js_urls: list[str], ai_analysis: bool = True) -> dict:
        """Analyze multiple JavaScript files."""
        results = {
            "files_analyzed": 0,
            "endpoints": [],
            "secrets": [],
            "vulnerabilities": [],
            "sensitive_paths": [],
            "auth_patterns": [],
            "source_maps": [],
            "ai_findings": [],
        }

        proxy = self.config.get("general", "proxy")
        async with HTTPClient(proxy=proxy, rate_limit=5, timeout=20) as client:
            responses = await client.multi_get(js_urls, concurrency=5)

            for resp in responses:
                if resp.status != 200 or not resp.body:
                    continue

                # Skip if already analyzed (by content hash)
                content_hash = hashlib.md5(resp.body.encode()).hexdigest()
                if content_hash in self._cache:
                    continue

                file_results = self._static_analysis(resp.body, resp.url)
                self._cache[content_hash] = file_results
                results["files_analyzed"] += 1

                results["endpoints"].extend(file_results.get("endpoints", []))
                results["secrets"].extend(file_results.get("secrets", []))
                results["vulnerabilities"].extend(file_results.get("vulnerabilities", []))
                results["sensitive_paths"].extend(file_results.get("sensitive_paths", []))
                results["auth_patterns"].extend(file_results.get("auth_patterns", []))
                results["source_maps"].extend(file_results.get("source_maps", []))

                # AI analysis for high-value files
                if ai_analysis and self.ai and self._is_high_value(file_results):
                    log.info(f"AI analyzing high-value JS: {resp.url}")
                    ai_result = self.ai.analyze_javascript(resp.body, resp.url)
                    if not ai_result.get("error"):
                        results["ai_findings"].append({
                            "source_url": resp.url,
                            "analysis": ai_result,
                        })

        # Deduplicate
        results["endpoints"] = self._dedup_findings(results["endpoints"])
        results["secrets"] = self._dedup_findings(results["secrets"])

        log.success(
            f"JS Analysis: {results['files_analyzed']} files | "
            f"{len(results['endpoints'])} endpoints | "
            f"{len(results['secrets'])} secrets | "
            f"{len(results['vulnerabilities'])} vulns"
        )

        return results

    def _static_analysis(self, js_content: str, source_url: str) -> dict:
        """Run static pattern matching on JavaScript content."""
        results: dict[str, list] = {
            "endpoints": [],
            "secrets": [],
            "vulnerabilities": [],
            "sensitive_paths": [],
            "auth_patterns": [],
            "source_maps": [],
        }

        # API Endpoints
        for pattern in STATIC_PATTERNS["api_endpoints"]:
            for match in re.finditer(pattern, js_content):
                endpoint = match.group(1)
                results["endpoints"].append({
                    "value": endpoint,
                    "source": source_url,
                    "full_url": urljoin(source_url, endpoint) if endpoint.startswith("/") else endpoint,
                    "context": match.group(0)[:150],
                })

        # Secrets
        for pattern, secret_type in STATIC_PATTERNS["secrets"]:
            for match in re.finditer(pattern, js_content):
                value = match.group(1) if match.lastindex else match.group(0)
                # Skip obvious false positives
                if len(value) < 8 or value in ("undefined", "null", "true", "false", "password"):
                    continue
                results["secrets"].append({
                    "type": secret_type,
                    "value": value[:50] + "..." if len(value) > 50 else value,
                    "source": source_url,
                    "context": match.group(0)[:200],
                })

        # Sensitive Paths
        for pattern, path_type in STATIC_PATTERNS["sensitive_paths"]:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                results["sensitive_paths"].append({
                    "type": path_type,
                    "value": match.group(1),
                    "source": source_url,
                })

        # Auth Patterns
        for pattern, auth_type in STATIC_PATTERNS["auth_patterns"]:
            for match in re.finditer(pattern, js_content):
                results["auth_patterns"].append({
                    "type": auth_type,
                    "source": source_url,
                    "context": match.group(0)[:200],
                })

        # Dangerous Functions (potential vulns)
        for pattern, vuln_type in STATIC_PATTERNS["dangerous_functions"]:
            for match in re.finditer(pattern, js_content):
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 100)
                context = js_content[start:end].strip()
                results["vulnerabilities"].append({
                    "type": vuln_type,
                    "source": source_url,
                    "context": context[:300],
                })

        # Source Maps
        for pattern, map_type in STATIC_PATTERNS["source_maps"]:
            for match in re.finditer(pattern, js_content):
                results["source_maps"].append({
                    "type": map_type,
                    "value": match.group(1),
                    "source": source_url,
                    "full_url": urljoin(source_url, match.group(1)),
                })

        return results

    def _is_high_value(self, static_results: dict) -> bool:
        """Determine if a JS file warrants AI analysis based on static findings."""
        score = 0
        score += len(static_results.get("endpoints", [])) * 2
        score += len(static_results.get("secrets", [])) * 5
        score += len(static_results.get("auth_patterns", [])) * 3
        score += len(static_results.get("vulnerabilities", [])) * 3
        return score >= 5  # Threshold for AI analysis

    def _dedup_findings(self, findings: list[dict]) -> list[dict]:
        """Deduplicate findings by value."""
        seen = set()
        unique = []
        for f in findings:
            key = f.get("value", f.get("context", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    async def analyze_single(self, url: str) -> dict:
        """Analyze a single JavaScript file."""
        async with HTTPClient(timeout=20) as client:
            resp = await client.get(url)
            if resp.status == 200 and resp.body:
                static = self._static_analysis(resp.body, url)
                ai_result = None
                if self.ai:
                    ai_result = self.ai.analyze_javascript(resp.body, url)
                return {"static": static, "ai": ai_result}
        return {"error": f"Failed to fetch {url}"}

    async def download_source_maps(self, source_map_urls: list[str], output_dir: str = "./data/sourcemaps") -> list[str]:
        """Download source maps for further analysis."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        downloaded = []

        async with HTTPClient(timeout=20) as client:
            for url in source_map_urls:
                resp = await client.get(url)
                if resp.status == 200:
                    filename = urlparse(url).path.split("/")[-1] or "sourcemap.map"
                    filepath = Path(output_dir) / filename
                    filepath.write_text(resp.body)
                    downloaded.append(str(filepath))
                    log.success(f"Downloaded source map: {filename}")

        return downloaded
