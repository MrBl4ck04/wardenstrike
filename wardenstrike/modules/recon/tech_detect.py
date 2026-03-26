"""
WardenStrike - Technology Detection Module
Identifies technologies, frameworks, WAFs, and CDNs.
"""

import json
import re
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.http import HTTPClient
from wardenstrike.utils.logger import get_logger

log = get_logger("tech_detect")

# Common technology fingerprints
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "Express": "nodejs_express",
            "PHP": "php",
            "ASP.NET": "aspnet",
            "Next.js": "nextjs",
            "Nuxt": "nuxtjs",
        },
        "Server": {
            "nginx": "nginx",
            "Apache": "apache",
            "Microsoft-IIS": "iis",
            "cloudflare": "cloudflare",
            "AmazonS3": "aws_s3",
            "gunicorn": "python_gunicorn",
            "Kestrel": "aspnet_kestrel",
        },
        "X-Generator": {
            "WordPress": "wordpress",
            "Drupal": "drupal",
            "Joomla": "joomla",
        },
    },
    "body_patterns": [
        (r"wp-content|wp-includes|wp-json", "wordpress"),
        (r"/sites/default/files|Drupal\.settings", "drupal"),
        (r"<meta name=\"generator\" content=\"Joomla", "joomla"),
        (r"__next|_next/static", "nextjs"),
        (r"__nuxt|_nuxt/", "nuxtjs"),
        (r"react-root|__react|reactjs", "react"),
        (r"ng-app|ng-controller|angular\.js", "angular"),
        (r"vue-app|__vue|v-bind:|v-if=", "vuejs"),
        (r"<meta name=\"generator\" content=\"Hugo", "hugo"),
        (r"shopify\.com|Shopify\.theme", "shopify"),
        (r"Laravel|laravel_session", "laravel"),
        (r"django|csrfmiddlewaretoken", "django"),
        (r"flask|Werkzeug", "flask"),
        (r"Spring Boot|whitelabel", "spring_boot"),
        (r"Ruby on Rails|csrf-token.*authenticity", "rails"),
        (r"graphql|GraphiQL|graphql-playground", "graphql"),
        (r"swagger-ui|swagger\.json|openapi\.json", "swagger"),
        (r"firebase|firebaseapp\.com", "firebase"),
        (r"amazonaws\.com|aws-sdk", "aws"),
        (r"GoogleAnalytics|gtag\(|ga\(", "google_analytics"),
    ],
    "cookies": {
        "PHPSESSID": "php",
        "JSESSIONID": "java",
        "ASP.NET_SessionId": "aspnet",
        "csrftoken": "django",
        "laravel_session": "laravel",
        "connect.sid": "nodejs_express",
        "_rails": "rails",
        "wp-settings": "wordpress",
    },
    "waf_signatures": {
        "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
        "incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
        "sucuri": ["x-sucuri-id", "sucuri"],
        "wordfence": ["wordfence"],
        "modsecurity": ["mod_security", "modsecurity"],
        "f5_bigip": ["bigipserver", "x-wa-info"],
        "barracuda": ["barra_counter_session"],
        "fortiweb": ["fortiwafsid"],
    },
}


class TechDetector:
    """Technology fingerprinting and WAF detection."""

    def __init__(self, config: Config):
        self.config = config

    async def run(self, urls: list[str]) -> dict[str, dict]:
        """Detect technologies for multiple URLs."""
        results = {}
        proxy = self.config.get("general", "proxy")

        async with HTTPClient(proxy=proxy, rate_limit=10, timeout=15) as client:
            responses = await client.multi_get(urls, concurrency=10)

            for resp in responses:
                if resp.status == 0:
                    continue

                techs = self._detect(resp)
                if techs:
                    results[resp.url] = techs

        log.info(f"Detected technologies on {len(results)} hosts")
        return results

    def _detect(self, response) -> dict:
        """Detect technologies from an HTTP response."""
        result = {
            "technologies": [],
            "waf": [],
            "cdn": [],
            "server": "",
            "framework": "",
        }

        detected = set()

        # Header analysis
        for header_name, signatures in TECH_SIGNATURES["headers"].items():
            header_val = response.header(header_name)
            if header_val:
                for sig, tech in signatures.items():
                    if sig.lower() in header_val.lower():
                        detected.add(tech)

        # Server header
        server = response.header("server")
        if server:
            result["server"] = server

        # Body pattern analysis
        body = response.body[:50000]  # First 50KB
        for pattern, tech in TECH_SIGNATURES["body_patterns"]:
            if re.search(pattern, body, re.IGNORECASE):
                detected.add(tech)

        # Cookie analysis
        cookies_header = response.header("set-cookie")
        if cookies_header:
            for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
                if cookie_name.lower() in cookies_header.lower():
                    detected.add(tech)

        # WAF detection
        all_headers = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        for waf_name, indicators in TECH_SIGNATURES["waf_signatures"].items():
            for indicator in indicators:
                if indicator.lower() in all_headers or indicator.lower() in cookies_header.lower() if cookies_header else False:
                    result["waf"].append(waf_name)
                    break

        # Security headers check
        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        result["security_headers"] = {
            name: bool(response.header(header))
            for header, name in security_headers.items()
        }
        result["missing_security_headers"] = [
            name for header, name in security_headers.items()
            if not response.header(header)
        ]

        result["technologies"] = sorted(detected)
        result["waf"] = list(set(result["waf"]))

        return result

    async def detect_single(self, url: str) -> dict:
        """Detect technologies for a single URL."""
        async with HTTPClient(timeout=15) as client:
            resp = await client.get(url)
            if resp.status > 0:
                return self._detect(resp)
        return {}
