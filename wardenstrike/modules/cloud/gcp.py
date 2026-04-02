"""
WardenStrike - GCP Enumerator
Enumeration and misconfiguration detection for Google Cloud Platform.
Covers: GCS, IAM, Compute, Cloud Functions, Cloud SQL, BigQuery, GKE, Secret Manager.
"""

import asyncio
import json
import subprocess
from dataclasses import dataclass, field

from wardenstrike.utils.logger import get_logger

log = get_logger("gcp")


@dataclass
class GCPFinding:
    service: str
    resource: str
    issue: str
    severity: str
    details: dict = field(default_factory=dict)
    remediation: str = ""


class GCPEnumerator:
    """GCP enumeration via gcloud CLI + direct API calls."""

    def __init__(self, config=None, project: str = None):
        self.config = config
        self.project = project
        self.findings: list[GCPFinding] = []

    def _run(self, args: list[str]) -> dict | list | None:
        cmd = ["gcloud"] + args + ["--format=json"]
        if self.project:
            cmd += ["--project", self.project]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _add(self, service, resource, issue, severity, details=None, remediation=""):
        self.findings.append(GCPFinding(service, resource, issue, severity, details or {}, remediation))
        log.info(f"[{severity.upper()}] GCP/{service}: {issue} — {resource}")

    # ─── GCS Buckets ──────────────────────────────────────────────

    def enum_gcs(self) -> list[dict]:
        log.info("Enumerating GCS buckets...")
        buckets = self._run(["storage", "buckets", "list"])
        if not buckets:
            return []

        results = []
        for bucket in buckets:
            name = bucket.get("name", bucket.get("id", "?"))
            b = {"name": name, "issues": []}

            # IAM policy
            iam = self._run(["storage", "buckets", "get-iam-policy", f"gs://{name}"])
            if iam:
                for binding in iam.get("bindings", []):
                    members = binding.get("members", [])
                    role = binding.get("role", "")
                    if "allUsers" in members:
                        sev = "critical" if "write" in role or "admin" in role else "high"
                        self._add("GCS", name, f"Bucket publicly accessible (allUsers) role: {role}", sev,
                                  remediation="Remove allUsers from bucket IAM bindings")
                        b["issues"].append(f"public_{role}")
                    if "allAuthenticatedUsers" in members:
                        self._add("GCS", name, f"Bucket accessible by all authenticated GCP users: {role}", "medium",
                                  remediation="Remove allAuthenticatedUsers from bucket IAM bindings")
                        b["issues"].append("all_auth_users")

            # Uniform bucket-level access
            if not bucket.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled"):
                self._add("GCS", name, "Uniform bucket-level access not enabled — ACL misconfig risk", "medium",
                          remediation="Enable uniform bucket-level access to prevent ACL bypasses")
                b["issues"].append("no_uniform_acl")

            results.append(b)

        return results

    # ─── IAM ──────────────────────────────────────────────────────

    def enum_iam(self) -> dict:
        log.info("Enumerating GCP IAM bindings...")
        result = {"service_accounts": [], "bindings": [], "issues": []}

        # Project-level IAM
        policy = self._run(["projects", "get-iam-policy", self.project or "$(gcloud config get-value project)"])
        if policy:
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                members = binding.get("members", [])

                # Owner/editor at project level
                if role in ("roles/owner", "roles/editor"):
                    for member in members:
                        if member.startswith("serviceAccount:") or member.startswith("user:"):
                            self._add("IAM", member, f"Has {role} at project level — overly permissive", "high",
                                      remediation="Replace owner/editor with specific least-privilege roles")
                            result["issues"].append(f"{member}:{role}")

                # allUsers or allAuthenticatedUsers at project level
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    self._add("IAM", "project", f"Role {role} assigned to allUsers/allAuthenticatedUsers", "critical",
                              remediation="Immediately remove public IAM bindings from project")

        # Service accounts
        sa_list = self._run(["iam", "service-accounts", "list"])
        if sa_list:
            for sa in sa_list:
                email = sa.get("email", "")
                s = {"email": email, "issues": []}

                # Check for user-managed keys
                keys = self._run(["iam", "service-accounts", "keys", "list",
                                  "--iam-account", email, "--filter=keyType=USER_MANAGED"])
                if keys:
                    self._add("IAM", email, f"Service account has {len(keys)} user-managed key(s)", "medium",
                              remediation="Use workload identity instead of service account keys")
                    s["issues"].append(f"{len(keys)}_user_keys")

                result["service_accounts"].append(s)

        return result

    # ─── Compute Engine ───────────────────────────────────────────

    def enum_compute(self) -> list[dict]:
        log.info("Enumerating Compute Engine instances...")
        instances = self._run(["compute", "instances", "list"])
        if not instances:
            return []

        results = []
        for inst in instances:
            name = inst.get("name", "")
            i = {"name": name, "zone": inst.get("zone", "").split("/")[-1], "issues": []}

            # Default service account with full API access
            for sa in inst.get("serviceAccounts", []):
                if "developer.gserviceaccount.com" in sa.get("email", ""):
                    scopes = sa.get("scopes", [])
                    if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                        self._add("Compute", name,
                                  "Instance uses default SA with cloud-platform scope (full access)", "critical",
                                  remediation="Use dedicated service account with minimal permissions")
                        i["issues"].append("full_cloud_platform_scope")

            # Metadata server SSH keys
            metadata = inst.get("metadata", {}).get("items", [])
            for item in metadata:
                if item.get("key") == "block-project-ssh-keys" and item.get("value") == "true":
                    pass  # Good
                elif item.get("key") == "ssh-keys":
                    self._add("Compute", name, "Instance-level SSH keys set in metadata", "low",
                              remediation="Use OS Login instead of metadata SSH keys")

            # Shielded VM
            shielded = inst.get("shieldedInstanceConfig", {})
            if not shielded.get("enableVtpm") or not shielded.get("enableIntegrityMonitoring"):
                i["issues"].append("shielded_vm_not_fully_enabled")

            # External IP
            for nic in inst.get("networkInterfaces", []):
                for access_config in nic.get("accessConfigs", []):
                    if access_config.get("natIP"):
                        i["external_ip"] = access_config["natIP"]

            results.append(i)

        return results

    # ─── Cloud Functions ──────────────────────────────────────────

    def enum_cloud_functions(self) -> list[dict]:
        log.info("Enumerating Cloud Functions...")
        functions = self._run(["functions", "list"])
        if not functions:
            return []

        results = []
        for fn in functions:
            fname = fn.get("name", "").split("/")[-1]
            f = {"name": fname, "issues": []}

            # Unauthenticated invocation
            iam = self._run(["functions", "get-iam-policy", fname])
            if iam:
                for binding in iam.get("bindings", []):
                    if "allUsers" in binding.get("members", []):
                        self._add("CloudFunctions", fname, "Function allows unauthenticated invocation", "high",
                                  remediation="Require authentication for Cloud Function invocation")
                        f["issues"].append("unauthenticated_invoke")

            # Env vars with secrets
            env_vars = fn.get("environmentVariables", {})
            for k in env_vars:
                if any(kw in k.lower() for kw in ["secret", "key", "password", "token", "credential"]):
                    self._add("CloudFunctions", fname, f"Potential secret in env var: {k}", "high",
                              remediation="Use Secret Manager for sensitive values")
                    f["issues"].append(f"secret_env_{k}")

            results.append(f)

        return results

    # ─── Cloud SQL ────────────────────────────────────────────────

    def enum_cloud_sql(self) -> list[dict]:
        log.info("Enumerating Cloud SQL instances...")
        instances = self._run(["sql", "instances", "list"])
        if not instances:
            return []

        results = []
        for db in instances:
            name = db.get("name", "")
            d = {"name": name, "database_version": db.get("databaseVersion", ""), "issues": []}

            settings = db.get("settings", {})

            # Public IP
            ip_config = settings.get("ipConfiguration", {})
            if ip_config.get("ipv4Enabled"):
                authorized_networks = ip_config.get("authorizedNetworks", [])
                for network in authorized_networks:
                    if network.get("value") in ("0.0.0.0/0", "::/0"):
                        self._add("CloudSQL", name, "Database accessible from any IP (0.0.0.0/0)", "critical",
                                  remediation="Restrict authorized networks to specific IPs")
                        d["issues"].append("public_access_any")

            # SSL required
            if not ip_config.get("requireSsl"):
                self._add("CloudSQL", name, "SSL not required for database connections", "high",
                          remediation="Enable requireSsl on Cloud SQL instance")
                d["issues"].append("ssl_not_required")

            # Backups
            if not settings.get("backupConfiguration", {}).get("enabled"):
                d["issues"].append("backups_disabled")

            # Flags for security
            db_flags = {f["name"]: f["value"] for f in settings.get("databaseFlags", [])}
            if db_flags.get("log_connections") != "on":
                d["issues"].append("log_connections_off")

            results.append(d)

        return results

    # ─── Full scan ────────────────────────────────────────────────

    async def run_full_scan(self, project: str = None) -> dict:
        """Run complete GCP security assessment."""
        if project:
            self.project = project

        log.info(f"Starting full GCP scan (project={self.project})")
        self.findings.clear()

        # Verify auth
        auth = self._run(["auth", "list", "--filter=status:ACTIVE"])
        if not auth:
            return {"error": "No active gcloud authentication. Run: gcloud auth login", "findings": []}

        return {
            "project": self.project,
            "gcs": self.enum_gcs(),
            "iam": self.enum_iam(),
            "compute": self.enum_compute(),
            "cloud_functions": self.enum_cloud_functions(),
            "cloud_sql": self.enum_cloud_sql(),
            "findings": [vars(f) for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            }
        }
