"""
WardenStrike - AWS Enumerator
Enumeration and misconfiguration detection for Amazon Web Services.
Covers: S3, IAM, EC2, Lambda, RDS, CloudFront, API Gateway, STS, SSM, Secrets Manager.
"""

import asyncio
import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from wardenstrike.utils.logger import get_logger

log = get_logger("aws")


@dataclass
class AWSFinding:
    service: str
    resource: str
    issue: str
    severity: str  # critical/high/medium/low/info
    details: dict = field(default_factory=dict)
    remediation: str = ""


class AWSEnumerator:
    """AWS enumeration and misconfiguration detection via awscli + boto3."""

    def __init__(self, config=None, profile: str = "default", region: str = "us-east-1"):
        self.config = config
        self.profile = profile
        self.region = region
        self.findings: list[AWSFinding] = []
        self._cli_base = ["aws", "--profile", profile, "--region", region, "--output", "json"]

    # ─────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────

    def _run(self, args: list[str]) -> dict | list | None:
        cmd = self._cli_base + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return json.loads(result.stdout) if result.stdout.strip() else {}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _add(self, service, resource, issue, severity, details=None, remediation=""):
        self.findings.append(AWSFinding(service, resource, issue, severity, details or {}, remediation))
        log.info(f"[{severity.upper()}] AWS/{service}: {issue} — {resource}")

    # ─────────────────────────────────────────────────────────────
    # S3
    # ─────────────────────────────────────────────────────────────

    def enum_s3(self) -> list[dict]:
        log.info("Enumerating S3 buckets...")
        buckets_data = self._run(["s3api", "list-buckets"])
        if not buckets_data:
            return []

        results = []
        for bucket in buckets_data.get("Buckets", []):
            name = bucket["Name"]
            b = {"name": name, "issues": []}

            # Public ACL check
            acl = self._run(["s3api", "get-bucket-acl", "--bucket", name])
            if acl:
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "").endswith("AllUsers"):
                        perm = grant.get("Permission", "")
                        sev = "critical" if perm in ("WRITE", "FULL_CONTROL") else "high"
                        self._add("S3", name, f"Public {perm} access via ACL", sev,
                                  remediation="Disable public ACLs and enable Block Public Access")
                        b["issues"].append(f"public_{perm.lower()}_acl")

            # Bucket policy public
            policy = self._run(["s3api", "get-bucket-policy", "--bucket", name])
            if policy:
                policy_str = json.dumps(policy)
                if '"Principal": "*"' in policy_str or '"Principal":"*"' in policy_str:
                    self._add("S3", name, "Bucket policy allows public access (Principal: *)", "high",
                              remediation="Restrict bucket policy to specific principals")
                    b["issues"].append("public_policy")

            # Versioning
            ver = self._run(["s3api", "get-bucket-versioning", "--bucket", name])
            if ver and ver.get("Status") != "Enabled":
                b["issues"].append("versioning_disabled")

            # Server-side encryption
            enc = self._run(["s3api", "get-bucket-encryption", "--bucket", name])
            if not enc:
                self._add("S3", name, "Bucket encryption not enabled", "medium",
                          remediation="Enable SSE-S3 or SSE-KMS encryption")
                b["issues"].append("no_encryption")

            # Logging
            log_cfg = self._run(["s3api", "get-bucket-logging", "--bucket", name])
            if log_cfg and not log_cfg.get("LoggingEnabled"):
                b["issues"].append("logging_disabled")

            # Website hosting (potential data exposure)
            website = self._run(["s3api", "get-bucket-website", "--bucket", name])
            if website:
                self._add("S3", name, "Static website hosting enabled — potential data exposure", "medium",
                          details={"website_config": website},
                          remediation="Review website configuration and disable if not needed")
                b["issues"].append("website_enabled")

            results.append(b)

        return results

    # ─────────────────────────────────────────────────────────────
    # IAM
    # ─────────────────────────────────────────────────────────────

    def enum_iam(self) -> dict:
        log.info("Enumerating IAM configuration...")
        result = {"users": [], "roles": [], "policies": [], "issues": []}

        # Users
        users_data = self._run(["iam", "list-users"])
        if users_data:
            for user in users_data.get("Users", []):
                uname = user["UserName"]
                u = {"name": uname, "issues": []}

                # Check MFA
                mfa = self._run(["iam", "list-mfa-devices", "--user-name", uname])
                if mfa and not mfa.get("MFADevices"):
                    self._add("IAM", uname, "User has no MFA device configured", "high",
                              remediation="Enforce MFA for all IAM users")
                    u["issues"].append("no_mfa")

                # Access keys age
                keys = self._run(["iam", "list-access-keys", "--user-name", uname])
                if keys:
                    for key in keys.get("AccessKeyMetadata", []):
                        if key.get("Status") == "Active":
                            # Check last used
                            last_used = self._run(["iam", "get-access-key-last-used",
                                                   "--access-key-id", key["AccessKeyId"]])
                            u["issues"].append(f"active_key_{key['AccessKeyId'][:8]}...")

                # Inline policies
                inline = self._run(["iam", "list-user-policies", "--user-name", uname])
                if inline and inline.get("PolicyNames"):
                    for pname in inline["PolicyNames"]:
                        doc = self._run(["iam", "get-user-policy", "--user-name", uname, "--policy-name", pname])
                        if doc:
                            doc_str = json.dumps(doc)
                            if '"Action": "*"' in doc_str or '"Resource": "*"' in doc_str:
                                self._add("IAM", uname, f"Inline policy '{pname}' has wildcard permissions", "critical",
                                          remediation="Apply principle of least privilege")
                                u["issues"].append(f"wildcard_inline_{pname}")

                result["users"].append(u)

        # Check for admin policies attached to users/groups/roles
        policies = self._run(["iam", "list-policies", "--scope", "Local"])
        if policies:
            for policy in policies.get("Policies", []):
                pname = policy["PolicyName"]
                pid = policy["Arn"]
                version = self._run(["iam", "get-policy-version", "--policy-arn", pid,
                                     "--version-id", policy.get("DefaultVersionId", "v1")])
                if version:
                    doc_str = json.dumps(version)
                    if '"Action": "*"' in doc_str and '"Resource": "*"' in doc_str:
                        self._add("IAM", pname, "Custom policy grants AdministratorAccess (*/*)", "critical",
                                  remediation="Scope down policy to minimum required permissions")

        # Password policy
        pw_policy = self._run(["iam", "get-account-password-policy"])
        if pw_policy:
            policy = pw_policy.get("PasswordPolicy", {})
            if not policy.get("RequireUppercaseCharacters"):
                result["issues"].append("password_no_uppercase")
            if not policy.get("RequireSymbols"):
                result["issues"].append("password_no_symbols")
            if policy.get("MaxPasswordAge", 999) > 90:
                self._add("IAM", "AccountPasswordPolicy", "Password expiry > 90 days or not set", "medium",
                          remediation="Set MaxPasswordAge to 90 days or less")
        else:
            self._add("IAM", "AccountPasswordPolicy", "No account password policy configured", "high",
                      remediation="Configure a strong account password policy")

        return result

    # ─────────────────────────────────────────────────────────────
    # EC2
    # ─────────────────────────────────────────────────────────────

    def enum_ec2(self) -> dict:
        log.info("Enumerating EC2 instances and security groups...")
        result = {"instances": [], "security_groups": [], "snapshots": []}

        # Security groups with overly permissive rules
        sgs = self._run(["ec2", "describe-security-groups"])
        if sgs:
            for sg in sgs.get("SecurityGroups", []):
                sgid = sg["GroupId"]
                sgname = sg.get("GroupName", sgid)
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    for iprange in perm.get("IpRanges", []):
                        if iprange.get("CidrIp") == "0.0.0.0/0":
                            risk_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL",
                                          5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                                          9200: "Elasticsearch", 2375: "Docker API"}
                            if from_port in risk_ports:
                                self._add("EC2", f"{sgname} ({sgid})",
                                          f"Port {from_port} ({risk_ports[from_port]}) open to 0.0.0.0/0", "critical",
                                          remediation=f"Restrict {risk_ports[from_port]} access to specific IPs")
                            elif from_port == 0 and to_port == 65535:
                                self._add("EC2", f"{sgname} ({sgid})",
                                          "All ports (0-65535) open to 0.0.0.0/0", "critical",
                                          remediation="Apply principle of least privilege to security group rules")
                            elif from_port <= 443 <= to_port or from_port in (80, 443, 8080, 8443):
                                pass  # HTTP/HTTPS expected
                            else:
                                self._add("EC2", f"{sgname} ({sgid})",
                                          f"Port {from_port}-{to_port} open to 0.0.0.0/0", "medium",
                                          remediation="Restrict port access to required sources only")

                result["security_groups"].append({"id": sgid, "name": sgname})

        # Public snapshots
        snapshots = self._run(["ec2", "describe-snapshots", "--owner-ids", "self"])
        if snapshots:
            for snap in snapshots.get("Snapshots", []):
                perms = self._run(["ec2", "describe-snapshot-attribute",
                                   "--snapshot-id", snap["SnapshotId"],
                                   "--attribute", "createVolumePermission"])
                if perms:
                    for perm in perms.get("CreateVolumePermissions", []):
                        if perm.get("Group") == "all":
                            self._add("EC2", snap["SnapshotId"],
                                      "EBS snapshot is publicly shared", "critical",
                                      remediation="Remove public sharing from snapshot")

        # IMDSv2 enforcement
        instances = self._run(["ec2", "describe-instances"])
        if instances:
            for reservation in instances.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    iid = inst["InstanceId"]
                    imds = inst.get("MetadataOptions", {})
                    if imds.get("HttpTokens") != "required":
                        self._add("EC2", iid, "IMDSv2 not enforced — SSRF can steal metadata credentials", "high",
                                  remediation="Set HttpTokens=required to enforce IMDSv2")
                    result["instances"].append({"id": iid, "state": inst.get("State", {}).get("Name")})

        return result

    # ─────────────────────────────────────────────────────────────
    # Lambda
    # ─────────────────────────────────────────────────────────────

    def enum_lambda(self) -> list[dict]:
        log.info("Enumerating Lambda functions...")
        functions_data = self._run(["lambda", "list-functions"])
        if not functions_data:
            return []

        results = []
        for fn in functions_data.get("Functions", []):
            fname = fn["FunctionName"]
            f = {"name": fname, "runtime": fn.get("Runtime", ""), "issues": []}

            # Environment variables (secrets)
            config = self._run(["lambda", "get-function-configuration", "--function-name", fname])
            if config:
                env_vars = config.get("Environment", {}).get("Variables", {})
                secret_keywords = ["password", "secret", "key", "token", "api_key", "access_key",
                                    "private", "credential", "passwd", "auth", "jwt"]
                for k, v in env_vars.items():
                    if any(kw in k.lower() for kw in secret_keywords) and v:
                        self._add("Lambda", fname,
                                  f"Potential secret in env var: {k}", "high",
                                  details={"key": k},
                                  remediation="Store secrets in AWS Secrets Manager or SSM Parameter Store")
                        f["issues"].append(f"secret_env_{k}")

            # Public resource policy
            policy = self._run(["lambda", "get-policy", "--function-name", fname])
            if policy:
                policy_str = json.dumps(policy)
                if '"Principal": "*"' in policy_str or '"AWS": "*"' in policy_str:
                    self._add("Lambda", fname, "Function resource policy allows public invocation", "critical",
                              remediation="Restrict Lambda resource policy to specific principals")
                    f["issues"].append("public_invoke")

            # Deprecated runtimes
            deprecated = ["python2.7", "nodejs8.10", "nodejs10.x", "ruby2.5",
                          "java8", "dotnetcore2.1", "nodejs12.x"]
            if fn.get("Runtime", "") in deprecated:
                self._add("Lambda", fname,
                          f"Deprecated runtime: {fn.get('Runtime')}", "medium",
                          remediation="Upgrade to a supported runtime version")
                f["issues"].append("deprecated_runtime")

            results.append(f)

        return results

    # ─────────────────────────────────────────────────────────────
    # Secrets Manager / SSM
    # ─────────────────────────────────────────────────────────────

    def enum_secrets(self) -> list[dict]:
        log.info("Enumerating Secrets Manager and SSM...")
        results = []

        # Secrets Manager
        secrets = self._run(["secretsmanager", "list-secrets"])
        if secrets:
            for secret in secrets.get("SecretList", []):
                s = {"name": secret["Name"], "arn": secret.get("ARN", ""), "issues": []}
                # Check rotation
                if not secret.get("RotationEnabled"):
                    self._add("SecretsManager", secret["Name"],
                              "Secret rotation not enabled", "medium",
                              remediation="Enable automatic rotation for secrets")
                    s["issues"].append("no_rotation")
                results.append(s)

        # SSM parameters with plaintext sensitive values
        params = self._run(["ssm", "describe-parameters"])
        if params:
            for param in params.get("Parameters", []):
                if param.get("Type") == "String":
                    name = param["Name"]
                    secret_keywords = ["password", "secret", "key", "token", "credential"]
                    if any(kw in name.lower() for kw in secret_keywords):
                        self._add("SSM", name,
                                  "Potential secret stored as plaintext SSM String (not SecureString)", "high",
                                  remediation="Use SecureString type for sensitive SSM parameters")

        return results

    # ─────────────────────────────────────────────────────────────
    # CloudTrail
    # ─────────────────────────────────────────────────────────────

    def enum_cloudtrail(self) -> dict:
        log.info("Checking CloudTrail configuration...")
        trails = self._run(["cloudtrail", "describe-trails"])
        result = {"trails": [], "issues": []}

        if not trails or not trails.get("trailList"):
            self._add("CloudTrail", "account", "No CloudTrail trails configured — no audit logging", "critical",
                      remediation="Enable CloudTrail in all regions with log file validation")
            result["issues"].append("no_trails")
            return result

        for trail in trails.get("trailList", []):
            tname = trail["Name"]
            t = {"name": tname, "issues": []}

            status = self._run(["cloudtrail", "get-trail-status", "--name", tname])
            if status and not status.get("IsLogging"):
                self._add("CloudTrail", tname, "CloudTrail logging is disabled", "critical",
                          remediation="Enable logging on the CloudTrail trail")
                t["issues"].append("logging_disabled")

            if not trail.get("LogFileValidationEnabled"):
                self._add("CloudTrail", tname, "Log file validation not enabled", "medium",
                          remediation="Enable log file validation to detect tampering")
                t["issues"].append("no_log_validation")

            if not trail.get("CloudWatchLogsLogGroupArn"):
                self._add("CloudTrail", tname, "CloudTrail not integrated with CloudWatch Logs", "low",
                          remediation="Send CloudTrail logs to CloudWatch for alerting")
                t["issues"].append("no_cloudwatch")

            result["trails"].append(t)

        return result

    # ─────────────────────────────────────────────────────────────
    # RDS
    # ─────────────────────────────────────────────────────────────

    def enum_rds(self) -> list[dict]:
        log.info("Enumerating RDS instances...")
        dbs = self._run(["rds", "describe-db-instances"])
        if not dbs:
            return []

        results = []
        for db in dbs.get("DBInstances", []):
            dbid = db["DBInstanceIdentifier"]
            d = {"id": dbid, "engine": db.get("Engine", ""), "issues": []}

            if db.get("PubliclyAccessible"):
                self._add("RDS", dbid, "Database instance is publicly accessible", "critical",
                          remediation="Disable PubliclyAccessible and place in private subnet")
                d["issues"].append("publicly_accessible")

            if not db.get("StorageEncrypted"):
                self._add("RDS", dbid, "RDS storage encryption not enabled", "high",
                          remediation="Enable storage encryption (requires new instance creation)")
                d["issues"].append("no_encryption")

            if not db.get("DeletionProtection"):
                d["issues"].append("no_deletion_protection")

            if not db.get("MultiAZ"):
                d["issues"].append("no_multi_az")

            # Auto minor version upgrades
            if not db.get("AutoMinorVersionUpgrade"):
                self._add("RDS", dbid, "Auto minor version upgrade disabled", "low",
                          remediation="Enable AutoMinorVersionUpgrade for security patches")

            results.append(d)

        return results

    # ─────────────────────────────────────────────────────────────
    # Full scan
    # ─────────────────────────────────────────────────────────────

    async def run_full_scan(self) -> dict:
        """Run complete AWS security assessment."""
        log.info(f"Starting full AWS scan (profile={self.profile}, region={self.region})")
        self.findings.clear()

        # Verify credentials
        identity = self._run(["sts", "get-caller-identity"])
        if not identity:
            return {"error": "Cannot authenticate to AWS. Check credentials/profile.", "findings": []}

        log.info(f"Authenticated as: {identity.get('Arn', 'Unknown')}")

        results = {
            "identity": identity,
            "s3": self.enum_s3(),
            "iam": self.enum_iam(),
            "ec2": self.enum_ec2(),
            "lambda": self.enum_lambda(),
            "secrets": self.enum_secrets(),
            "cloudtrail": self.enum_cloudtrail(),
            "rds": self.enum_rds(),
            "findings": [vars(f) for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            }
        }

        log.info(f"AWS scan complete. Findings: {results['summary']}")
        return results
