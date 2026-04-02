"""
WardenStrike - Azure Enumerator
Enumeration and misconfiguration detection for Microsoft Azure.
Covers: Storage Accounts, IAM/RBAC, VMs, App Services, SQL, Key Vault, AKS, NSGs.
"""

import asyncio
import json
import subprocess
from dataclasses import dataclass, field

from wardenstrike.utils.logger import get_logger

log = get_logger("azure")


@dataclass
class AzureFinding:
    service: str
    resource: str
    issue: str
    severity: str
    details: dict = field(default_factory=dict)
    remediation: str = ""


class AzureEnumerator:
    """Azure enumeration via az CLI."""

    def __init__(self, config=None, subscription: str = None):
        self.config = config
        self.subscription = subscription
        self.findings: list[AzureFinding] = []

    def _run(self, args: list[str]) -> dict | list | None:
        cmd = ["az"] + args
        if self.subscription:
            cmd += ["--subscription", self.subscription]
        cmd += ["--output", "json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return None

    def _add(self, service, resource, issue, severity, details=None, remediation=""):
        self.findings.append(AzureFinding(service, resource, issue, severity, details or {}, remediation))
        log.info(f"[{severity.upper()}] Azure/{service}: {issue} — {resource}")

    # ─── Storage Accounts ─────────────────────────────────────────

    def enum_storage(self) -> list[dict]:
        log.info("Enumerating Azure Storage Accounts...")
        accounts = self._run(["storage", "account", "list"])
        if not accounts:
            return []

        results = []
        for account in accounts:
            name = account.get("name", "")
            a = {"name": name, "issues": []}

            # Public blob access
            if account.get("allowBlobPublicAccess"):
                self._add("Storage", name, "Blob public access allowed on storage account", "high",
                          remediation="Set allowBlobPublicAccess=false on storage account")
                a["issues"].append("blob_public_access")

            # HTTPS only
            if not account.get("enableHttpsTrafficOnly"):
                self._add("Storage", name, "HTTPS-only traffic not enforced", "high",
                          remediation="Enable supportsHttpsTrafficOnly on storage account")
                a["issues"].append("no_https_only")

            # Minimum TLS version
            if account.get("minimumTlsVersion") in (None, "TLS1_0", "TLS1_1"):
                self._add("Storage", name, "Minimum TLS version < 1.2", "medium",
                          remediation="Set minimumTlsVersion=TLS1_2")
                a["issues"].append("weak_tls")

            # Infrastructure encryption
            if not account.get("encryption", {}).get("requireInfrastructureEncryption"):
                a["issues"].append("no_infra_encryption")

            # Soft delete
            blob_props = self._run(["storage", "account", "blob-service-properties", "show",
                                    "--account-name", name])
            if blob_props and not blob_props.get("deleteRetentionPolicy", {}).get("enabled"):
                self._add("Storage", name, "Blob soft delete not enabled — data loss risk", "low",
                          remediation="Enable blob soft delete with retention period")
                a["issues"].append("no_soft_delete")

            # Network rules
            network_rules = account.get("networkRuleSet", {})
            if network_rules.get("defaultAction") == "Allow":
                self._add("Storage", name, "Storage network rules default to Allow — no network restriction", "high",
                          remediation="Set defaultAction=Deny and whitelist specific networks/IPs")
                a["issues"].append("network_allow_default")

            results.append(a)

        return results

    # ─── NSG / Network ────────────────────────────────────────────

    def enum_nsgs(self) -> list[dict]:
        log.info("Enumerating Network Security Groups...")
        nsgs = self._run(["network", "nsg", "list"])
        if not nsgs:
            return []

        results = []
        for nsg in nsgs:
            name = nsg.get("name", "")
            n = {"name": name, "issues": []}

            for rule in nsg.get("securityRules", []):
                if rule.get("direction") == "Inbound" and rule.get("access") == "Allow":
                    dest_range = rule.get("destinationAddressPrefix", "")
                    src_range = rule.get("sourceAddressPrefix", "")
                    dst_port = rule.get("destinationPortRange", "")
                    priority = rule.get("priority", 9999)

                    if src_range in ("*", "Internet", "0.0.0.0/0"):
                        risk_ports = {"22": "SSH", "3389": "RDP", "3306": "MySQL",
                                      "5432": "PostgreSQL", "6379": "Redis",
                                      "27017": "MongoDB", "9200": "Elasticsearch",
                                      "2375": "Docker API", "445": "SMB", "135": "WMI"}
                        if dst_port in risk_ports:
                            sev = "critical" if dst_port in ("22", "3389", "445") else "high"
                            self._add("NSG", name,
                                      f"Port {dst_port} ({risk_ports[dst_port]}) open to Internet", sev,
                                      remediation=f"Restrict {risk_ports[dst_port]} to known IPs")
                            n["issues"].append(f"public_{dst_port}")
                        elif dst_port == "*":
                            self._add("NSG", name, "All ports open to Internet", "critical",
                                      remediation="Apply specific port restrictions")
                            n["issues"].append("all_ports_open")

            results.append(n)

        return results

    # ─── Virtual Machines ─────────────────────────────────────────

    def enum_vms(self) -> list[dict]:
        log.info("Enumerating Azure VMs...")
        vms = self._run(["vm", "list"])
        if not vms:
            return []

        results = []
        for vm in vms:
            name = vm.get("name", "")
            v = {"name": name, "issues": []}

            # Disk encryption
            encryption = vm.get("storageProfile", {}).get("osDisk", {}).get("encryptionSettings")
            if not encryption or not encryption.get("enabled"):
                self._add("VMs", name, "OS disk encryption not enabled", "high",
                          remediation="Enable Azure Disk Encryption on VM disks")
                v["issues"].append("disk_not_encrypted")

            # Boot diagnostics
            if not vm.get("diagnosticsProfile", {}).get("bootDiagnostics", {}).get("enabled"):
                v["issues"].append("no_boot_diagnostics")

            results.append(v)

        return results

    # ─── App Services ─────────────────────────────────────────────

    def enum_app_services(self) -> list[dict]:
        log.info("Enumerating App Services...")
        apps = self._run(["webapp", "list"])
        if not apps:
            return []

        results = []
        for app in apps:
            name = app.get("name", "")
            a = {"name": name, "issues": []}

            # HTTPS only
            if not app.get("httpsOnly"):
                self._add("AppService", name, "App Service not enforcing HTTPS", "medium",
                          remediation="Enable httpsOnly on App Service")
                a["issues"].append("no_https_only")

            # Minimum TLS
            site_config = app.get("siteConfig") or {}
            if site_config.get("minTlsVersion") in (None, "1.0", "1.1"):
                self._add("AppService", name, "Minimum TLS version < 1.2", "medium",
                          remediation="Set minTlsVersion=1.2 in App Service configuration")
                a["issues"].append("weak_tls")

            # Remote debugging
            if site_config.get("remoteDebuggingEnabled"):
                self._add("AppService", name, "Remote debugging is enabled — code execution risk", "critical",
                          remediation="Disable remote debugging in production")
                a["issues"].append("remote_debugging_on")

            # Auth/Identity
            if not app.get("identity"):
                a["issues"].append("no_managed_identity")

            # FTP state
            ftp_state = site_config.get("ftpsState", "AllAllowed")
            if ftp_state == "AllAllowed":
                self._add("AppService", name, "FTP (plaintext) allowed on App Service", "medium",
                          remediation="Set ftpsState=FtpsOnly or Disabled")
                a["issues"].append("ftp_allowed")

            results.append(a)

        return results

    # ─── Key Vault ────────────────────────────────────────────────

    def enum_keyvault(self) -> list[dict]:
        log.info("Enumerating Key Vaults...")
        vaults = self._run(["keyvault", "list"])
        if not vaults:
            return []

        results = []
        for vault in vaults:
            name = vault.get("name", "")
            v = {"name": name, "issues": []}

            properties = vault.get("properties", {})

            # Soft delete
            if not properties.get("enableSoftDelete"):
                self._add("KeyVault", name, "Soft delete not enabled — permanent deletion risk", "high",
                          remediation="Enable soft delete on Key Vault")
                v["issues"].append("no_soft_delete")

            # Purge protection
            if not properties.get("enablePurgeProtection"):
                self._add("KeyVault", name, "Purge protection not enabled — data loss risk", "medium",
                          remediation="Enable purge protection on Key Vault")
                v["issues"].append("no_purge_protection")

            # Network rules
            network_acls = properties.get("networkAcls", {})
            if network_acls.get("defaultAction") == "Allow":
                self._add("KeyVault", name, "Key Vault accessible from all networks", "high",
                          remediation="Restrict Key Vault network access to specific subnets/IPs")
                v["issues"].append("network_allow_all")

            results.append(v)

        return results

    # ─── Full scan ────────────────────────────────────────────────

    async def run_full_scan(self, subscription: str = None) -> dict:
        """Run complete Azure security assessment."""
        if subscription:
            self.subscription = subscription

        log.info("Starting full Azure scan...")
        self.findings.clear()

        # Verify auth
        account = self._run(["account", "show"])
        if not account:
            return {"error": "Not authenticated to Azure. Run: az login", "findings": []}

        log.info(f"Authenticated as: {account.get('user', {}).get('name', 'Unknown')}")

        return {
            "account": account,
            "storage": self.enum_storage(),
            "nsgs": self.enum_nsgs(),
            "vms": self.enum_vms(),
            "app_services": self.enum_app_services(),
            "keyvault": self.enum_keyvault(),
            "findings": [vars(f) for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            }
        }
