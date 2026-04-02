"""
WardenStrike - Active Directory Engine
Internal pentesting: LDAP enumeration, SMB scanning, Kerberos attacks,
BloodHound data collection, and common AD misconfigurations.
"""

import asyncio
import json
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("ad_engine")


@dataclass
class ADFinding:
    category: str
    asset: str
    issue: str
    severity: str
    details: dict = field(default_factory=dict)
    remediation: str = ""
    attack_path: str = ""


class ADEngine:
    """
    Active Directory / Internal Network assessment engine.
    Orchestrates: LDAP enum, SMB, Kerberoasting, ASREPRoasting,
    password spraying prep, BloodHound, domain privesc paths.
    """

    def __init__(self, config: Config, db=None, engagement_id: int = None):
        self.config = config
        self.db = db
        self.engagement_id = engagement_id
        self.findings: list[ADFinding] = []

    def _run(self, cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return "", str(e), -1

    def _add(self, category, asset, issue, severity, details=None, remediation="", attack_path=""):
        f = ADFinding(category, asset, issue, severity, details or {}, remediation, attack_path)
        self.findings.append(f)
        log.info(f"[{severity.upper()}] AD/{category}: {issue} — {asset}")

    # ─── Network Discovery ────────────────────────────────────────

    async def discover_domain_controllers(self, domain: str) -> list[str]:
        """Discover domain controllers via DNS SRV records."""
        log.info(f"Discovering domain controllers for {domain}...")
        dcs = []

        try:
            out, _, rc = self._run(["nslookup", "-type=SRV", f"_ldap._tcp.dc._msdcs.{domain}"])
            if rc == 0:
                hosts = re.findall(r"svr hostname\s*=\s*(\S+)", out, re.I)
                for host in hosts:
                    host = host.rstrip(".")
                    try:
                        ip = socket.gethostbyname(host)
                        dcs.append(ip)
                        log.info(f"DC found: {host} ({ip})")
                    except Exception:
                        dcs.append(host)
        except Exception as e:
            log.debug(f"DC discovery error: {e}")

        return dcs

    # ─── LDAP Enumeration ─────────────────────────────────────────

    def ldap_enum(self, dc_ip: str, domain: str, username: str = "", password: str = "",
                  anonymous: bool = True) -> dict:
        """
        Enumerate Active Directory via LDAP.
        Uses ldapsearch if available, otherwise attempts anonymous bind checks.
        """
        log.info(f"LDAP enumeration: {dc_ip} ({domain})")
        result = {"users": [], "groups": [], "computers": [], "gpos": [], "issues": []}

        # Build auth args
        if anonymous:
            auth_args = ["-x", "-H", f"ldap://{dc_ip}"]
            self._add("LDAP", dc_ip, "Anonymous LDAP bind may be enabled — testing...", "medium",
                      remediation="Disable anonymous LDAP binds")
        else:
            auth_args = ["-x", "-H", f"ldap://{dc_ip}", "-D",
                         f"{username}@{domain}", "-w", password]

        base_dn = "DC=" + ",DC=".join(domain.split("."))

        # Enumerate users
        user_filter = "(&(objectCategory=person)(objectClass=user))"
        user_attrs = "sAMAccountName,userPrincipalName,description,memberOf,adminCount,userAccountControl,pwdLastSet"
        out, err, rc = self._run(["ldapsearch"] + auth_args +
                                 ["-b", base_dn, user_filter] +
                                 user_attrs.split(","), timeout=30)

        if rc == 0 and out:
            users = re.findall(r"sAMAccountName:\s*(.+)", out)
            descriptions = re.findall(r"description:\s*(.+)", out)
            admin_counts = re.findall(r"adminCount:\s*(\d+)", out)

            for user in users:
                user = user.strip()
                result["users"].append(user)

            # Descriptions with passwords (common AD misconfiguration)
            for desc in descriptions:
                for kw in ["password", "passwd", "pwd", "temp", "welcome", "pass"]:
                    if kw in desc.lower():
                        self._add("LDAP", dc_ip,
                                  f"User description contains potential credential: '{desc.strip()}'",
                                  "critical",
                                  details={"description": desc.strip()},
                                  remediation="Remove credentials from LDAP description fields",
                                  attack_path="LDAP anon/auth → read description → login")

            log.info(f"LDAP: Found {len(users)} users")
        elif anonymous and rc != 0:
            result["issues"].append("anonymous_bind_failed")
            log.info("Anonymous LDAP bind not allowed")

        # Enumerate computers
        comp_filter = "(objectClass=computer)"
        out, _, rc = self._run(["ldapsearch"] + auth_args +
                                ["-b", base_dn, comp_filter, "dNSHostName", "operatingSystem"],
                               timeout=30)
        if rc == 0 and out:
            computers = re.findall(r"dNSHostName:\s*(.+)", out)
            os_list = re.findall(r"operatingSystem:\s*(.+)", out)
            result["computers"] = [c.strip() for c in computers]

            # Detect EOL OS
            for os_ver in os_list:
                eol_patterns = ["Windows XP", "Windows 2003", "Windows 2008", "Windows 7",
                                 "Windows Vista", "Windows Server 2008"]
                for eol in eol_patterns:
                    if eol.lower() in os_ver.lower():
                        self._add("LDAP", dc_ip, f"EOL OS detected in domain: {os_ver.strip()}", "high",
                                  details={"os": os_ver.strip()},
                                  remediation="Upgrade or isolate end-of-life systems",
                                  attack_path="EOL system → known unpatched CVE → lateral movement")

        return result

    # ─── Kerberoasting ────────────────────────────────────────────

    def check_kerberoastable(self, dc_ip: str, domain: str,
                              username: str, password: str) -> list[dict]:
        """
        Find Kerberoastable accounts (SPNs set on user accounts).
        Uses impacket's GetUserSPNs.py if available.
        """
        log.info("Checking for Kerberoastable accounts...")
        results = []

        out, err, rc = self._run([
            "GetUserSPNs.py",
            f"{domain}/{username}:{password}",
            "-dc-ip", dc_ip,
            "-outputfile", "/tmp/ws_kerberoast_hashes.txt",
        ], timeout=60)

        if rc == 0 and out:
            spns = re.findall(r"(\S+)\s+\d+\s+\d+\s+\d+\s+(\S+)", out)
            for spn_user, spn in spns:
                self._add("Kerberos", spn_user,
                          f"Kerberoastable account with SPN: {spn}",
                          "high",
                          details={"spn": spn, "user": spn_user},
                          remediation="Use managed service accounts (gMSA) instead of user accounts for services",
                          attack_path="SPN enum → request TGS → offline crack → service account creds → lateral movement")
                results.append({"user": spn_user, "spn": spn})

            if results:
                log.warning(f"Found {len(results)} Kerberoastable accounts!")
                log.info("Hashes saved to /tmp/ws_kerberoast_hashes.txt")

        return results

    # ─── ASREPRoasting ────────────────────────────────────────────

    def check_asrep_roastable(self, dc_ip: str, domain: str,
                               users_file: str = None) -> list[dict]:
        """
        Find accounts with Kerberos pre-auth disabled (ASREPRoastable).
        Uses impacket's GetNPUsers.py.
        """
        log.info("Checking for ASREPRoastable accounts...")
        results = []

        cmd = [
            "GetNPUsers.py",
            f"{domain}/",
            "-dc-ip", dc_ip,
            "-no-pass",
            "-outputfile", "/tmp/ws_asrep_hashes.txt",
        ]
        if users_file:
            cmd += ["-usersfile", users_file]

        out, err, rc = self._run(cmd, timeout=60)

        if rc == 0:
            users = re.findall(r"\$krb5asrep\$[^\s]+\$([^:]+):", out)
            for user in users:
                self._add("Kerberos", user,
                          "Kerberos pre-authentication disabled — ASREPRoastable",
                          "high",
                          details={"user": user},
                          remediation="Enable Kerberos pre-authentication for all accounts",
                          attack_path="No pre-auth → request AS-REP hash → offline crack → account compromise")
                results.append({"user": user})

        return results

    # ─── SMB Enumeration ──────────────────────────────────────────

    def smb_enum(self, target_ip: str, domain: str = "",
                 username: str = "", password: str = "") -> dict:
        """
        SMB enumeration: shares, null sessions, signing, relay vulnerability.
        """
        log.info(f"SMB enumeration: {target_ip}")
        result = {"shares": [], "issues": [], "signing": None}

        # SMB signing check
        out, _, rc = self._run(["nmap", "--script", "smb2-security-mode", "-p", "445",
                                 target_ip, "-oN", "-"], timeout=30)
        if rc == 0:
            if "Message signing enabled but not required" in out:
                self._add("SMB", target_ip,
                          "SMB signing not required — vulnerable to relay attacks (NTLM relay)",
                          "high",
                          remediation="Enable SMB signing enforcement via GPO",
                          attack_path="Capture NTLM challenge → relay to other hosts → RCE/auth bypass")
                result["signing"] = "not_required"
                result["issues"].append("smb_signing_not_required")
            elif "Message signing enabled and required" in out:
                result["signing"] = "required"

        # Null session / anonymous share enum
        auth_flag = f"{domain}/{username}:{password}" if username else "%"
        out, _, rc = self._run(["smbclient", "-L", f"//{target_ip}/", "-N"], timeout=15)
        if rc == 0 and "Sharename" in out:
            self._add("SMB", target_ip, "Null session allowed — anonymous share enumeration possible", "medium",
                      remediation="Disable null session access",
                      attack_path="Null session → enumerate shares → read sensitive data")
            result["issues"].append("null_session")

            shares = re.findall(r"(\S+)\s+Disk\s+(.+)", out)
            for share_name, comment in shares:
                result["shares"].append({"name": share_name, "comment": comment.strip()})
                # Check for sensitive share names
                sensitive = ["backup", "admin$", "sysvol", "netlogon", "finance", "hr", "payroll",
                             "password", "secret", "confidential", "private"]
                if any(s in share_name.lower() for s in sensitive):
                    self._add("SMB", f"{target_ip}\\{share_name}",
                              f"Potentially sensitive share accessible: {share_name}",
                              "high",
                              remediation="Review share permissions and remove unnecessary access")

        return result

    # ─── Password Spray Prep ──────────────────────────────────────

    def password_policy_check(self, dc_ip: str, domain: str) -> dict:
        """Check domain password policy to calculate safe spray window."""
        log.info("Checking domain password policy...")

        out, _, rc = self._run([
            "crackmapexec", "smb", dc_ip, "-u", "", "-p", "",
            "--pass-pol"
        ], timeout=30)

        policy = {}
        if rc == 0 and out:
            lockout = re.search(r"Account Lockout Threshold:\s*(\d+)", out)
            window = re.search(r"Account Lockout Duration:\s*(\d+)", out)
            min_pass = re.search(r"Minimum Password Length:\s*(\d+)", out)
            complexity = re.search(r"Password Complexity:\s*(\w+)", out)

            policy = {
                "lockout_threshold": int(lockout.group(1)) if lockout else None,
                "lockout_window_min": int(window.group(1)) if window else None,
                "min_length": int(min_pass.group(1)) if min_pass else None,
                "complexity": complexity.group(1) if complexity else None,
            }

            threshold = policy.get("lockout_threshold")
            if threshold and threshold <= 3:
                self._add("PasswordPolicy", domain,
                          f"Low lockout threshold ({threshold} attempts) — very limited spray window",
                          "info",
                          details=policy,
                          remediation="This is correct behavior — document in report as mitigating control")
            elif threshold is None or threshold == 0:
                self._add("PasswordPolicy", domain,
                          "No account lockout configured — unlimited password spray possible",
                          "critical",
                          details=policy,
                          remediation="Configure account lockout policy (threshold ≤ 10, duration ≥ 30 min)",
                          attack_path="No lockout → unlimited spray → account compromise via weak passwords")
            elif threshold >= 10:
                self._add("PasswordPolicy", domain,
                          f"High lockout threshold ({threshold} attempts) — spray-friendly policy",
                          "high",
                          details=policy,
                          remediation="Reduce lockout threshold to ≤ 5 attempts")

            if policy.get("min_length", 99) < 12:
                self._add("PasswordPolicy", domain,
                          f"Minimum password length {policy.get('min_length')} < 12",
                          "medium",
                          remediation="Set minimum password length to 14+ characters")

        return policy

    # ─── BloodHound Collection ────────────────────────────────────

    def collect_bloodhound(self, dc_ip: str, domain: str,
                            username: str, password: str) -> bool:
        """
        Run BloodHound data collection via SharpHound.py / bloodhound-python.
        """
        log.info("Running BloodHound collection...")

        out, err, rc = self._run([
            "bloodhound-python",
            "-u", username,
            "-p", password,
            "-ns", dc_ip,
            "-d", domain,
            "-c", "All",
            "--zip",
            "--outputdir", "/tmp/wardenstrike_bloodhound",
        ], timeout=300)

        if rc == 0:
            log.info("BloodHound data collected! Import ZIP into BloodHound GUI.")
            self._add("BloodHound", domain,
                      "BloodHound data collected — analyze attack paths in BloodHound GUI",
                      "info",
                      details={"output": "/tmp/wardenstrike_bloodhound"},
                      attack_path="See BloodHound GUI for shortest path to Domain Admin")
            return True
        else:
            log.warning(f"BloodHound collection failed: {err[:200]}")
            return False

    # ─── Common AD Misconfigurations ──────────────────────────────

    def check_ad_misconfigs(self, dc_ip: str, domain: str,
                             username: str, password: str) -> list[dict]:
        """Check for common AD misconfigurations using CrackMapExec."""
        log.info("Checking common AD misconfigurations...")
        results = []

        checks = [
            (["crackmapexec", "smb", dc_ip, "-u", username, "-p", password, "--shares"],
             "share_enum", "SMB Shares"),
            (["crackmapexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "zerologon"],
             "zerologon", "Zerologon (CVE-2020-1472)"),
            (["crackmapexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "petitpotam"],
             "petitpotam", "PetitPotam (NTLM coerce)"),
            (["crackmapexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "nopac"],
             "nopac", "NoPac (CVE-2021-42278/42287)"),
            (["crackmapexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "printnightmare"],
             "printnightmare", "PrintNightmare (CVE-2021-1675)"),
        ]

        for cmd, check_id, check_name in checks:
            out, _, rc = self._run(cmd, timeout=30)
            if rc == 0 and ("VULNERABLE" in out or "pwn3d" in out.lower()):
                self._add("MisconfigCheck", dc_ip,
                          f"{check_name} — VULNERABLE", "critical",
                          details={"check": check_id, "output": out[:500]},
                          remediation=f"Apply Microsoft patch for {check_name}",
                          attack_path=f"{check_name} → Domain Admin / SYSTEM")
                results.append({"check": check_name, "status": "vulnerable"})
            else:
                results.append({"check": check_name, "status": "not_detected"})

        return results

    # ─── LLMNR/NBT-NS Poisoning prep ─────────────────────────────

    def check_llmnr_status(self, network_range: str) -> dict:
        """Check if LLMNR/NBT-NS is enabled (allows Responder attacks)."""
        log.info("Checking LLMNR/NBT-NS status...")

        # Use nmap to detect
        out, _, rc = self._run([
            "nmap", "-sU", "-p", "5355,137", "--script", "llmnr-resolve",
            network_range, "-oN", "-"
        ], timeout=60)

        if rc == 0 and "open" in out:
            self._add("Network", network_range,
                      "LLMNR/NBT-NS responding — Responder NTLM capture possible",
                      "high",
                      remediation="Disable LLMNR and NBT-NS via GPO",
                      attack_path="Responder → NTLM capture → crack offline or relay → lateral movement")
            return {"llmnr_active": True}

        return {"llmnr_active": False}

    # ─── IPv6 DNS Takeover ────────────────────────────────────────

    def check_ipv6_dns(self, dc_ip: str) -> dict:
        """Check for IPv6 DNS takeover opportunity (mitm6)."""
        log.info("Checking IPv6 DNS configuration...")

        # Check if IPv6 is active in the domain
        out, _, rc = self._run(["ping6", "-c", "1", dc_ip], timeout=5)
        result = {"ipv6_reachable": rc == 0}

        # Check if DHCPv6 is running (nmap)
        out2, _, rc2 = self._run(["nmap", "-6", "--script", "dhcpv6-*",
                                    dc_ip, "-oN", "-"], timeout=15)
        if rc2 == 0 and "dhcpv6" in out2.lower():
            self._add("Network", dc_ip,
                      "DHCPv6 active — mitm6 NTLM relay/account creation possible",
                      "high",
                      remediation="Block DHCPv6 via Windows Firewall GPO or disable IPv6 if not used",
                      attack_path="mitm6 → DHCPv6 spoof → NTLM relay to LDAPS/HTTPS → account creation → DA")
            result["dhcpv6_active"] = True

        return result

    # ─── Full Scan ────────────────────────────────────────────────

    async def run_full_scan(self, domain: str, dc_ip: str = None,
                             username: str = "", password: str = "",
                             network_range: str = None) -> dict:
        """Run complete Active Directory / internal assessment."""
        log.info(f"Starting AD assessment for domain: {domain}")
        self.findings.clear()

        # Auto-discover DCs if not provided
        if not dc_ip:
            dcs = await self.discover_domain_controllers(domain)
            dc_ip = dcs[0] if dcs else None

        if not dc_ip:
            return {"error": f"Cannot resolve domain controllers for {domain}", "findings": []}

        results = {
            "domain": domain,
            "dc_ip": dc_ip,
            "ldap": self.ldap_enum(dc_ip, domain, username, password, anonymous=not username),
            "smb": self.smb_enum(dc_ip, domain, username, password),
            "password_policy": self.password_policy_check(dc_ip, domain),
        }

        if username and password:
            results["kerberoastable"] = self.check_kerberoastable(dc_ip, domain, username, password)
            results["asrep_roastable"] = self.check_asrep_roastable(dc_ip, domain)
            results["ad_misconfigs"] = self.check_ad_misconfigs(dc_ip, domain, username, password)
            results["bloodhound_collected"] = self.collect_bloodhound(dc_ip, domain, username, password)

        if network_range:
            results["llmnr"] = self.check_llmnr_status(network_range)
            results["ipv6"] = self.check_ipv6_dns(dc_ip)

        # Save to DB
        if self.db and self.engagement_id:
            for f in self.findings:
                self.db.add_finding(
                    engagement_id=self.engagement_id,
                    title=f"AD | {f.category} | {f.issue}",
                    severity=f.severity,
                    vuln_type=f"internal_ad_{f.category.lower()}",
                    url=f.asset,
                    description=f.issue,
                    evidence=str(f.details),
                    remediation=f.remediation,
                    tool_source="wardenstrike-ad",
                    raw_data=vars(f),
                )

        results["findings"] = [vars(f) for f in self.findings]
        results["summary"] = {
            "total": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
            "high": sum(1 for f in self.findings if f.severity == "high"),
            "medium": sum(1 for f in self.findings if f.severity == "medium"),
            "attack_paths": [f.attack_path for f in self.findings if f.attack_path],
        }

        return results
