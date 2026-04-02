"""
WardenStrike - Continuous Monitor
Tracks asset changes, new subdomains, content changes, new endpoints,
certificate changes, and open ports. Fires alerts on new attack surface.
"""

import asyncio
import hashlib
import json
import sqlite3
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from wardenstrike.config import Config
from wardenstrike.utils.logger import get_logger

log = get_logger("monitor")


@dataclass
class MonitorAlert:
    alert_type: str
    target: str
    change: str
    severity: str  # high/medium/low
    old_value: str = ""
    new_value: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ContinuousMonitor:
    """
    Continuous asset monitoring for bug bounty / ongoing engagements.
    Detects: new subdomains, new ports, content changes, new JS endpoints,
    certificate changes, new parameters, technology stack changes.
    """

    def __init__(self, config: Config, db_path: str = None):
        self.config = config
        self.alerts: list[MonitorAlert] = []

        # Monitor-specific SQLite for state tracking
        db_dir = Path(db_path or config.get("monitor", "db_path", default="~/.wardenstrike/monitor.db"))
        db_dir = Path(str(db_dir).replace("~", str(Path.home())))
        db_dir.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_dir))
        self._init_db()

    def _init_db(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            snapshot_type TEXT NOT NULL,
            value TEXT NOT NULL,
            hash TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            target TEXT,
            change TEXT,
            severity TEXT,
            old_value TEXT,
            new_value TEXT,
            timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_target ON snapshots(target);
        CREATE INDEX IF NOT EXISTS idx_snapshots_type ON snapshots(snapshot_type, target);
        """)
        self.conn.commit()

    def _add_alert(self, alert_type, target, change, severity, old_value="", new_value=""):
        alert = MonitorAlert(alert_type, target, change, severity, old_value, new_value)
        self.alerts.append(alert)
        self.conn.execute(
            "INSERT INTO alerts (alert_type,target,change,severity,old_value,new_value,timestamp) VALUES (?,?,?,?,?,?,?)",
            (alert_type, target, change, severity, old_value, new_value, alert.timestamp)
        )
        self.conn.commit()
        log.warning(f"[MONITOR/{severity.upper()}] {alert_type}: {change} @ {target}")

    def _get_snapshot(self, target: str, snap_type: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT value FROM snapshots WHERE target=? AND snapshot_type=?",
            (target, snap_type)
        ).fetchall()
        return [r[0] for r in rows]

    def _update_snapshot(self, target: str, snap_type: str, values: list[str]):
        now = datetime.utcnow().isoformat()
        existing = set(self._get_snapshot(target, snap_type))
        new = set(values)

        # Add new entries
        for v in new - existing:
            h = hashlib.md5(v.encode()).hexdigest()
            self.conn.execute(
                "INSERT INTO snapshots (target,snapshot_type,value,hash,first_seen,last_seen) VALUES (?,?,?,?,?,?)",
                (target, snap_type, v, h, now, now)
            )

        # Update last_seen for existing
        for v in new & existing:
            self.conn.execute(
                "UPDATE snapshots SET last_seen=? WHERE target=? AND snapshot_type=? AND value=?",
                (now, target, snap_type, v)
            )

        self.conn.commit()
        return new - existing  # Return new items

    # ─── Subdomain Monitoring ─────────────────────────────────────

    async def monitor_subdomains(self, domain: str) -> list[str]:
        """Check for new subdomains via CT logs and DNS."""
        import subprocess
        current_subs = set()

        # crt.sh
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike-Monitor/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if domain in name:
                            current_subs.add(name)
        except Exception as e:
            log.debug(f"CT log error: {e}")

        # subfinder if available
        try:
            out = subprocess.run(["subfinder", "-d", domain, "-silent"],
                                 capture_output=True, text=True, timeout=60)
            if out.returncode == 0:
                for line in out.stdout.strip().split("\n"):
                    if line.strip():
                        current_subs.add(line.strip().lower())
        except FileNotFoundError:
            pass

        new_subs = self._update_snapshot(domain, "subdomain", list(current_subs))
        for sub in new_subs:
            self._add_alert("new_subdomain", domain, f"New subdomain discovered: {sub}",
                            "high", new_value=sub)

        return list(new_subs)

    # ─── Content Change Monitoring ────────────────────────────────

    async def monitor_content(self, url: str) -> dict:
        """Monitor URL content for changes (hash-based + semantic)."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike-Monitor/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode(errors="replace")
                status = resp.status
        except urllib.error.HTTPError as e:
            content = ""
            status = e.code
        except Exception:
            return {}

        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        old_hash = self._get_snapshot(url, "content_hash")
        if old_hash and old_hash[0] != content_hash:
            self._add_alert("content_change", url,
                            "Page content changed",
                            "medium",
                            old_value=old_hash[0],
                            new_value=content_hash)

        self._update_snapshot(url, "content_hash", [content_hash])

        # Check for new interesting patterns
        patterns = {
            "api_endpoint": r'["\'](/api/v\d+/[^"\']+)["\']',
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "jwt_token": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
            "private_ip": r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
            "internal_domain": r'["\'](https?://(?:internal|intranet|staging|dev|uat|localhost)[^"\']+)["\']',
        }

        import re
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                new_matches = self._update_snapshot(url, f"pattern_{pattern_name}", matches)
                for match in new_matches:
                    sev = "high" if pattern_name in ("aws_key", "jwt_token") else "medium"
                    self._add_alert(f"new_{pattern_name}", url,
                                    f"New {pattern_name} found: {match[:80]}",
                                    sev, new_value=match)

        return {"url": url, "status": status, "hash": content_hash}

    # ─── Port / Service Monitoring ────────────────────────────────

    async def monitor_ports(self, host: str, ports: list[int] = None) -> list[int]:
        """Monitor for newly opened ports."""
        import subprocess

        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389,
                     5432, 6379, 8080, 8443, 8888, 9200, 27017]

        port_str = ",".join(str(p) for p in ports)
        open_ports = []

        try:
            out = subprocess.run(
                ["nmap", "-sS", "-p", port_str, "--open", "-oG", "-", host],
                capture_output=True, text=True, timeout=60
            )
            import re
            for line in out.stdout.split("\n"):
                matches = re.findall(r"(\d+)/open", line)
                open_ports.extend(int(m) for m in matches)
        except FileNotFoundError:
            # Fallback: socket connect
            for port in ports:
                try:
                    import socket
                    with socket.create_connection((host, port), timeout=2):
                        open_ports.append(port)
                except Exception:
                    pass

        new_ports = self._update_snapshot(host, "open_port", [str(p) for p in open_ports])

        risky_ports = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
                       3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                       27017: "MongoDB", 9200: "Elasticsearch"}

        for port_str_val in new_ports:
            port = int(port_str_val)
            svc = risky_ports.get(port, "Unknown")
            sev = "critical" if port in risky_ports else "medium"
            self._add_alert("new_open_port", host,
                            f"New port opened: {port} ({svc})",
                            sev, new_value=str(port))

        return [int(p) for p in new_ports]

    # ─── Certificate Monitoring ───────────────────────────────────

    async def monitor_certificate(self, domain: str) -> dict:
        """Monitor TLS certificate for changes (expiry, SAN, issuer)."""
        import ssl
        import socket
        from datetime import datetime

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
        except Exception as e:
            return {"error": str(e)}

        # Parse cert info
        san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter", "")

        cert_fingerprint = hashlib.md5(json.dumps(cert, default=str).encode()).hexdigest()

        old_fp = self._get_snapshot(domain, "cert_fingerprint")
        if old_fp and old_fp[0] != cert_fingerprint:
            self._add_alert("certificate_changed", domain,
                            "TLS certificate changed — new cert installed",
                            "medium", old_value=old_fp[0], new_value=cert_fingerprint)

        # New SANs
        new_sans = self._update_snapshot(domain, "cert_san", san)
        for s in new_sans:
            self._add_alert("new_cert_san", domain,
                            f"New SAN in certificate: {s}",
                            "low", new_value=s)

        self._update_snapshot(domain, "cert_fingerprint", [cert_fingerprint])

        return {
            "domain": domain,
            "san": san,
            "issuer": issuer.get("organizationName", ""),
            "not_after": not_after,
            "fingerprint": cert_fingerprint,
        }

    # ─── Technology Stack Changes ─────────────────────────────────

    async def monitor_technologies(self, url: str) -> list[str]:
        """Detect technology stack changes via response headers."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WardenStrike-Monitor/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = dict(resp.headers)
        except Exception:
            return []

        tech_indicators = []
        header_tech_map = {
            "X-Powered-By": "powered_by",
            "Server": "server",
            "X-Generator": "generator",
            "X-AspNet-Version": "aspnet",
            "X-AspNetMvc-Version": "aspnetmvc",
        }

        for header, tech_type in header_tech_map.items():
            value = headers.get(header, "")
            if value:
                tech_indicators.append(f"{tech_type}:{value}")

        new_techs = self._update_snapshot(url, "technology", tech_indicators)
        for tech in new_techs:
            self._add_alert("new_technology_detected", url,
                            f"New technology header: {tech}",
                            "low", new_value=tech)

        return list(new_techs)

    # ─── Full monitor run ─────────────────────────────────────────

    async def run(self, targets: list[str], deep: bool = False) -> dict:
        """
        Run continuous monitoring check on all targets.
        Call this on a schedule (e.g. every 4-24 hours).
        """
        log.info(f"Monitoring run started for {len(targets)} targets")
        self.alerts.clear()
        results = {"targets": {}, "new_alerts": []}

        for target in targets:
            log.info(f"Monitoring: {target}")
            t_results = {}

            # Determine if target is a domain or URL
            is_url = target.startswith("http")
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]

            t_results["subdomains"] = await self.monitor_subdomains(domain)
            t_results["certificate"] = await self.monitor_certificate(domain)
            t_results["ports"] = await self.monitor_ports(domain)

            if is_url:
                t_results["content"] = await self.monitor_content(target)
                t_results["technologies"] = await self.monitor_technologies(target)

            results["targets"][target] = t_results

        results["new_alerts"] = [vars(a) for a in self.alerts]
        results["summary"] = {
            "targets_checked": len(targets),
            "new_alerts": len(self.alerts),
            "high_severity": sum(1 for a in self.alerts if a.severity == "high"),
            "timestamp": datetime.utcnow().isoformat(),
        }

        log.info(f"Monitoring complete: {len(self.alerts)} new alerts")
        return results

    def get_alerts_history(self, target: str = None, severity: str = None,
                            limit: int = 100) -> list[dict]:
        """Get historical alerts from the monitor database."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if target:
            query += " AND target=?"
            params.append(target)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        cols = ["id", "alert_type", "target", "change", "severity", "old_value", "new_value", "timestamp"]
        return [dict(zip(cols, row)) for row in rows]
