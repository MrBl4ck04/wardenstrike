"""
WardenStrike - Session & Database Management
SQLite-backed persistence for engagements, targets, findings.
"""

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime,
    ForeignKey, create_engine, Index, event
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

Base = declarative_base()


class Engagement(Base):
    __tablename__ = "engagements"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    platform = Column(String(50))  # hackerone, bugcrowd, intigriti, immunefi, private
    program_url = Column(String(500))
    scope_domains = Column(Text)  # JSON list
    scope_ips = Column(Text)  # JSON list
    out_of_scope = Column(Text)  # JSON list
    notes = Column(Text)
    status = Column(String(20), default="active")  # active, paused, completed
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    targets = relationship("Target", back_populates="engagement", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="engagement", cascade="all, delete-orphan")

    @property
    def scope_list(self) -> list[str]:
        return json.loads(self.scope_domains) if self.scope_domains else []

    @scope_list.setter
    def scope_list(self, domains: list[str]):
        self.scope_domains = json.dumps(domains)


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (Index("idx_target_domain", "domain"),)

    id = Column(Integer, primary_key=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"), nullable=False)
    domain = Column(String(255), nullable=False)
    ip_address = Column(String(45))
    ports = Column(Text)  # JSON list
    technologies = Column(Text)  # JSON list
    status_code = Column(Integer)
    title = Column(String(500))
    cdn = Column(String(50))
    waf = Column(String(50))
    server = Column(String(100))
    content_length = Column(Integer)
    is_alive = Column(Boolean, default=True)
    recon_data = Column(Text)  # JSON blob for extra recon data
    last_scanned = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    engagement = relationship("Engagement", back_populates="targets")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")

    @property
    def tech_list(self) -> list[str]:
        return json.loads(self.technologies) if self.technologies else []


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_hash", "finding_hash"),
        Index("idx_finding_type", "vuln_type"),
    )

    id = Column(Integer, primary_key=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"))
    finding_hash = Column(String(16), unique=True)  # dedup hash
    title = Column(String(500), nullable=False)
    vuln_type = Column(String(50))  # xss, sqli, ssrf, idor, etc.
    severity = Column(String(10))  # critical, high, medium, low, info
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    cwe_id = Column(String(20))
    url = Column(String(2000))
    endpoint = Column(String(500))
    method = Column(String(10))
    parameter = Column(String(100))
    payload = Column(Text)
    evidence = Column(Text)  # proof/screenshot description
    request = Column(Text)  # raw HTTP request
    response = Column(Text)  # raw HTTP response (truncated)
    description = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    references = Column(Text)  # JSON list of URLs
    steps_to_reproduce = Column(Text)  # JSON list of steps
    tool_source = Column(String(50))  # nuclei, burp, zap, manual, ai
    confidence = Column(String(10), default="medium")  # high, medium, low
    status = Column(String(20), default="new")  # new, confirmed, false_positive, duplicate, reported
    reported_at = Column(DateTime)
    bounty_amount = Column(Float)
    notes = Column(Text)
    ai_analysis = Column(Text)  # AI-generated analysis
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    engagement = relationship("Engagement", back_populates="findings")
    target = relationship("Target", back_populates="findings")


class ReconResult(Base):
    __tablename__ = "recon_results"
    __table_args__ = (Index("idx_recon_type", "result_type"),)

    id = Column(Integer, primary_key=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"))
    result_type = Column(String(50))  # subdomain, port, url, js_file, endpoint, parameter, technology
    value = Column(Text, nullable=False)
    source = Column(String(50))  # tool that found it
    metadata = Column(Text)  # JSON blob
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"), nullable=False)
    scan_type = Column(String(50))  # recon, vuln_scan, exploit_validation
    tool = Column(String(50))
    target = Column(String(255))
    command = Column(Text)
    status = Column(String(20))  # running, completed, failed, cancelled
    results_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    output_file = Column(String(500))
    error = Column(Text)


class SessionManager:
    """Manages database sessions and provides query helpers."""

    def __init__(self, db_path: str = "./data/wardenstrike.db"):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(f"sqlite:///{path}", echo=False)

        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        Base.metadata.create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        return self._session_factory()

    # --- Engagement helpers ---

    def create_engagement(self, name: str, platform: str = "", scope_domains: list[str] | None = None, **kwargs) -> Engagement:
        with self.get_session() as session:
            eng = Engagement(
                name=name,
                platform=platform,
                scope_domains=json.dumps(scope_domains or []),
                **kwargs,
            )
            session.add(eng)
            session.commit()
            session.refresh(eng)
            return eng

    def get_engagement(self, engagement_id: int) -> Engagement | None:
        with self.get_session() as session:
            return session.query(Engagement).get(engagement_id)

    def list_engagements(self, status: str | None = None) -> list[Engagement]:
        with self.get_session() as session:
            q = session.query(Engagement)
            if status:
                q = q.filter(Engagement.status == status)
            return q.order_by(Engagement.updated_at.desc()).all()

    def get_active_engagement(self) -> Engagement | None:
        with self.get_session() as session:
            return session.query(Engagement).filter(Engagement.status == "active").order_by(Engagement.updated_at.desc()).first()

    # --- Target helpers ---

    def add_target(self, engagement_id: int, domain: str, **kwargs) -> Target:
        with self.get_session() as session:
            existing = session.query(Target).filter_by(engagement_id=engagement_id, domain=domain).first()
            if existing:
                for k, v in kwargs.items():
                    if v is not None:
                        setattr(existing, k, v)
                session.commit()
                session.refresh(existing)
                return existing

            target = Target(engagement_id=engagement_id, domain=domain, **kwargs)
            session.add(target)
            session.commit()
            session.refresh(target)
            return target

    def get_targets(self, engagement_id: int, alive_only: bool = False) -> list[Target]:
        with self.get_session() as session:
            q = session.query(Target).filter_by(engagement_id=engagement_id)
            if alive_only:
                q = q.filter(Target.is_alive == True)
            return q.all()

    # --- Finding helpers ---

    def add_finding(self, engagement_id: int, finding_hash: str, **kwargs) -> Finding | None:
        """Add finding if not duplicate. Returns None if duplicate found."""
        with self.get_session() as session:
            existing = session.query(Finding).filter_by(finding_hash=finding_hash).first()
            if existing:
                return None  # Duplicate

            finding = Finding(engagement_id=engagement_id, finding_hash=finding_hash, **kwargs)
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding

    def get_findings(self, engagement_id: int, severity: str | None = None, vuln_type: str | None = None, status: str | None = None) -> list[Finding]:
        with self.get_session() as session:
            q = session.query(Finding).filter_by(engagement_id=engagement_id)
            if severity:
                q = q.filter(Finding.severity == severity)
            if vuln_type:
                q = q.filter(Finding.vuln_type == vuln_type)
            if status:
                q = q.filter(Finding.status == status)
            return q.order_by(Finding.severity, Finding.created_at.desc()).all()

    def update_finding_status(self, finding_id: int, status: str, **kwargs):
        with self.get_session() as session:
            finding = session.query(Finding).get(finding_id)
            if finding:
                finding.status = status
                for k, v in kwargs.items():
                    if hasattr(finding, k):
                        setattr(finding, k, v)
                session.commit()

    def get_finding_stats(self, engagement_id: int) -> dict:
        with self.get_session() as session:
            findings = session.query(Finding).filter_by(engagement_id=engagement_id).all()
            stats = {"total": len(findings), "by_severity": {}, "by_type": {}, "by_status": {}}
            for f in findings:
                stats["by_severity"][f.severity] = stats["by_severity"].get(f.severity, 0) + 1
                stats["by_type"][f.vuln_type] = stats["by_type"].get(f.vuln_type, 0) + 1
                stats["by_status"][f.status] = stats["by_status"].get(f.status, 0) + 1
            return stats

    # --- Recon helpers ---

    def add_recon_result(self, engagement_id: int, result_type: str, value: str, source: str, target_id: int | None = None, metadata: dict | None = None):
        with self.get_session() as session:
            existing = session.query(ReconResult).filter_by(
                engagement_id=engagement_id, result_type=result_type, value=value
            ).first()
            if not existing:
                result = ReconResult(
                    engagement_id=engagement_id,
                    target_id=target_id,
                    result_type=result_type,
                    value=value,
                    source=source,
                    metadata=json.dumps(metadata) if metadata else None,
                )
                session.add(result)
                session.commit()

    def get_recon_results(self, engagement_id: int, result_type: str | None = None) -> list[ReconResult]:
        with self.get_session() as session:
            q = session.query(ReconResult).filter_by(engagement_id=engagement_id)
            if result_type:
                q = q.filter(ReconResult.result_type == result_type)
            return q.all()

    # --- Scan log helpers ---

    def log_scan(self, engagement_id: int, scan_type: str, tool: str, target: str, command: str = "") -> ScanLog:
        with self.get_session() as session:
            log = ScanLog(
                engagement_id=engagement_id,
                scan_type=scan_type,
                tool=tool,
                target=target,
                command=command,
                status="running",
            )
            session.add(log)
            session.commit()
            session.refresh(log)
            return log

    def finish_scan(self, scan_id: int, status: str = "completed", results_count: int = 0, error: str = ""):
        with self.get_session() as session:
            log = session.query(ScanLog).get(scan_id)
            if log:
                log.status = status
                log.results_count = results_count
                log.finished_at = datetime.utcnow()
                if error:
                    log.error = error
                session.commit()
