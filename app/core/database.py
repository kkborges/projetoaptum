"""Database models and session management."""
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, ForeignKey, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

from app.core.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)
    vendor = Column(String(255), nullable=True)
    os_detected = Column(String(255), nullable=True)
    status = Column(String(20), default="unknown")  # up, down, unknown
    host_type = Column(String(50), default="unknown")  # server, workstation, router, switch, firewall, printer
    snmp_enabled = Column(Boolean, default=False)
    agent_installed = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    location = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    # Topology position
    topology_x = Column(Float, nullable=True)
    topology_y = Column(Float, nullable=True)

    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    metrics = relationship("HostMetric", back_populates="host", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="host", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20), default="closed")  # open, closed, filtered
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)
    last_scanned = Column(DateTime, default=datetime.utcnow)

    host = relationship("Host", back_populates="ports")


class HostMetric(Base):
    __tablename__ = "host_metrics"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    metric_type = Column(String(50), nullable=False)  # cpu, memory, disk, network, uptime
    metric_value = Column(Float, nullable=False)
    metric_unit = Column(String(20), nullable=True)
    details = Column(JSON, nullable=True)
    collected_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String(20), default="snmp")  # snmp, agent, scan

    host = relationship("Host", back_populates="metrics")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    alert_type = Column(String(50), nullable=False)  # security, performance, availability, vulnerability
    severity = Column(String(20), default="info")  # critical, high, medium, low, info
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(50), nullable=True)  # ids, scanner, anomaly, pentest, log_analysis
    status = Column(String(20), default="open")  # open, acknowledged, resolved, false_positive
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    host = relationship("Host", back_populates="alerts")


class NetworkLink(Base):
    __tablename__ = "network_links"

    id = Column(Integer, primary_key=True, index=True)
    source_host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    target_host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    link_type = Column(String(50), default="ethernet")  # ethernet, wifi, vpn, virtual
    bandwidth = Column(String(50), nullable=True)
    status = Column(String(20), default="active")
    discovered_at = Column(DateTime, default=datetime.utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)  # discovery, port_scan, vulnerability, pentest
    target = Column(String(255), nullable=False)
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    progress = Column(Integer, default=0)
    results = Column(JSON, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    source = Column(String(100), nullable=False)
    level = Column(String(20), default="info")  # debug, info, warning, error, critical
    message = Column(Text, nullable=False)
    raw_log = Column(Text, nullable=True)
    parsed_data = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)
