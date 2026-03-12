"""Database models for the licensing system."""
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text,
    ForeignKey, JSON, BigInteger, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime

from app.core.database import Base


class License(Base):
    """Master license record."""
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(512), unique=True, nullable=False, index=True)
    customer_name = Column(String(255), nullable=False)
    customer_email = Column(String(255), nullable=True)
    license_type = Column(String(50), nullable=False)  # trial, standard, professional, enterprise
    status = Column(String(20), default="active")  # active, suspended, expired, revoked
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    max_hosts = Column(Integer, default=10)
    max_gb_processed = Column(Float, default=1.0)  # GB quota per month
    max_concurrent_sessions = Column(Integer, default=1)  # floating license seats
    signature = Column(Text, nullable=False)  # cryptographic signature for chain of trust
    issuer_fingerprint = Column(String(64), nullable=True)  # fingerprint of signing key
    metadata_json = Column(JSON, nullable=True)  # extra license metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    modules = relationship("LicenseModule", back_populates="license", cascade="all, delete-orphan")
    activations = relationship("LicenseActivation", back_populates="license", cascade="all, delete-orphan")
    usage_records = relationship("UsageRecord", back_populates="license", cascade="all, delete-orphan")


class LicenseModule(Base):
    """Licensed modules — controls which features are enabled."""
    __tablename__ = "license_modules"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=False)
    module_name = Column(String(100), nullable=False)  # scanner, ids, snmp, agent, pentest, logs, anomaly, topology, network
    enabled = Column(Boolean, default=True)
    quota_limit = Column(Float, nullable=True)  # module-specific quota (e.g., scans/day)
    quota_used = Column(Float, default=0.0)
    quota_reset_at = Column(DateTime, nullable=True)
    settings = Column(JSON, nullable=True)  # module-specific settings

    license = relationship("License", back_populates="modules")

    __table_args__ = (
        UniqueConstraint("license_id", "module_name", name="uq_license_module"),
    )


class LicenseActivation(Base):
    """Machine binding — tracks where the license is activated."""
    __tablename__ = "license_activations"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=False)
    machine_id = Column(String(255), nullable=False)  # hardware fingerprint
    machine_hostname = Column(String(255), nullable=True)
    machine_ip = Column(String(45), nullable=True)
    activated_at = Column(DateTime, default=datetime.utcnow)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    session_token = Column(String(512), nullable=True)  # for floating license session tracking
    deactivated_at = Column(DateTime, nullable=True)

    license = relationship("License", back_populates="activations")

    __table_args__ = (
        UniqueConstraint("license_id", "machine_id", name="uq_license_machine"),
        Index("ix_activation_heartbeat", "last_heartbeat"),
    )


class UsageRecord(Base):
    """Tracks GB processed and resource consumption."""
    __tablename__ = "usage_records"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=False)
    record_type = Column(String(50), nullable=False)  # gb_processed, scan_count, log_ingested, api_call
    amount = Column(Float, nullable=False, default=0.0)
    unit = Column(String(20), default="GB")
    module_name = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    recorded_at = Column(DateTime, default=datetime.utcnow)

    license = relationship("License", back_populates="usage_records")

    __table_args__ = (
        Index("ix_usage_recorded", "recorded_at"),
        Index("ix_usage_license_type", "license_id", "record_type"),
    )


class LicenseCache(Base):
    """Offline cache — stores validated license state for grace period."""
    __tablename__ = "license_cache"

    id = Column(Integer, primary_key=True, index=True)
    license_key_hash = Column(String(64), unique=True, nullable=False, index=True)
    cached_license = Column(JSON, nullable=False)  # full license snapshot
    cached_modules = Column(JSON, nullable=False)  # module list snapshot
    validated_at = Column(DateTime, nullable=False)  # last successful online validation
    grace_period_hours = Column(Integer, default=72)  # how long cache is valid
    machine_id = Column(String(255), nullable=False)
    is_valid = Column(Boolean, default=True)


class LicenseAuditLog(Base):
    """Audit trail for all license operations."""
    __tablename__ = "license_audit_log"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=True)
    action = Column(String(100), nullable=False)  # activate, deactivate, validate, quota_exceeded, etc.
    actor = Column(String(255), nullable=True)  # who performed the action
    machine_id = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_audit_timestamp", "timestamp"),
    )
