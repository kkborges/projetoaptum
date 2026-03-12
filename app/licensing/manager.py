"""License Manager — central orchestrator for the licensing system.

Handles:
  - License creation and validation with chain of trust
  - Module-level access control
  - GB processed tracking and quota enforcement
  - Floating license session management
  - Machine binding and activation
  - Offline cache with grace period
"""
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.licensing.models import (
    License, LicenseModule, LicenseActivation,
    UsageRecord, LicenseCache, LicenseAuditLog,
)
from app.licensing.crypto import (
    generate_license_key, sign_license_payload, verify_license_signature,
    get_machine_id, verify_machine_binding, get_key_fingerprint,
    generate_keypair, compute_cache_hmac, verify_cache_hmac,
)
from app.core.config import SECRET_KEY

logger = logging.getLogger(__name__)

# All available modules in the system
ALL_MODULES = [
    "scanner", "ids", "snmp", "agent", "pentest",
    "logs", "anomaly", "topology", "network", "dashboard",
]

# Default module grants per license type
LICENSE_TIER_DEFAULTS = {
    "trial": {
        "max_hosts": 5,
        "max_gb_processed": 0.5,
        "max_concurrent_sessions": 1,
        "duration_days": 30,
        "modules": ["dashboard", "scanner", "logs"],
    },
    "standard": {
        "max_hosts": 50,
        "max_gb_processed": 10.0,
        "max_concurrent_sessions": 2,
        "duration_days": 365,
        "modules": ["dashboard", "scanner", "ids", "snmp", "agent", "logs", "anomaly"],
    },
    "professional": {
        "max_hosts": 500,
        "max_gb_processed": 100.0,
        "max_concurrent_sessions": 5,
        "duration_days": 365,
        "modules": ["dashboard", "scanner", "ids", "snmp", "agent", "pentest", "logs", "anomaly", "topology"],
    },
    "enterprise": {
        "max_hosts": -1,  # unlimited
        "max_gb_processed": -1.0,  # unlimited
        "max_concurrent_sessions": -1,  # unlimited
        "duration_days": 365,
        "modules": ALL_MODULES,
    },
}

# Grace period for offline cache (hours)
DEFAULT_GRACE_PERIOD_HOURS = 72

# Floating license heartbeat timeout (minutes)
FLOATING_HEARTBEAT_TIMEOUT = 15


class LicenseManager:
    """Manages the full license lifecycle."""

    def __init__(self, private_pem: Optional[bytes] = None, public_pem: Optional[bytes] = None):
        self._private_pem = private_pem
        self._public_pem = public_pem
        self._setup_mode = True  # start with no license
        self._current_license: Optional[dict] = None

    @property
    def is_setup_mode(self) -> bool:
        return self._setup_mode

    def set_setup_mode(self, val: bool):
        self._setup_mode = val

    # --- Key Management ---

    def ensure_keys(self, db: Session):
        """Ensure signing keys exist. Generate if needed."""
        key_dir = os.path.join(os.path.dirname(__file__), ".keys")
        os.makedirs(key_dir, exist_ok=True)
        priv_path = os.path.join(key_dir, "license.key")
        pub_path = os.path.join(key_dir, "license.pub")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                self._private_pem = f.read()
            with open(pub_path, "rb") as f:
                self._public_pem = f.read()
        else:
            self._private_pem, self._public_pem = generate_keypair()
            with open(priv_path, "wb") as f:
                f.write(self._private_pem)
            os.chmod(priv_path, 0o600)
            with open(pub_path, "wb") as f:
                f.write(self._public_pem)
            logger.info("Generated new license signing keypair")

    # --- License Creation ---

    def create_license(
        self,
        db: Session,
        customer_name: str,
        license_type: str = "trial",
        customer_email: Optional[str] = None,
        max_hosts: Optional[int] = None,
        max_gb_processed: Optional[float] = None,
        max_concurrent_sessions: Optional[int] = None,
        duration_days: Optional[int] = None,
        modules: Optional[list[str]] = None,
    ) -> License:
        """Create and sign a new license."""
        self.ensure_keys(db)

        tier = LICENSE_TIER_DEFAULTS.get(license_type, LICENSE_TIER_DEFAULTS["trial"])
        _max_hosts = max_hosts if max_hosts is not None else tier["max_hosts"]
        _max_gb = max_gb_processed if max_gb_processed is not None else tier["max_gb_processed"]
        _max_sessions = max_concurrent_sessions if max_concurrent_sessions is not None else tier["max_concurrent_sessions"]
        _duration = duration_days if duration_days is not None else tier["duration_days"]
        _modules = modules if modules is not None else tier["modules"]

        license_key = generate_license_key()
        now = datetime.utcnow()
        expires_at = now + timedelta(days=_duration) if _duration > 0 else None

        # Build payload for signing
        payload = {
            "license_key": license_key,
            "customer_name": customer_name,
            "license_type": license_type,
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "max_hosts": _max_hosts,
            "max_gb_processed": _max_gb,
            "max_concurrent_sessions": _max_sessions,
            "modules": sorted(_modules),
        }

        signature = sign_license_payload(payload, self._private_pem)
        fingerprint = get_key_fingerprint(self._public_pem)

        lic = License(
            license_key=license_key,
            customer_name=customer_name,
            customer_email=customer_email,
            license_type=license_type,
            status="active",
            issued_at=now,
            expires_at=expires_at,
            max_hosts=_max_hosts,
            max_gb_processed=_max_gb,
            max_concurrent_sessions=_max_sessions,
            signature=signature,
            issuer_fingerprint=fingerprint,
            metadata_json={"payload": payload},
        )
        db.add(lic)
        db.flush()

        # Create module entries
        for mod_name in _modules:
            mod = LicenseModule(
                license_id=lic.id,
                module_name=mod_name,
                enabled=True,
            )
            db.add(mod)

        self._audit(db, lic.id, "license_created", details={
            "type": license_type, "modules": _modules,
        })

        db.commit()
        db.refresh(lic)
        logger.info(f"License created: {license_key} ({license_type}) for {customer_name}")
        return lic

    # --- License Validation (Chain of Trust) ---

    def validate_license(self, db: Session, license_key: str) -> dict:
        """Validate a license key with full chain of trust verification.

        Returns dict with: valid, license, modules, errors
        """
        self.ensure_keys(db)

        lic = db.query(License).filter(License.license_key == license_key).first()
        if not lic:
            return {"valid": False, "errors": ["License key not found"]}

        errors = []

        # 1. Verify cryptographic signature
        payload = lic.metadata_json.get("payload") if lic.metadata_json else None
        if not payload:
            errors.append("License payload missing — cannot verify signature")
        elif not verify_license_signature(payload, lic.signature, self._public_pem):
            errors.append("Invalid license signature — chain of trust broken")

        # 2. Verify issuer fingerprint
        expected_fp = get_key_fingerprint(self._public_pem)
        if lic.issuer_fingerprint and lic.issuer_fingerprint != expected_fp:
            errors.append("Issuer fingerprint mismatch")

        # 3. Check status
        if lic.status != "active":
            errors.append(f"License status is '{lic.status}'")

        # 4. Check expiration
        if lic.expires_at and datetime.utcnow() > lic.expires_at:
            errors.append("License has expired")
            lic.status = "expired"
            db.commit()

        modules = [
            {"name": m.module_name, "enabled": m.enabled, "quota_limit": m.quota_limit, "quota_used": m.quota_used}
            for m in lic.modules
        ]

        valid = len(errors) == 0
        self._audit(db, lic.id, "license_validated", details={
            "valid": valid, "errors": errors,
        })

        if valid:
            self._setup_mode = False
            self._current_license = {
                "id": lic.id,
                "key": lic.license_key,
                "type": lic.license_type,
                "customer": lic.customer_name,
                "modules": [m.module_name for m in lic.modules if m.enabled],
                "max_hosts": lic.max_hosts,
                "max_gb_processed": lic.max_gb_processed,
            }

        return {
            "valid": valid,
            "license": {
                "id": lic.id,
                "key": lic.license_key,
                "type": lic.license_type,
                "customer": lic.customer_name,
                "status": lic.status,
                "issued_at": lic.issued_at.isoformat(),
                "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
                "max_hosts": lic.max_hosts,
                "max_gb_processed": lic.max_gb_processed,
                "max_concurrent_sessions": lic.max_concurrent_sessions,
            },
            "modules": modules,
            "errors": errors,
        }

    # --- Module Access Control ---

    def check_module_access(self, db: Session, module_name: str) -> dict:
        """Check if a module is licensed and within quota."""
        if self._setup_mode:
            return {"allowed": False, "reason": "No license activated — system in setup mode"}

        if not self._current_license:
            return {"allowed": False, "reason": "No active license"}

        lic_id = self._current_license["id"]
        mod = db.query(LicenseModule).filter(
            LicenseModule.license_id == lic_id,
            LicenseModule.module_name == module_name,
        ).first()

        if not mod:
            return {"allowed": False, "reason": f"Module '{module_name}' not included in license"}

        if not mod.enabled:
            return {"allowed": False, "reason": f"Module '{module_name}' is disabled"}

        # Check module-specific quota
        if mod.quota_limit is not None and mod.quota_limit > 0:
            if mod.quota_used >= mod.quota_limit:
                return {"allowed": False, "reason": f"Module '{module_name}' quota exceeded ({mod.quota_used}/{mod.quota_limit})"}

        return {"allowed": True, "module": module_name, "quota_used": mod.quota_used, "quota_limit": mod.quota_limit}

    # --- GB Processed Tracking ---

    def record_usage(self, db: Session, amount_bytes: int, module_name: Optional[str] = None, details: Optional[dict] = None):
        """Record data processed (in bytes), track against GB quota."""
        if not self._current_license:
            return

        lic_id = self._current_license["id"]
        amount_gb = amount_bytes / (1024 ** 3)

        record = UsageRecord(
            license_id=lic_id,
            record_type="gb_processed",
            amount=amount_gb,
            unit="GB",
            module_name=module_name,
            details=details,
        )
        db.add(record)
        db.commit()

    def check_gb_quota(self, db: Session) -> dict:
        """Check current GB processed against license quota."""
        if not self._current_license:
            return {"within_quota": False, "reason": "No active license"}

        lic_id = self._current_license["id"]
        max_gb = self._current_license.get("max_gb_processed", 0)

        if max_gb < 0:  # unlimited
            return {"within_quota": True, "used_gb": 0, "max_gb": -1, "unlimited": True}

        # Sum GB processed this month
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        total = db.query(func.coalesce(func.sum(UsageRecord.amount), 0.0)).filter(
            UsageRecord.license_id == lic_id,
            UsageRecord.record_type == "gb_processed",
            UsageRecord.recorded_at >= month_start,
        ).scalar()

        within = total < max_gb
        return {
            "within_quota": within,
            "used_gb": round(float(total), 4),
            "max_gb": max_gb,
            "remaining_gb": round(max_gb - float(total), 4) if within else 0,
            "unlimited": False,
        }

    # --- Floating License Management ---

    def activate_session(self, db: Session, license_key: str, machine_id: Optional[str] = None) -> dict:
        """Activate a floating license session on a machine."""
        lic = db.query(License).filter(License.license_key == license_key).first()
        if not lic:
            return {"success": False, "error": "License not found"}
        if lic.status != "active":
            return {"success": False, "error": f"License is {lic.status}"}

        mid = machine_id or get_machine_id()

        # Check existing activation for this machine
        existing = db.query(LicenseActivation).filter(
            LicenseActivation.license_id == lic.id,
            LicenseActivation.machine_id == mid,
            LicenseActivation.is_active == True,
        ).first()

        if existing:
            existing.last_heartbeat = datetime.utcnow()
            db.commit()
            return {"success": True, "activation_id": existing.id, "reactivated": True}

        # Check concurrent session limit
        if lic.max_concurrent_sessions > 0:
            cutoff = datetime.utcnow() - timedelta(minutes=FLOATING_HEARTBEAT_TIMEOUT)
            active_count = db.query(LicenseActivation).filter(
                LicenseActivation.license_id == lic.id,
                LicenseActivation.is_active == True,
                LicenseActivation.last_heartbeat >= cutoff,
            ).count()

            if active_count >= lic.max_concurrent_sessions:
                # Try to reclaim stale sessions
                stale = db.query(LicenseActivation).filter(
                    LicenseActivation.license_id == lic.id,
                    LicenseActivation.is_active == True,
                    LicenseActivation.last_heartbeat < cutoff,
                ).all()
                for s in stale:
                    s.is_active = False
                    s.deactivated_at = datetime.utcnow()
                db.flush()

                active_count = db.query(LicenseActivation).filter(
                    LicenseActivation.license_id == lic.id,
                    LicenseActivation.is_active == True,
                    LicenseActivation.last_heartbeat >= cutoff,
                ).count()

                if active_count >= lic.max_concurrent_sessions:
                    return {"success": False, "error": f"Max concurrent sessions reached ({lic.max_concurrent_sessions})"}

        import secrets
        session_token = secrets.token_urlsafe(32)

        activation = LicenseActivation(
            license_id=lic.id,
            machine_id=mid,
            machine_hostname=None,
            session_token=session_token,
            is_active=True,
        )
        db.add(activation)

        self._audit(db, lic.id, "session_activated", machine_id=mid)
        db.commit()
        db.refresh(activation)

        return {"success": True, "activation_id": activation.id, "session_token": session_token}

    def deactivate_session(self, db: Session, license_key: str, machine_id: Optional[str] = None) -> dict:
        """Release a floating license session."""
        lic = db.query(License).filter(License.license_key == license_key).first()
        if not lic:
            return {"success": False, "error": "License not found"}

        mid = machine_id or get_machine_id()
        activation = db.query(LicenseActivation).filter(
            LicenseActivation.license_id == lic.id,
            LicenseActivation.machine_id == mid,
            LicenseActivation.is_active == True,
        ).first()

        if not activation:
            return {"success": False, "error": "No active session for this machine"}

        activation.is_active = False
        activation.deactivated_at = datetime.utcnow()
        self._audit(db, lic.id, "session_deactivated", machine_id=mid)
        db.commit()

        return {"success": True}

    def heartbeat(self, db: Session, license_key: str, machine_id: Optional[str] = None) -> dict:
        """Update floating license heartbeat."""
        lic = db.query(License).filter(License.license_key == license_key).first()
        if not lic:
            return {"success": False, "error": "License not found"}

        mid = machine_id or get_machine_id()
        activation = db.query(LicenseActivation).filter(
            LicenseActivation.license_id == lic.id,
            LicenseActivation.machine_id == mid,
            LicenseActivation.is_active == True,
        ).first()

        if not activation:
            return {"success": False, "error": "No active session"}

        activation.last_heartbeat = datetime.utcnow()
        db.commit()
        return {"success": True, "next_heartbeat_seconds": FLOATING_HEARTBEAT_TIMEOUT * 60 // 2}

    # --- Offline Cache ---

    def cache_license(self, db: Session, license_key: str):
        """Cache license state for offline use."""
        lic = db.query(License).filter(License.license_key == license_key).first()
        if not lic:
            return

        key_hash = hashlib.sha256(license_key.encode()).hexdigest()
        mid = get_machine_id()

        cached_license = {
            "id": lic.id,
            "key": lic.license_key,
            "type": lic.license_type,
            "customer": lic.customer_name,
            "status": lic.status,
            "max_hosts": lic.max_hosts,
            "max_gb_processed": lic.max_gb_processed,
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        }
        cached_modules = [
            {"name": m.module_name, "enabled": m.enabled}
            for m in lic.modules
        ]

        existing = db.query(LicenseCache).filter(LicenseCache.license_key_hash == key_hash).first()
        if existing:
            existing.cached_license = cached_license
            existing.cached_modules = cached_modules
            existing.validated_at = datetime.utcnow()
            existing.machine_id = mid
            existing.is_valid = True
        else:
            cache = LicenseCache(
                license_key_hash=key_hash,
                cached_license=cached_license,
                cached_modules=cached_modules,
                validated_at=datetime.utcnow(),
                grace_period_hours=DEFAULT_GRACE_PERIOD_HOURS,
                machine_id=mid,
                is_valid=True,
            )
            db.add(cache)

        db.commit()

    def validate_from_cache(self, db: Session, license_key: str) -> dict:
        """Validate license from offline cache with grace period check."""
        key_hash = hashlib.sha256(license_key.encode()).hexdigest()
        cached = db.query(LicenseCache).filter(
            LicenseCache.license_key_hash == key_hash,
            LicenseCache.is_valid == True,
        ).first()

        if not cached:
            return {"valid": False, "errors": ["No cached license found"], "from_cache": True}

        # Check machine binding
        if not verify_machine_binding(cached.machine_id):
            return {"valid": False, "errors": ["Machine ID mismatch — cache invalid"], "from_cache": True}

        # Check grace period
        grace_deadline = cached.validated_at + timedelta(hours=cached.grace_period_hours)
        now = datetime.utcnow()
        if now > grace_deadline:
            cached.is_valid = False
            db.commit()
            return {"valid": False, "errors": ["Grace period expired — online validation required"], "from_cache": True}

        remaining_hours = (grace_deadline - now).total_seconds() / 3600

        self._setup_mode = False
        self._current_license = cached.cached_license

        return {
            "valid": True,
            "from_cache": True,
            "license": cached.cached_license,
            "modules": cached.cached_modules,
            "grace_remaining_hours": round(remaining_hours, 1),
            "errors": [],
        }

    # --- Status & Info ---

    def get_status(self, db: Session) -> dict:
        """Get current licensing status."""
        if self._setup_mode:
            return {
                "mode": "setup",
                "licensed": False,
                "message": "No license activated. Use the licensing interface to activate a license.",
            }

        if not self._current_license:
            return {"mode": "setup", "licensed": False, "message": "No active license"}

        quota = self.check_gb_quota(db)

        lic = db.query(License).filter(License.id == self._current_license["id"]).first()
        active_sessions = 0
        if lic:
            cutoff = datetime.utcnow() - timedelta(minutes=FLOATING_HEARTBEAT_TIMEOUT)
            active_sessions = db.query(LicenseActivation).filter(
                LicenseActivation.license_id == lic.id,
                LicenseActivation.is_active == True,
                LicenseActivation.last_heartbeat >= cutoff,
            ).count()

        return {
            "mode": "licensed",
            "licensed": True,
            "license": self._current_license,
            "quota": quota,
            "active_sessions": active_sessions,
            "max_sessions": lic.max_concurrent_sessions if lic else 0,
        }

    def get_available_modules(self) -> list[str]:
        """Get list of all available modules."""
        return ALL_MODULES.copy()

    def get_licensed_modules(self) -> list[str]:
        """Get list of currently licensed modules."""
        if not self._current_license:
            return []
        return self._current_license.get("modules", [])

    # --- Audit ---

    def _audit(self, db: Session, license_id: Optional[int], action: str,
               machine_id: Optional[str] = None, details: Optional[dict] = None):
        entry = LicenseAuditLog(
            license_id=license_id,
            action=action,
            machine_id=machine_id or get_machine_id(),
            details=details,
        )
        db.add(entry)

    def get_audit_log(self, db: Session, license_id: Optional[int] = None, limit: int = 100) -> list[dict]:
        query = db.query(LicenseAuditLog)
        if license_id:
            query = query.filter(LicenseAuditLog.license_id == license_id)
        entries = query.order_by(LicenseAuditLog.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": e.id,
                "license_id": e.license_id,
                "action": e.action,
                "machine_id": e.machine_id,
                "details": e.details,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in entries
        ]


# Singleton instance
license_manager = LicenseManager()
