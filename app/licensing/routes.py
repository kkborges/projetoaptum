"""API routes for the licensing system."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.licensing.manager import license_manager, ALL_MODULES
from app.licensing.models import License, LicenseModule, UsageRecord

router = APIRouter(prefix="/api/licensing", tags=["licensing"])


# --- Request/Response Models ---

class LicenseCreateRequest(BaseModel):
    customer_name: str
    license_type: str = "trial"
    customer_email: Optional[str] = None
    max_hosts: Optional[int] = None
    max_gb_processed: Optional[float] = None
    max_concurrent_sessions: Optional[int] = None
    duration_days: Optional[int] = None
    modules: Optional[list[str]] = None


class LicenseActivateRequest(BaseModel):
    license_key: str
    machine_id: Optional[str] = None


class HeartbeatRequest(BaseModel):
    license_key: str
    machine_id: Optional[str] = None


class ModuleCheckRequest(BaseModel):
    module_name: str


class UsageReportRequest(BaseModel):
    amount_bytes: int
    module_name: Optional[str] = None
    details: Optional[dict] = None


# --- Status & Setup ---

@router.get("/status")
def get_licensing_status(db: Session = Depends(get_db)):
    """Get current licensing status. Returns setup mode info if no license is active."""
    return license_manager.get_status(db)


@router.get("/modules")
def get_available_modules():
    """List all available modules and their licensing status."""
    licensed = license_manager.get_licensed_modules()
    return {
        "all_modules": ALL_MODULES,
        "licensed_modules": licensed,
        "modules": [
            {"name": m, "licensed": m in licensed}
            for m in ALL_MODULES
        ],
    }


# --- License CRUD ---

@router.post("/licenses")
def create_license(req: LicenseCreateRequest, db: Session = Depends(get_db)):
    """Create a new license (server-side, for admin use)."""
    if req.license_type not in ("trial", "standard", "professional", "enterprise"):
        raise HTTPException(status_code=400, detail="Invalid license type")
    if req.modules:
        invalid = [m for m in req.modules if m not in ALL_MODULES]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid modules: {invalid}")

    lic = license_manager.create_license(
        db,
        customer_name=req.customer_name,
        license_type=req.license_type,
        customer_email=req.customer_email,
        max_hosts=req.max_hosts,
        max_gb_processed=req.max_gb_processed,
        max_concurrent_sessions=req.max_concurrent_sessions,
        duration_days=req.duration_days,
        modules=req.modules,
    )
    return {
        "license_key": lic.license_key,
        "license_type": lic.license_type,
        "customer": lic.customer_name,
        "status": lic.status,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "modules": [m.module_name for m in lic.modules],
    }


@router.get("/licenses")
def list_licenses(db: Session = Depends(get_db)):
    """List all licenses."""
    licenses = db.query(License).order_by(License.created_at.desc()).all()
    return [
        {
            "id": lic.id,
            "license_key": lic.license_key,
            "customer": lic.customer_name,
            "type": lic.license_type,
            "status": lic.status,
            "issued_at": lic.issued_at.isoformat(),
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "max_hosts": lic.max_hosts,
            "max_gb_processed": lic.max_gb_processed,
            "modules": [m.module_name for m in lic.modules if m.enabled],
        }
        for lic in licenses
    ]


@router.get("/licenses/{license_id}")
def get_license_detail(license_id: int, db: Session = Depends(get_db)):
    """Get detailed license information."""
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")

    return {
        "id": lic.id,
        "license_key": lic.license_key,
        "customer_name": lic.customer_name,
        "customer_email": lic.customer_email,
        "license_type": lic.license_type,
        "status": lic.status,
        "issued_at": lic.issued_at.isoformat(),
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "max_hosts": lic.max_hosts,
        "max_gb_processed": lic.max_gb_processed,
        "max_concurrent_sessions": lic.max_concurrent_sessions,
        "modules": [
            {
                "name": m.module_name,
                "enabled": m.enabled,
                "quota_limit": m.quota_limit,
                "quota_used": m.quota_used,
            }
            for m in lic.modules
        ],
        "activations": [
            {
                "id": a.id,
                "machine_id": a.machine_id,
                "is_active": a.is_active,
                "activated_at": a.activated_at.isoformat(),
                "last_heartbeat": a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            }
            for a in lic.activations
        ],
    }


# --- Validation & Activation ---

@router.post("/validate")
def validate_license(req: LicenseActivateRequest, db: Session = Depends(get_db)):
    """Validate a license key (chain of trust verification)."""
    result = license_manager.validate_license(db, req.license_key)
    if result["valid"]:
        license_manager.cache_license(db, req.license_key)
    return result


@router.post("/activate")
def activate_license(req: LicenseActivateRequest, db: Session = Depends(get_db)):
    """Activate a floating license session on this machine."""
    # First validate
    validation = license_manager.validate_license(db, req.license_key)
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail=validation["errors"])

    # Then activate session
    result = license_manager.activate_session(db, req.license_key, req.machine_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])

    # Cache for offline
    license_manager.cache_license(db, req.license_key)

    return {
        "status": "activated",
        "activation_id": result["activation_id"],
        "session_token": result.get("session_token"),
        "license": validation["license"],
        "modules": validation["modules"],
    }


@router.post("/deactivate")
def deactivate_license(req: LicenseActivateRequest, db: Session = Depends(get_db)):
    """Release a floating license session."""
    result = license_manager.deactivate_session(db, req.license_key, req.machine_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"status": "deactivated"}


@router.post("/heartbeat")
def license_heartbeat(req: HeartbeatRequest, db: Session = Depends(get_db)):
    """Keep floating license session alive."""
    result = license_manager.heartbeat(db, req.license_key, req.machine_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# --- Module Access ---

@router.post("/check-module")
def check_module_access(req: ModuleCheckRequest, db: Session = Depends(get_db)):
    """Check if a specific module is licensed."""
    return license_manager.check_module_access(db, req.module_name)


# --- Quota & Usage ---

@router.get("/quota")
def get_quota_status(db: Session = Depends(get_db)):
    """Get current GB quota status."""
    return license_manager.check_gb_quota(db)


@router.post("/usage")
def report_usage(req: UsageReportRequest, db: Session = Depends(get_db)):
    """Report data usage (GB processed)."""
    license_manager.record_usage(db, req.amount_bytes, req.module_name, req.details)
    return license_manager.check_gb_quota(db)


@router.get("/usage/history")
def get_usage_history(days: int = 30, db: Session = Depends(get_db)):
    """Get usage history."""
    if not license_manager._current_license:
        return {"records": [], "total_gb": 0}

    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    records = db.query(UsageRecord).filter(
        UsageRecord.license_id == license_manager._current_license["id"],
        UsageRecord.recorded_at >= cutoff,
    ).order_by(UsageRecord.recorded_at.desc()).limit(500).all()

    return {
        "records": [
            {
                "type": r.record_type,
                "amount": r.amount,
                "unit": r.unit,
                "module": r.module_name,
                "recorded_at": r.recorded_at.isoformat(),
            }
            for r in records
        ],
        "total_gb": sum(r.amount for r in records if r.record_type == "gb_processed"),
    }


# --- Offline Cache ---

@router.post("/validate-offline")
def validate_offline(req: LicenseActivateRequest, db: Session = Depends(get_db)):
    """Validate license from offline cache (grace period)."""
    return license_manager.validate_from_cache(db, req.license_key)


# --- Audit Log ---

@router.get("/audit")
def get_audit_log(license_id: Optional[int] = None, limit: int = 100, db: Session = Depends(get_db)):
    """Get license audit log."""
    return license_manager.get_audit_log(db, license_id, limit)
