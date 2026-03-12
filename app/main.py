"""AptumNet - Network Monitoring & Security Platform."""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import os

from app.core.database import init_db, Base, engine
from app.api.routes import router as api_router
from app.licensing.routes import router as licensing_router
from app.licensing.middleware import LicenseMiddleware
from app.licensing.manager import license_manager
from app.licensing import models as licensing_models  # noqa: F401 — register models

app = FastAPI(
    title="AptumNet",
    description="Network Monitoring & Security Platform",
    version="1.0.0",
)

# License enforcement middleware
app.add_middleware(LicenseMiddleware)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "templates", "static")
templates_dir = os.path.join(os.path.dirname(__file__), "templates")

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Include API routes
app.include_router(api_router)
app.include_router(licensing_router)


@app.on_event("startup")
def startup():
    init_db()
    # Create licensing tables
    licensing_models.License.metadata.create_all(bind=engine)
    # Check if any active license exists to exit setup mode
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        active = db.query(licensing_models.License).filter(
            licensing_models.License.status == "active"
        ).first()
        if active:
            license_manager.validate_license(db, active.license_key)
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request):
    """Serve the topology visualization page."""
    return templates.TemplateResponse("topology.html", {"request": request})


@app.get("/licensing", response_class=HTMLResponse)
async def licensing_page(request: Request):
    """Serve the licensing management page."""
    return templates.TemplateResponse("licensing.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "healthy", "service": "AptumNet"}
