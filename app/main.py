"""AptumNet - Network Monitoring & Security Platform."""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import os

from app.core.database import init_db
from app.api.routes import router as api_router

app = FastAPI(
    title="AptumNet",
    description="Network Monitoring & Security Platform",
    version="1.0.0",
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "templates", "static")
templates_dir = os.path.join(os.path.dirname(__file__), "templates")

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Include API routes
app.include_router(api_router)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request):
    """Serve the topology visualization page."""
    return templates.TemplateResponse("topology.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "healthy", "service": "AptumNet"}
