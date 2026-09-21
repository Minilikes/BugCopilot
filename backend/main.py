"""BugCopilot FastAPI application entrypoint."""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse

from backend.db import create_db_and_tables
from backend.routers import scope, recon, analysis, reports, findings, targets, timeline

app = FastAPI(
    title="BugCopilot API",
    description="AI-assisted bug bounty research tool — for authorized researchers only",
    version="1.0.0",
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(scope.router,    prefix="/api/scope",    tags=["Scope Gate"])
app.include_router(recon.router,    prefix="/api/recon",    tags=["Recon"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(reports.router,  prefix="/api/reports",  tags=["Reports"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(targets.router,  prefix="/api/targets",  tags=["Targets"])
app.include_router(timeline.router, prefix="/api/timeline", tags=["Timeline"])

# ── Static files ──────────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
FRONTEND_DIR = os.path.normpath(FRONTEND_DIR)

app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")


# ── Page routes ───────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/scope", include_in_schema=False)
async def page_scope():
    return FileResponse(os.path.join(FRONTEND_DIR, "scope.html"))


@app.get("/recon", include_in_schema=False)
async def page_recon():
    return FileResponse(os.path.join(FRONTEND_DIR, "recon.html"))


@app.get("/analysis", include_in_schema=False)
async def page_analysis():
    return FileResponse(os.path.join(FRONTEND_DIR, "analysis.html"))


@app.get("/report", include_in_schema=False)
async def page_report():
    return FileResponse(os.path.join(FRONTEND_DIR, "report.html"))


@app.get("/targets", include_in_schema=False)
async def page_targets():
    return FileResponse(os.path.join(FRONTEND_DIR, "targets.html"))


@app.get("/timeline", include_in_schema=False)
async def page_timeline():
    return FileResponse(os.path.join(FRONTEND_DIR, "timeline.html"))


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    create_db_and_tables()
    print("[OK] BugCopilot started. Database initialized.")
