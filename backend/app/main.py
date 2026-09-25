import sys
import os
import time
from datetime import datetime

# Ensure backend directory is in sys.path so 'app' can be imported anywhere
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# If executed directly as a script (e.g., `python backend/app/main.py`), launch uvicorn
if __name__ == "__main__" and (__package__ is None or __package__ == ""):
    import uvicorn
    print("=" * 60)
    print(" Starting AetherGuard AI SOC FastAPI & ML Backend")
    print(" Endpoint: http://127.0.0.1:8000")
    print(" Swagger Docs: http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
    sys.exit(0)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

try:
    from .schemas.models import SystemStatus
    from .ml.isolation_forest import detector
    from .db.database import init_db, get_db_stats
    from .routers import (
        auth_router,
        logs_router,
        threats_router,
        incidents_router,
        ai_router,
        reports_router
    )
except ImportError:
    from app.schemas.models import SystemStatus
    from app.ml.isolation_forest import detector
    from app.db.database import init_db, get_db_stats
    from app.routers import (
        auth_router,
        logs_router,
        threats_router,
        incidents_router,
        ai_router,
        reports_router
    )

# Initialize SQLite Database on startup
init_db()

app = FastAPI(
    title="AetherGuard AI SOC Backend",
    description="Enterprise AI Threat Detection & Isolation Forest ML Telemetry Pipeline",
    version="3.4-e"
)

# Enable CORS for all origins so frontend connects seamlessly
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()

# Register Routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(threats_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
app.include_router(ai_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import HTTPException
import os

project_root = os.path.dirname(backend_dir)
frontend_dir = os.path.join(project_root, "frontend")

# Mount the frontend directory to serve static assets if any
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="frontend")

@app.get("/", tags=["Frontend"])
async def serve_frontend():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="Frontend index.html not found.")

@app.get("/health", tags=["Health"])
@app.get("/api/v1/status", response_model=SystemStatus, tags=["Health"])
async def get_system_status():
    uptime = int(time.time() - START_TIME)
    db_stats = get_db_stats()
    return SystemStatus(
        status="healthy",
        fastapi="Connected",
        isolation_forest="Ready" if detector.is_fitted else "Initializing",
        version="v3.4-e",
        active_threats=db_stats.get("threats", 0),
        active_incidents=db_stats.get("incidents", 0),
        model_contamination=detector.contamination,
        n_estimators=detector.n_estimators
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
