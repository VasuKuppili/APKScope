import os
from dotenv import load_dotenv

# Load environment configuration before importing modules
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database.connection import init_db

# Import routers
from backend.routes.health import router as health_router
from backend.routes.upload import router as upload_router
from backend.routes.passive import router as passive_router
from backend.routes.active import router as active_router
from backend.routes.jobs import router as jobs_router
from backend.routes.results import router as results_router
from backend.routes.history import router as history_router
from backend.routes.threat_intelligence import router as threat_intel_router
from backend.routes.gemini import router as gemini_router
from backend.routes.reports import router as reports_router

# Initialize database schema
init_db()

app = FastAPI(
    title="Android Malware Family Classification API",
    description="Explainable AI-based Android Malware Family Classification with STIX/TAXII Threat Intelligence Sharing",
    version="1.0.0"
)

# CORS setup for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(health_router)
app.include_router(upload_router)
app.include_router(passive_router)
app.include_router(active_router)
app.include_router(jobs_router)
app.include_router(results_router)
app.include_router(history_router)
app.include_router(threat_intel_router)
app.include_router(gemini_router)
app.include_router(reports_router)

# Mount frontend production build if present
frontend_dist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")
if os.path.exists(frontend_dist):
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def serve_react_app(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api"):
            return {"error": "API route not found"}
        target_file = os.path.join(frontend_dist, full_path)
        if os.path.exists(target_file) and os.path.isfile(target_file):
            return FileResponse(target_file)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "message": "Android Malware Family Classification API is running",
            "documentation": "/docs",
            "version": "1.0.0"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
