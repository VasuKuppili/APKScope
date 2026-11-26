import os
from fastapi import APIRouter
from backend.database.connection import engine

router = APIRouter(tags=["Health"])

@router.get("/api/health")
def check_health():
    db_healthy = False
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
            db_healthy = True
    except Exception:
        # SQLite or other DB check fallback
        try:
            with engine.connect() as conn:
                from sqlalchemy import text
                conn.execute(text("SELECT 1"))
                db_healthy = True
        except Exception as e:
            db_healthy = False

    model_present = os.path.exists("backend/models/malware_classifier.joblib")
    features_present = os.path.exists("backend/models/feature_names.json")

    return {
        "status": "online" if db_healthy else "degraded",
        "database": "connected" if db_healthy else "disconnected",
        "classifier_model": "loaded" if (model_present and features_present) else "missing",
        "gemini_api_configured": bool(os.getenv("GEMINI_API_KEY"))
    }
