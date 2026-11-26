import os
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.models import AnalysisRecord

router = APIRouter(tags=["Results"])

@router.get("/api/results/{job_id}")
def get_analysis_results(job_id: str, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    res = record.to_dict()
    if record.status != "COMPLETED":
        return {
            "id": record.id,
            "status": record.status,
            "progress": record.progress,
            "status_message": record.status_message,
            "is_complete": False
        }

    ext = res.get("extracted_features") or {}
    sisik_data = ext.get("sisik_inspection")
    if not sisik_data and record.file_path and os.path.exists(record.file_path):
        try:
            from backend.static_analysis.sisik_analyzer import analyze_sisik_features
            sisik_data = analyze_sisik_features(
                record.file_path, 
                ext, 
                {"classification": record.classification, "malware_family": record.malware_family}
            )
            ext["sisik_inspection"] = sisik_data
            ext["tech_specs"] = sisik_data["tech_specs"]
            ext["ads_and_trackers"] = sisik_data["ads_and_trackers"]
            ext["data_used_breakdown"] = sisik_data["data_used_breakdown"]
            ext["safety_rationalization"] = sisik_data["safety_rationalization"]
        except Exception:
            pass

    if sisik_data:
        res["tech_specs"] = sisik_data.get("tech_specs")
        res["ads_and_trackers"] = sisik_data.get("ads_and_trackers")
        res["data_used_breakdown"] = sisik_data.get("data_used_breakdown")
        res["safety_rationalization"] = sisik_data.get("safety_rationalization")

    styk_data = ext.get("styk_analysis")
    if not styk_data and record.file_path and os.path.exists(record.file_path):
        try:
            from backend.static_analysis.styk_apk_tester import test_apk_security_suite
            styk_data = test_apk_security_suite(
                record.file_path,
                ext,
                {"classification": record.classification, "malware_family": record.malware_family}
            )
            ext["styk_analysis"] = styk_data
        except Exception:
            pass

    if styk_data:
        res["styk_analysis"] = styk_data

    return {
        **res,
        "is_complete": True
    }

@router.get("/api/results/{job_id}/explanation")
def get_shap_explanation(job_id: str, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    
    data = record.to_dict()
    if not data.get("shap_explanation"):
        raise HTTPException(status_code=404, detail="SHAP explanation not available for this record.")

    return {
        "job_id": job_id,
        "classification": record.classification,
        "malware_family": record.malware_family,
        "confidence_score": record.confidence_score,
        "shap": data["shap_explanation"]
    }
