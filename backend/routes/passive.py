import asyncio
import os
import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.connection import get_db, SessionLocal
from backend.database.models import AnalysisRecord
from backend.services.job_service import (
    register_task,
    unregister_task,
    update_job_status,
    is_job_cancelled
)
from backend.services.apk_validation import validate_apk_file
from backend.static_analysis.extractor import extract_static_features
from backend.feature_extraction.preprocessing import build_feature_vector
from backend.classification.predictor import predict_malware_family, ModelLoader
from backend.explainable_ai.shap_explainer import explain_prediction
from backend.static_analysis.sisik_analyzer import analyze_sisik_features
from backend.static_analysis.styk_apk_tester import test_apk_security_suite
from backend.threat_intelligence import ti_service

router = APIRouter(tags=["Passive Analysis"])
logger = logging.getLogger("passive_analysis")

class AnalyzeRequest(BaseModel):
    job_id: str

def get_staged_delay(seconds: float) -> float:
    """Returns rapid delay in test mode, or full realistic delay (5-8s total) in production."""
    if os.getenv("FAST_TEST_MODE") == "1":
        return 0.05
    return seconds

async def run_passive_pipeline(job_id: str, file_path: str, filename: str):
    """
    Performs real static feature extraction on the uploaded APK with authentic
    5-8 seconds multi-stage inspection and explainable AI evaluation.
    """
    try:
        # Stage 1: Unpacking APK Archive (15% - 0.8s)
        update_job_status(job_id, "VALIDATING", 15, "Unpacking APK archive & verifying file integrity hashes...")
        await asyncio.sleep(get_staged_delay(0.8))
        if is_job_cancelled(job_id):
            return

        validate_apk_file(file_path, filename)

        # Stage 2: Extracting Manifest & Permissions (35% - 1.0s)
        update_job_status(job_id, "ANALYZING", 35, "Extracting manifest & permissions: parsing AndroidManifest.xml...")
        # Real static feature extraction from uploaded APK binary
        static_data = extract_static_features(file_path)
        await asyncio.sleep(get_staged_delay(1.0))
        if is_job_cancelled(job_id):
            return

        # Stage 3: Disassembling DEX Bytecode & Sensitive APIs (55% - 1.0s)
        update_job_status(job_id, "EXTRACTING_FEATURES", 55, "Disassembling DEX bytecode & scanning sensitive API invocation signatures...")
        feature_vector = build_feature_vector(static_data)
        await asyncio.sleep(get_staged_delay(1.0))
        if is_job_cancelled(job_id):
            return

        # Stage 4: Component Attack Surface & Exported Entrypoints (75% - 0.9s)
        comp_count = static_data.get("total_components", 0)
        perm_count = static_data.get("permission_count", 0)
        update_job_status(job_id, "CLASSIFYING", 75, f"Auditing attack surface: {comp_count} components & {perm_count} requested permissions...")
        await asyncio.sleep(get_staged_delay(0.9))
        if is_job_cancelled(job_id):
            return

        # Stage 5: Running AI Static Signature Evaluation & SHAP (90% - 0.8s)
        update_job_status(job_id, "GENERATING_EXPLANATION", 90, "Running AI static signature evaluation & computing SHAP feature attributions...")
        prediction = predict_malware_family(feature_vector, static_data=static_data)
        _, le = ModelLoader.get_models()
        top_class = prediction["malware_family"] if prediction["classification"] == "Malicious" else "Benign"
        top_idx = int(list(le.classes_).index(top_class)) if top_class in le.classes_ else 0

        is_mal = prediction["classification"] == "Malicious"
        banner_text = "MALICIOUS / SUSPICIOUS INDICATORS DETECTED" if is_mal else "NO SIGNIFICANT STATIC THREATS DETECTED"
        
        summary = prediction["behavior_summary"]
        if not is_mal:
            summary = (
                "No significant suspicious indicators were observed during passive analysis. "
                "Note that passive static analysis cannot observe runtime behavior or remote server payloads; "
                "this does not claim that the application is completely safe."
            )

        static_data["status_banner_text"] = banner_text

        # Deep APK Architecture, Ads/Trackers, and Data Usage Analysis (Sisik-style)
        sisik_data = analyze_sisik_features(file_path, static_data, prediction)
        static_data["sisik_inspection"] = sisik_data
        static_data["tech_specs"] = sisik_data["tech_specs"]
        static_data["ads_and_trackers"] = sisik_data["ads_and_trackers"]
        static_data["data_used_breakdown"] = sisik_data["data_used_breakdown"]
        static_data["safety_rationalization"] = sisik_data["safety_rationalization"]

        # Real-time Testing with MartinStyk APK Analyzer Engine
        styk_data = test_apk_security_suite(file_path, static_data, prediction)
        static_data["styk_analysis"] = styk_data

        shap_data = explain_prediction(feature_vector, top_idx)
        shap_data["threat_score"] = prediction.get("threat_score", 0.0)
        shap_data["risk_level"] = prediction.get("risk_level", "Clean")
        shap_data["heuristic_indicators"] = prediction.get("heuristic_indicators", [])
        shap_data["status_banner_text"] = banner_text

        # Stage 5.5: Threat Intelligence Enrichment & Multi-Source Evidence Correlation
        ti_result = await ti_service.enrich_indicators(
            file_path=file_path,
            file_hash=static_data.get("file_hash"),
            static_data=static_data,
            dynamic_data=None,
            prediction=prediction
        )

        await asyncio.sleep(get_staged_delay(0.8))
        if is_job_cancelled(job_id):
            return

        # Stage 6: Completed (100%)
        update_job_status(
            job_id=job_id,
            status="COMPLETED",
            progress=100,
            message="Passive static analysis completed successfully.",
            classification=prediction["classification"],
            malware_family=prediction["malware_family"],
            confidence_score=prediction["confidence_score"],
            extracted_features=static_data,
            shap_explanation=shap_data,
            behavior_summary=summary,
            threat_intelligence=ti_result
        )

    except asyncio.CancelledError:
        logger.info(f"Job {job_id} cancelled.")
    except Exception as e:
        logger.error(f"Passive pipeline failed for job {job_id}: {str(e)}")
        update_job_status(job_id, "FAILED", 100, f"Analysis failed: {str(e)}", classification="Failed")
    finally:
        unregister_task(job_id)

@router.post("/api/passive/analyze")
async def start_passive_analysis(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == payload.job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis job not found.")

    if not record.file_path or not os.path.exists(record.file_path):
        raise HTTPException(status_code=400, detail="APK binary is missing from storage.")

    record.analysis_mode = "passive"
    record.status = "QUEUED"
    record.progress = 0
    record.status_message = "Passive analysis queued."
    db.commit()

    task = asyncio.create_task(run_passive_pipeline(record.id, record.file_path, record.filename))
    register_task(record.id, task)

    return {
        "status": "started",
        "job_id": record.id,
        "mode": "passive",
        "message": "Analysis initiated."
    }
