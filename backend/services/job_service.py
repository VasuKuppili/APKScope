import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from backend.database.connection import SessionLocal
from backend.database.models import AnalysisRecord, ThreatIntelRecord

logger = logging.getLogger("job_service")

# In-memory tracking for running tasks to allow clean cooperative cancellation
active_tasks: Dict[str, asyncio.Task] = {}
cancellation_flags: Dict[str, bool] = {}

def get_job(job_id: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        if record:
            return record.to_dict()
        return None
    finally:
        db.close()

def update_job_status(
    job_id: str,
    status: str,
    progress: int,
    message: str,
    classification: Optional[str] = None,
    malware_family: Optional[str] = None,
    confidence_score: Optional[float] = None,
    extracted_features: Optional[dict] = None,
    shap_explanation: Optional[dict] = None,
    behavior_summary: Optional[str] = None,
    threat_intelligence: Optional[dict] = None
):
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        if record:
            record.status = status
            record.progress = progress
            record.status_message = message
            
            if classification is not None:
                record.classification = classification
            if malware_family is not None:
                record.malware_family = malware_family
            if confidence_score is not None:
                record.confidence_score = confidence_score
            if extracted_features is not None:
                record.extracted_features = json.dumps(extracted_features)
            if shap_explanation is not None:
                record.shap_explanation = json.dumps(shap_explanation)
            if behavior_summary is not None:
                record.behavior_summary = behavior_summary
            if threat_intelligence is not None:
                pub = threat_intelligence.get("public", threat_intelligence)
                record.threat_intelligence = json.dumps(pub)

                # Also insert or update ThreatIntelRecord
                try:
                    ti_rec = db.query(ThreatIntelRecord).filter(ThreatIntelRecord.analysis_id == job_id).first()
                    if not ti_rec:
                        ti_rec = ThreatIntelRecord(
                            analysis_id=job_id,
                            file_hash=record.file_hash
                        )
                        db.add(ti_rec)

                    ti_rec.match_status = pub.get("intelligence_match_status", "No Known Threat Indicators Identified")
                    ti_rec.hash_reputation = pub.get("hash_reputation")
                    ti_rec.domain_reputation = pub.get("domain_reputation")
                    ti_rec.ip_reputation = pub.get("ip_reputation")
                    ti_rec.malware_association = pub.get("malware_association")
                    ti_rec.threat_confidence = pub.get("threat_confidence", 0.0)
                    ti_rec.composite_threat_score = pub.get("composite_threat_score", 0.0)
                    ti_rec.risk_tier = pub.get("risk_tier", "Clean")
                    ti_rec.correlated_evidence = json.dumps(pub.get("correlated_evidence", []))
                    ti_rec.audit_provenance = json.dumps(threat_intelligence.get("audit", {}))
                except Exception as tie:
                    logger.warning(f"Could not write ThreatIntelRecord for {job_id}: {tie}")
                
            if status in ["COMPLETED", "FAILED", "CANCELLED"]:
                record.completed_at = datetime.now(timezone.utc)
                
            db.commit()
    except Exception as e:
        logger.error(f"Failed to update job {job_id} in DB: {e}")
        db.rollback()
    finally:
        db.close()

def is_job_cancelled(job_id: str) -> bool:
    return cancellation_flags.get(job_id, False)

def cancel_job(job_id: str) -> bool:
    cancellation_flags[job_id] = True
    task = active_tasks.get(job_id)
    if task and not task.done():
        task.cancel()
        update_job_status(job_id, "CANCELLED", 100, "Analysis was cancelled by analyst.")
        return True
    
    # Check if job is still queued in DB
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        if record and record.status not in ["COMPLETED", "FAILED", "CANCELLED"]:
            record.status = "CANCELLED"
            record.status_message = "Analysis cancelled before execution."
            record.completed_at = datetime.now(timezone.utc)
            db.commit()
            return True
        return False
    finally:
        db.close()

def register_task(job_id: str, task: asyncio.Task):
    active_tasks[job_id] = task
    cancellation_flags[job_id] = False

def unregister_task(job_id: str):
    active_tasks.pop(job_id, None)
    cancellation_flags.pop(job_id, None)
