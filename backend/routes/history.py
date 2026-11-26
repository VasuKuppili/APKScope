import os
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database.connection import get_db
from backend.database.models import AnalysisRecord

router = APIRouter(tags=["History"])

@router.get("/api/history")
def get_analysis_history(
    q: Optional[str] = Query(None, description="Search by filename or SHA-256 hash"),
    mode: Optional[str] = Query(None, description="Filter by mode: passive or active"),
    classification: Optional[str] = Query(None, description="Filter by classification: Benign or Malicious"),
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(AnalysisRecord).filter(AnalysisRecord.status == "COMPLETED")

    if q:
        query = query.filter(
            (AnalysisRecord.filename.ilike(f"%{q}%")) |
            (AnalysisRecord.file_hash.ilike(f"%{q}%")) |
            (AnalysisRecord.malware_family.ilike(f"%{q}%"))
        )
    if mode:
        query = query.filter(AnalysisRecord.analysis_mode == mode)
    if classification:
        query = query.filter(AnalysisRecord.classification == classification)

    total = query.count()
    records = query.order_by(desc(AnalysisRecord.created_at)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "items": [r.to_dict() for r in records]
    }

@router.delete("/api/history/{job_id}")
def delete_analysis_record(job_id: str, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    # Safely remove associated APK binary if present
    if record.file_path and os.path.exists(record.file_path):
        try:
            os.remove(record.file_path)
        except Exception:
            pass

    db.delete(record)
    db.commit()

    return {"status": "success", "message": f"Record {job_id} deleted."}

@router.post("/api/history/clear")
def clear_analysis_history(db: Session = Depends(get_db)):
    records = db.query(AnalysisRecord).all()
    count = len(records)
    for r in records:
        if r.file_path and os.path.exists(r.file_path):
            try:
                os.remove(r.file_path)
            except Exception:
                pass
        db.delete(r)
    db.commit()

    return {"status": "success", "message": f"Cleared {count} analysis records and associated cache files."}

@router.get("/api/dashboard/stats")
def get_dashboard_statistics(db: Session = Depends(get_db)):
    completed = db.query(AnalysisRecord).filter(AnalysisRecord.status == "COMPLETED").all()
    
    total = len(completed)
    benign = sum(1 for r in completed if r.classification == "Benign")
    malicious = sum(1 for r in completed if r.classification == "Malicious")
    unknown = sum(1 for r in completed if r.classification not in ["Benign", "Malicious"])

    # Malware family frequency breakdown
    family_counts = {}
    for r in completed:
        if r.classification == "Malicious" and r.malware_family:
            family_counts[r.malware_family] = family_counts.get(r.malware_family, 0) + 1

    recent = db.query(AnalysisRecord).order_by(desc(AnalysisRecord.created_at)).limit(6).all()

    return {
        "total_analyses": total,
        "benign_samples": benign,
        "malicious_samples": malicious,
        "unknown_samples": unknown,
        "malware_family_distribution": family_counts,
        "recent_activity": [r.to_dict() for r in recent]
    }
