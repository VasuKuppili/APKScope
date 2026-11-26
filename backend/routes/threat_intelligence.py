import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from taxii2client.v21 import Server, Collection

from backend.database.connection import get_db
from backend.database.models import AnalysisRecord, TaxiiConfig, ThreatIntelRecord
from backend.threat_intelligence.stix_generator import generate_stix_bundle

router = APIRouter(tags=["Threat Intelligence"])

class TaxiiConfigPayload(BaseModel):
    server_url: str
    collection_id: str = None
    username: str = None
    password: str = None
    use_https: bool = True

class TaxiiSharePayload(BaseModel):
    job_id: str

@router.get("/api/results/{job_id}/stix")
def export_stix_bundle(job_id: str, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    if record.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="Cannot export STIX for an incomplete analysis.")

    bundle = generate_stix_bundle(record.to_dict())
    return bundle

@router.get("/api/results/{job_id}/threat-intelligence")
def get_threat_intelligence_correlation(job_id: str, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    ti_rec = db.query(ThreatIntelRecord).filter(ThreatIntelRecord.analysis_id == job_id).first()
    if ti_rec:
        return {
            "job_id": job_id,
            "status": "COMPLETED" if record.status == "COMPLETED" else record.status,
            **ti_rec.to_dict()
        }

    # Fallback to AnalysisRecord.threat_intelligence if present
    data = record.to_dict()
    ti_data = data.get("threat_intelligence")
    if ti_data:
        return {
            "job_id": job_id,
            "status": record.status,
            **ti_data
        }

    return {
        "job_id": job_id,
        "status": record.status,
        "intelligence_match_status": "No external threat intelligence recorded",
        "hash_reputation": "Unobserved / Neutral",
        "domain_reputation": "Neutral",
        "ip_reputation": "Neutral",
        "malware_association": "None",
        "threat_confidence": 0.0,
        "correlated_evidence": []
    }

@router.get("/api/taxii/config")
def get_taxii_configuration(db: Session = Depends(get_db)):
    config = db.query(TaxiiConfig).first()
    if not config:
        return {
            "configured": False,
            "server_url": "",
            "collection_id": "",
            "username": "",
            "status": "DISCONNECTED"
        }
    return {
        "configured": True,
        **config.to_dict()
    }

@router.post("/api/taxii/config")
def save_taxii_configuration(payload: TaxiiConfigPayload, db: Session = Depends(get_db)):
    config = db.query(TaxiiConfig).first()
    if not config:
        config = TaxiiConfig()
        db.add(config)

    config.server_url = payload.server_url
    config.collection_id = payload.collection_id
    config.username = payload.username
    config.password = payload.password
    config.use_https = payload.use_https
    config.status = "DISCONNECTED"
    config.status_message = "Configuration saved. Ready for connection test."
    db.commit()

    return {"status": "success", "message": "TAXII configuration saved."}

@router.post("/api/taxii/test")
def test_taxii_connection(db: Session = Depends(get_db)):
    config = db.query(TaxiiConfig).first()
    if not config or not config.server_url:
        raise HTTPException(status_code=400, detail="No TAXII server configured. Please configure server URL first.")

    try:
        auth_user = config.username if config.username else None
        auth_pass = config.password if config.password else None
        server = Server(config.server_url, user=auth_user, password=auth_pass)
        
        # Probe api roots
        api_roots = server.api_roots
        root_count = len(api_roots) if api_roots else 0

        config.status = "CONNECTED"
        config.status_message = f"Connected successfully. Detected {root_count} API Root(s)."
        config.last_tested_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "status": "success",
            "message": config.status_message,
            "api_roots_count": root_count
        }
    except Exception as e:
        config.status = "ERROR"
        config.status_message = f"Connection failed: {str(e)}"
        config.last_tested_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=502, detail=f"TAXII Server connection failed: {str(e)}")

@router.post("/api/taxii/share")
def share_intelligence(payload: TaxiiSharePayload, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == payload.job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    config = db.query(TaxiiConfig).first()
    if not config or not config.server_url:
        raise HTTPException(status_code=400, detail="TAXII server is not configured. Go to Threat Intelligence to set up TAXII.")

    if not config.collection_id:
        raise HTTPException(status_code=400, detail="No TAXII Collection ID specified in configuration.")

    bundle = generate_stix_bundle(record.to_dict())

    try:
        auth_user = config.username if config.username else None
        auth_pass = config.password if config.password else None
        
        collection_url = f"{config.server_url.rstrip('/')}/collections/{config.collection_id}/"
        collection = Collection(collection_url, user=auth_user, password=auth_pass)
        collection.add_objects(bundle)

        return {
            "status": "success",
            "message": f"Successfully transmitted STIX 2.1 threat intelligence bundle for {record.filename} to TAXII collection {config.collection_id}."
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"TAXII sharing failed: {str(e)}")
