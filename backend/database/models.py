import json
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, Boolean, DateTime
from backend.database.connection import Base

class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), index=True, nullable=False)  # SHA-256
    file_size = Column(Integer, nullable=False)  # In bytes
    file_path = Column(String(512), nullable=True)
    analysis_mode = Column(String(32), default="passive")  # "passive" or "active"
    status = Column(String(32), default="QUEUED", index=True)
    progress = Column(Integer, default=0)
    status_message = Column(String(255), default="Job queued")
    
    # Classification results
    classification = Column(String(32), nullable=True)  # "Benign", "Malicious", "Unknown", "Failed"
    malware_family = Column(String(64), nullable=True)  # e.g., "Trojan.Banker", "Ransomware"
    confidence_score = Column(Float, nullable=True)  # Percentage, e.g., 97.2
    model_version = Column(String(32), default="1.0.0")
    behavior_summary = Column(Text, nullable=True)

    # Detailed payloads stored as serialized JSON
    extracted_features = Column(Text, nullable=True)
    shap_explanation = Column(Text, nullable=True)
    gemini_explanation = Column(Text, nullable=True)
    threat_intelligence = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "file_path": self.file_path,
            "analysis_mode": self.analysis_mode,
            "status": self.status,
            "progress": self.progress,
            "status_message": self.status_message,
            "classification": self.classification,
            "malware_family": self.malware_family,
            "confidence_score": self.confidence_score,
            "model_version": self.model_version,
            "behavior_summary": self.behavior_summary,
            "extracted_features": json.loads(self.extracted_features) if self.extracted_features else None,
            "shap_explanation": json.loads(self.shap_explanation) if self.shap_explanation else None,
            "gemini_explanation": self.gemini_explanation,
            "threat_intelligence": json.loads(self.threat_intelligence) if self.threat_intelligence else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

class TaxiiConfig(Base):
    __tablename__ = "taxii_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_url = Column(String(512), nullable=False)
    collection_id = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    use_https = Column(Boolean, default=True)
    last_tested_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="DISCONNECTED")  # "CONNECTED", "DISCONNECTED", "ERROR"
    status_message = Column(String(255), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "server_url": self.server_url,
            "collection_id": self.collection_id,
            "username": self.username,
            "use_https": self.use_https,
            "last_tested_at": self.last_tested_at.isoformat() if self.last_tested_at else None,
            "status": self.status,
            "status_message": self.status_message,
        }

class ThreatIntelRecord(Base):
    __tablename__ = "threat_intel_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), index=True, nullable=False)
    file_hash = Column(String(64), index=True, nullable=False)
    match_status = Column(String(128), default="No Known Threat Indicators Identified")
    hash_reputation = Column(String(128), nullable=True)
    domain_reputation = Column(String(128), nullable=True)
    ip_reputation = Column(String(128), nullable=True)
    malware_association = Column(String(128), nullable=True)
    threat_confidence = Column(Float, default=0.0)
    composite_threat_score = Column(Float, default=0.0)
    risk_tier = Column(String(32), default="Clean")
    correlated_evidence = Column(Text, nullable=True)  # Serialized JSON
    audit_provenance = Column(Text, nullable=True)     # Serialized JSON
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "analysis_id": self.analysis_id,
            "file_hash": self.file_hash,
            "match_status": self.match_status,
            "hash_reputation": self.hash_reputation,
            "domain_reputation": self.domain_reputation,
            "ip_reputation": self.ip_reputation,
            "malware_association": self.malware_association,
            "threat_confidence": self.threat_confidence,
            "composite_threat_score": self.composite_threat_score,
            "risk_tier": self.risk_tier,
            "correlated_evidence": json.loads(self.correlated_evidence) if self.correlated_evidence else [],
            "audit_provenance": json.loads(self.audit_provenance) if self.audit_provenance else {},
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
