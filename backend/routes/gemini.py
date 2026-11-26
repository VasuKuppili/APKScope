import os
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from google import genai

from backend.database.connection import get_db
from backend.database.models import AnalysisRecord

router = APIRouter(tags=["Gemini"])

class GeminiKeyUpdate(BaseModel):
    api_key: str
    model_name: str = "gemini-2.5-flash"

@router.post("/api/results/{job_id}/gemini-explanation")
def generate_gemini_explanation(job_id: str, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    if record.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="Cannot generate explanation for an incomplete analysis.")

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Gemini API Key is not configured. Please add your key in Settings."
        )

    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    rec_dict = record.to_dict()
    shap_data = rec_dict.get("shap_explanation") or {}
    top_features = shap_data.get("top_features", [])

    prompt = f"""
Explain the following Android malware analysis in simple, objective technical language for a security analyst.

Analysis Metadata:
- File Name: {record.filename}
- SHA-256 Hash: {record.file_hash}
- Analysis Mode: {record.analysis_mode.upper()}
- ML Classification: {record.classification}
- Predicted Malware Family: {record.malware_family}
- Model Confidence: {record.confidence_score}%

Key Explanatory Features (from SHAP Feature Attribution):
{top_features}

Instructions:
1. Explain what these features indicate and why they contributed to the prediction.
2. Do not change the classification or predicted family.
3. Do not invent unobserved evidence.
4. Keep the explanation under 250 words, structured with clear bullet points.
"""

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=prompt
        )
        explanation_text = response.text

        record.gemini_explanation = explanation_text
        db.commit()

        return {
            "job_id": job_id,
            "gemini_explanation": explanation_text
        }
    except Exception as e:
        error_msg = str(e)
        if "quota" in error_msg.lower() or "resourceexhausted" in error_msg.lower():
            raise HTTPException(status_code=429, detail="Gemini API quota exhausted. Try again later or use a different key.")
        raise HTTPException(status_code=502, detail=f"Gemini API error: {error_msg}")

@router.post("/api/settings/gemini/test")
def test_gemini_connection(payload: GeminiKeyUpdate = None):
    api_key = payload.api_key if payload and payload.api_key else os.getenv("GEMINI_API_KEY")
    model_name = payload.model_name if payload and payload.model_name else os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    if not api_key:
        raise HTTPException(status_code=400, detail="No Gemini API Key provided to test.")

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents="Respond with 'API_CONNECTED_SUCCESSFULLY' if you receive this ping."
        )
        if "API_CONNECTED_SUCCESSFULLY" in response.text or len(response.text) > 0:
            return {"status": "success", "message": f"Connection established with {model_name}."}
        return {"status": "warning", "message": "Unexpected response received from model."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Gemini test failed: {str(e)}")
