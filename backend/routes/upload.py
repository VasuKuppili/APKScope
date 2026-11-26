import os
import uuid
import aiofiles
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import AnalysisRecord
from backend.services.apk_validation import validate_apk_file, APKValidationError
from backend.services.hash_service import calculate_sha256

router = APIRouter(tags=["Upload"])
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "backend/uploads")

@router.post("/api/upload")
async def upload_apk(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    original_filename = file.filename
    if not original_filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Invalid file type. File must have an .apk extension.")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_id = str(uuid.uuid4())
    stored_filename = f"{file_id}_{original_filename}"
    file_path = os.path.join(UPLOAD_DIR, stored_filename)

    # Save stream safely to disk
    try:
        async with aiofiles.open(file_path, "wb") as out_file:
            while chunk := await file.read(1024 * 64):
                await out_file.write(chunk)
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")

    # Validate file integrity
    try:
        val_result = validate_apk_file(file_path, original_filename)
    except APKValidationError as val_err:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=422, detail=str(val_err))

    # Calculate SHA-256
    file_hash = calculate_sha256(file_path)
    file_size = val_result["file_size"]

    # Check for duplicate in history
    existing = db.query(AnalysisRecord).filter(
        AnalysisRecord.file_hash == file_hash,
        AnalysisRecord.status == "COMPLETED"
    ).order_by(AnalysisRecord.created_at.desc()).first()

    # Create new analysis job record
    job_record = AnalysisRecord(
        id=file_id,
        filename=original_filename,
        file_hash=file_hash,
        file_size=file_size,
        file_path=file_path,
        analysis_mode="pending",
        status="QUEUED",
        progress=0,
        status_message="File validated and ready for analysis."
    )
    db.add(job_record)
    db.commit()

    return {
        "job_id": file_id,
        "filename": original_filename,
        "file_hash": file_hash,
        "sha256": file_hash,
        "file_size": file_size,
        "has_dex": val_result["has_dex"],
        "is_duplicate": existing is not None,
        "existing_analysis_id": existing.id if existing else None
    }
