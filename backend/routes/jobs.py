from fastapi import APIRouter, HTTPException
from backend.services.job_service import get_job, cancel_job

router = APIRouter(tags=["Jobs"])

@router.get("/api/jobs/{job_id}")
def get_job_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    return job

@router.post("/api/jobs/{job_id}/cancel")
def cancel_job_endpoint(job_id: str):
    success = cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=400, detail="Job could not be cancelled (it may have already completed, failed, or does not exist).")
    return {"status": "success", "message": f"Job {job_id} cancelled."}
