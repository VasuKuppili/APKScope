# Launch Full-Stack Android Malware Classifier (FastAPI + React SPA)
Set-Location -Path $PSScriptRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Starting Android Malware Family Classification Platform" -ForegroundColor Cyan
Write-Host " Dashboard URL: http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan

Start-Process "http://127.0.0.1:8000"
& "$PSScriptRoot\backend\venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
