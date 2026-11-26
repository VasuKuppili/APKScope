@echo off
cd /d "%~dp0"
echo ======================================================================
echo  Starting Android Malware Family Classification Platform (Full Stack)
echo ======================================================================
echo URL: http://127.0.0.1:8000
echo.
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:8000"
backend\venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
pause
