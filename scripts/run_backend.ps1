# scripts/run_backend.ps1
# Launches the CyberSentinel FastAPI backend on port 8000
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot\..

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "🛡️ Starting CyberSentinel Backend (FastAPI)" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

& .\venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
