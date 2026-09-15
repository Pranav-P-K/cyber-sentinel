# scripts/run_frontend.ps1
# Launches the CyberSentinel Streamlit dashboard on port 8501
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot\..

Write-Host "=================================================" -ForegroundColor Green
Write-Host "🛡️ Starting CyberSentinel Dashboard (Streamlit)" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green

& .\venv\Scripts\streamlit.exe run frontend/pages/dashboard.py --server.port 8501
