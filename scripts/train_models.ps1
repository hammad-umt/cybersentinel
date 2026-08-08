# Train CyberSentinel ML models (XGBoost + Isolation Forest)
# Run from repo root: .\scripts\train_models.ps1

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$BackendVenv = Join-Path $RepoRoot "cybersentinel-backend\venv\Scripts\python.exe"
$Python = if (Test-Path $BackendVenv) { $BackendVenv } else { "python" }

Write-Host "CyberSentinel model training" -ForegroundColor Cyan
Write-Host "  Repo:   $RepoRoot"
Write-Host "  Python: $Python"

& $Python (Join-Path $RepoRoot "scripts\train_models.py") @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nModels ready in supervised_learning\models\" -ForegroundColor Green
