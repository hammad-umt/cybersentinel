# Build the CyberSentinel desktop engine (FastAPI) for bundling with Flutter.
# Requires: Python 3.12 recommended, trained ML models in supervised_learning/

param(
    [string]$Python = "",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Backend = Join-Path $RepoRoot "cybersentinel-backend"
$DistPath = Join-Path $PSScriptRoot "dist"
$WorkPath = Join-Path $PSScriptRoot "build"
$DistDir = Join-Path $DistPath "CyberSentinelEngine"
$SupervisedModels = Join-Path $RepoRoot "supervised_learning\models"
$UnsupervisedModels = Join-Path $RepoRoot "unsupervised_learning\models"
$SpecFile = Join-Path $PSScriptRoot "cybersentinel_engine.spec"

if (-not $Python) {
    foreach ($candidate in @("py -3.12", "py -3.13", "python3.12", "python")) {
        $cmd = $candidate.Split(" ")[0]
        $args = @()
        if ($candidate -match " ") { $args = $candidate.Split(" ")[1..99] }
        try {
            & $cmd @args -c "import sys; print(sys.version)" 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $Python = $candidate
                break
            }
        } catch { }
    }
    if (-not $Python) { $Python = "python" }
}

function Stop-CyberSentinelProcesses {
    foreach ($name in @("cybersentinel_engine", "cybersentinel")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Remove-LockedPath {
    param(
        [string]$Path,
        [int]$Retries = 6
    )
    if (-not (Test-Path $Path)) { return }

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            Remove-Item $Path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ($attempt -eq $Retries) {
                throw "Could not remove locked path: $Path`nClose CyberSentinel, pause OneDrive sync, then retry."
            }
            Write-Host "    Path locked ($attempt/$Retries): $Path" -ForegroundColor Yellow
            Stop-CyberSentinelProcesses
            Start-Sleep -Seconds 3
        }
    }
}

function Invoke-Python {
    param([string[]]$Arguments)
    $parts = $Python.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
    $exe = $parts[0]
    $prefix = @()
    if ($parts.Length -gt 1) { $prefix = $parts[1..($parts.Length - 1)] }
    & $exe @prefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed ($Python $($Arguments -join ' '))"
    }
}

Write-Host "==> CyberSentinel engine build" -ForegroundColor Cyan
Write-Host "    Repo:   $RepoRoot"
Write-Host "    Python: $Python"

$ver = (Invoke-Python -Arguments @("-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")) -join ""
if ($ver -match "^3\.(1[4-9]|[2-9][0-9])") {
    Write-Warning "Python $ver detected. Use Python 3.12 if the frozen engine fails at runtime."
}

if (-not (Test-Path $SupervisedModels)) {
    Write-Warning "Missing $SupervisedModels — train supervised model first."
}
if (-not (Test-Path $UnsupervisedModels)) {
    Write-Warning "Missing $UnsupervisedModels — train unsupervised model first."
}

if (-not $SkipInstall) {
    Write-Host "==> Installing backend + build dependencies..."
    Invoke-Python -Arguments @("-m", "pip", "install", "--upgrade", "pip")
    Invoke-Python -Arguments @("-m", "pip", "install", "-r", (Join-Path $Backend "requirements.txt"))
    Invoke-Python -Arguments @("-m", "pip", "install", "-r", (Join-Path $RepoRoot "packaging\requirements-build.txt"))
}

Write-Host "==> Running PyInstaller (output: $DistDir)..."
Stop-CyberSentinelProcesses
Start-Sleep -Seconds 1

# Use a fresh work folder so a locked base_library.zip from a prior run cannot break --clean.
$workRun = Join-Path $WorkPath ("run_" + (Get-Date -Format "yyyyMMddHHmmss"))
Remove-LockedPath $workRun

Push-Location $PSScriptRoot
try {
    Invoke-Python -Arguments @(
        "-m", "PyInstaller", $SpecFile,
        "--noconfirm", "--clean",
        "--distpath", $DistPath,
        "--workpath", $workRun
    )
}
finally {
    Pop-Location
}

# Drop old PyInstaller work folders (keep the folder that just succeeded).
Get-ChildItem $WorkPath -Directory -Filter "run_*" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $workRun } |
    ForEach-Object { Remove-LockedPath $_.FullName }
Remove-LockedPath (Join-Path $WorkPath "cybersentinel_engine")

# Legacy fallback when an older script wrote to cybersentinel-backend\dist
$legacyDist = Join-Path $Backend "dist\CyberSentinelEngine"
if (-not (Test-Path $DistDir) -and (Test-Path $legacyDist)) {
    Write-Host "==> Found legacy build at $legacyDist — copying to $DistDir"
    Copy-Item -Path $legacyDist -Destination $DistDir -Recurse -Force
}

if (-not (Test-Path (Join-Path $DistDir "cybersentinel_engine.exe"))) {
    throw "Build failed — cybersentinel_engine.exe not found in $DistDir"
}

Write-Host "==> Copying ML models next to engine executable..."
$destSupervised = Join-Path $DistDir "supervised_learning"
$destUnsupervised = Join-Path $DistDir "unsupervised_learning"
$modelsDest = Join-Path $destSupervised "models"
New-Item -ItemType Directory -Force -Path $modelsDest | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $destUnsupervised "models") | Out-Null

if (Test-Path $SupervisedModels) {
    Copy-Item -Path (Join-Path $SupervisedModels "*") -Destination $modelsDest -Recurse -Force
}
if (Test-Path (Join-Path $RepoRoot "supervised_learning\model.py")) {
    Copy-Item -Path (Join-Path $RepoRoot "supervised_learning\model.py") -Destination $destSupervised -Force
}
if (Test-Path $UnsupervisedModels) {
    Copy-Item -Path (Join-Path $UnsupervisedModels "*") -Destination (Join-Path $destUnsupervised "models") -Recurse -Force
}
Get-ChildItem (Join-Path $RepoRoot "unsupervised_learning") -Filter "*.py" | ForEach-Object {
    Copy-Item $_.FullName -Destination $destUnsupervised -Force
}

$engineEnv = Join-Path $DistDir "engine.env"
if (-not (Test-Path $engineEnv)) {
    Copy-Item (Join-Path $PSScriptRoot "engine.env.example") $engineEnv
    Write-Warning "Created $engineEnv from example — edit DATABASE_URL and JWT_SECRET_KEY before shipping."
}

Write-Host ""
Write-Host "==> Build complete:" -ForegroundColor Green
Write-Host "    $DistDir\cybersentinel_engine.exe"
