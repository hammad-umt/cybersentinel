# Copies VC++ redistributable into Flutter release deps (bundled by Inno Setup).
$ErrorActionPreference = "Stop"
$FlutterRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendRepo = "C:\Users\hamma\OneDrive\Desktop\cybersentinel"
$Source = Join-Path $BackendRepo "packaging\windows\deps\vc_redist.x64.exe"
$DestDir = Join-Path $FlutterRoot "windows\runner\deps"
$Dest = Join-Path $DestDir "vc_redist.x64.exe"

if ((Test-Path $Dest) -and (Get-Item $Dest).Length -gt 1MB) {
    Write-Host "VC++ redist already present at $Dest" -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $Source)) {
    Write-Host "VC++ redist not found. Downloading..." -ForegroundColor Yellow
    & (Join-Path $BackendRepo "packaging\windows\download_vcredist.ps1")
}

if (-not (Test-Path $Source)) {
    throw "Missing $Source"
}

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
        Copy-Item $Source $Dest -Force -ErrorAction Stop
        break
    } catch {
        if ($attempt -eq 5) { throw }
        Start-Sleep -Seconds 2
    }
}
Write-Host "VC++ redist ready at $Dest" -ForegroundColor Green
