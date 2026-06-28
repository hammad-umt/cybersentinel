# Download Microsoft VC++ 2015-2022 x64 redistributable (required by PyInstaller engine on clean PCs).
param(
    [string]$DestDir = (Join-Path $PSScriptRoot "deps")
)

$ErrorActionPreference = "Stop"
$Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$Dest = Join-Path $DestDir "vc_redist.x64.exe"

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null

if ((Test-Path $Dest) -and (Get-Item $Dest).Length -gt 1MB) {
    Write-Host "VC++ redist already present: $Dest" -ForegroundColor Green
    exit 0
}

Write-Host "Downloading VC++ 2015-2022 x64 redistributable..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing

if (-not (Test-Path $Dest) -or (Get-Item $Dest).Length -lt 1MB) {
    throw "Download failed or file too small: $Dest"
}

Write-Host "Saved: $Dest ($([math]::Round((Get-Item $Dest).Length / 1MB, 1)) MB)" -ForegroundColor Green
