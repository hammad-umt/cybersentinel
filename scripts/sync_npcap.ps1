# Copies Npcap installer into the Flutter project for dev/release builds.
# Run download_npcap.ps1 in cybersentinel first if deps folder is empty.

$ErrorActionPreference = "Stop"
$FlutterRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendRepo = "C:\Users\hamma\OneDrive\Desktop\cybersentinel"
$Source = Join-Path $BackendRepo "packaging\windows\deps\npcap-installer.exe"
$DestDir = Join-Path $FlutterRoot "windows\runner\deps"
$Dest = Join-Path $DestDir "npcap-installer.exe"

if (-not (Test-Path $Source)) {
    Write-Host "Npcap installer not found. Downloading..." -ForegroundColor Yellow
    & (Join-Path $BackendRepo "packaging\windows\download_npcap.ps1") -FlutterRoot $FlutterRoot
}

if (-not (Test-Path $Source)) {
    throw "Missing $Source — run packaging\windows\download_npcap.ps1"
}

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Copy-Item $Source $Dest -Force
Write-Host "Npcap installer ready at $Dest" -ForegroundColor Green
