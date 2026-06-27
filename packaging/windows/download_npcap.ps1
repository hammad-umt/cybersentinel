# Downloads the official Npcap installer for bundling with CyberSentinel.
# Output: packaging/windows/deps/npcap-installer.exe
#         (also copied to Flutter windows/runner/deps/ by sync_npcap.ps1)

param(
    [string]$Version = "1.82",
    [string]$FlutterRoot = "C:\Users\hamma\OneDrive\Desktop\New folder"
)

$ErrorActionPreference = "Stop"
$DepsDir = Join-Path $PSScriptRoot "deps"
$OutFile = Join-Path $DepsDir "npcap-installer.exe"
$Url = "https://npcap.com/dist/npcap-$Version.exe"

New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null

Write-Host "==> Downloading Npcap $Version from $Url" -ForegroundColor Cyan
Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing

if (-not (Test-Path $OutFile)) {
    throw "Download failed — file not created: $OutFile"
}

$sizeMb = [math]::Round((Get-Item $OutFile).Length / 1MB, 1)
Write-Host "==> Saved $OutFile ($sizeMb MB)" -ForegroundColor Green

$flutterDeps = Join-Path $FlutterRoot "windows\runner\deps"
if (Test-Path (Split-Path $FlutterRoot -Parent)) {
    New-Item -ItemType Directory -Force -Path $flutterDeps | Out-Null
    Copy-Item $OutFile (Join-Path $flutterDeps "npcap-installer.exe") -Force
    Write-Host "==> Copied to $flutterDeps" -ForegroundColor Green
}

Write-Host "`nNpcap is ready to bundle in the installer and Release build."
