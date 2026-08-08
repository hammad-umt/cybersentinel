# Upload CyberSentinel-Setup.exe to GitHub Releases so the website download works.
# Vercel cannot serve Git LFS files — users otherwise get a ~134 byte pointer file.
#
# Prerequisites:
#   1. Run .\scripts\prepare_release.ps1 first
#   2. gh auth login   (or set GH_TOKEN)
#
# Usage:
#   .\scripts\publish_release.ps1
#   .\scripts\publish_release.ps1 -Tag v1.0.1

param(
    [string]$Tag = "v1.0.0",
    [string]$Repo = "hammad-umt/cybersentinel"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Installer = Join-Path $Root "packaging\windows\output\CyberSentinel-Setup.exe"

if (-not (Test-Path $Installer)) {
    throw "Installer not found. Run .\scripts\prepare_release.ps1 first.`nExpected: $Installer"
}

$sizeMb = [math]::Round((Get-Item $Installer).Length / 1MB, 1)
Write-Host "Installer: $Installer ($sizeMb MB)" -ForegroundColor Cyan

function Find-GitHubCli {
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        return (Get-Command gh).Source
    }
    foreach ($path in @(
        "$env:ProgramFiles\GitHub CLI\gh.exe",
        "${env:ProgramFiles(x86)}\GitHub CLI\gh.exe",
        "$env:LOCALAPPDATA\Programs\GitHub CLI\gh.exe"
    )) {
        if (Test-Path $path) { return $path }
    }
    return $null
}

$gh = Find-GitHubCli
if (-not $gh) {
    throw @"
GitHub CLI (gh) is required. Install from https://cli.github.com/
Then close and reopen PowerShell, run: gh auth login
Or upload manually:
  https://github.com/$Repo/releases/new?tag=$Tag
  Attach: $Installer
"@
}

Write-Host "Using GitHub CLI: $gh" -ForegroundColor DarkGray

$releaseExists = $false
try {
    & $gh release view $Tag --repo $Repo 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $releaseExists = $true }
} catch { }

if ($releaseExists) {
    Write-Host "Uploading asset to existing release $Tag..." -ForegroundColor Yellow
    & $gh release upload $Tag $Installer --repo $Repo --clobber
} else {
    Write-Host "Creating release $Tag..." -ForegroundColor Yellow
    & $gh release create $Tag $Installer `
        --repo $Repo `
        --title "CyberSentinel $Tag" `
        --notes "Windows desktop installer (Flutter + local FastAPI engine)."
}

Write-Host ""
Write-Host "Done. Download URL:" -ForegroundColor Green
Write-Host "  https://github.com/$Repo/releases/download/$Tag/CyberSentinel-Setup.exe"
Write-Host ""
Write-Host "Redeploy the website (constants.ts already points at this URL)." -ForegroundColor Yellow
