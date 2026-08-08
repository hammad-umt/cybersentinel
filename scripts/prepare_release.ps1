# Production Windows release builder.
# The user only installs and runs the Flutter application. The bundled
# backend runtime is started silently by the app at launch.
#
# Example:
#   .\scripts\prepare_release.ps1

param(
    [switch]$SkipEngineBuild,
    [switch]$SkipInstaller,
    [switch]$SkipNpcap,
    [switch]$SkipVCRedist
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$PackagingWindows = Join-Path $Root 'packaging\windows'
$FlutterRelease = Join-Path $Root 'build\windows\x64\runner\Release'
$InstallerOut = Join-Path $PackagingWindows 'output\CyberSentinel-Setup.exe'
$EngineDir = Join-Path $Root 'windows\runner\engine'
$RuntimeConfig = Join-Path $EngineDir 'engine.env'

function Write-Step {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host "`n==> $Message" -ForegroundColor $Color
}

function Assert-Command {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InstallHint
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required dependency '$Name'. $InstallHint"
    }
}

function Assert-Path {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$Directory,
        [switch]$File
    )

    if ($Directory -and -not (Test-Path $Path -PathType Container)) {
        throw "$Description was not found: $Path"
    }

    if ($File -and -not (Test-Path $Path -PathType Leaf)) {
        throw "$Description was not found: $Path"
    }
}

function Find-BackendRepo {
    $candidates = @(
        $env:CYBERSENTINEL_BACKEND_REPO,
        'C:\Users\hamma\OneDrive\Desktop\cybersentinel',
        (Join-Path $Root '..\cybersentinel'),
        (Join-Path $Root '..\cybersentinel-backend'),
        (Join-Path $Root '..\..\cybersentinel'),
        (Join-Path $PSScriptRoot '..\..\cybersentinel')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($candidate in $candidates) {
        $resolved = $candidate
        if (Test-Path $candidate) {
            $resolved = (Resolve-Path $candidate).Path
        }
        if (Test-Path (Join-Path $resolved 'packaging\windows\build_engine.ps1')) {
            return $resolved
        }
    }

    return $null
}

function Resolve-PythonCommand {
    foreach ($candidate in @('py -3.12', 'py -3.13', 'python')) {
        $parts = $candidate -split ' '
        $cmd = $parts[0]
        $args = @()
        if ($parts.Length -gt 1) {
            $args = $parts[1..($parts.Length - 1)]
        }
        try {
            & $cmd @args -c 'import sys' 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {}
    }

    return $null
}

function Find-EngineArtifact {
    param([Parameter(Mandatory = $true)][string]$SearchRoot)

    if (-not (Test-Path $SearchRoot)) {
        return $null
    }

    foreach ($name in @('cybersentinel_engine.exe', 'cybersentinel_engine')) {
        $matches = @(Get-ChildItem -Path $SearchRoot -Recurse -File -Filter $name -ErrorAction SilentlyContinue)
        if ($matches.Count -gt 0) {
            return $matches[0].FullName
        }
    }

    return $null
}

Write-Step 'Validating release prerequisites' 'Cyan'
Assert-Command -Name 'flutter' -InstallHint 'Install Flutter SDK and make sure flutter.exe is on PATH.'
Assert-Command -Name 'dart' -InstallHint 'Install Flutter SDK so the Dart SDK is available.'
Assert-Path -Path (Join-Path $Root 'pubspec.yaml') -Description 'Flutter project manifest' -File
Assert-Path -Path (Join-Path $Root 'windows\runner\CMakeLists.txt') -Description 'Windows runner project' -File

$backendRepo = Find-BackendRepo
if ($backendRepo) {
    Write-Host "Backend repo detected at: $backendRepo" -ForegroundColor Green
} else {
    Write-Warning 'No backend repository was discovered; packaging will rely on an existing bundled engine if present.'
}

if (-not $SkipEngineBuild -and -not $backendRepo) {
    throw 'No backend repository was found and no packaged engine binary is available. Provide CYBERSENTINEL_BACKEND_REPO or run the packaging flow after syncing an engine bundle.'
}

if (-not $SkipEngineBuild) {
    $pythonCmd = Resolve-PythonCommand
    if (-not $pythonCmd) {
        throw 'Python 3.12 or 3.13 was not found. Install Python and ensure py.exe or python.exe is available.'
    }
    Write-Host "Using Python command: $pythonCmd" -ForegroundColor Green
}

Write-Step 'Preparing clean release output' 'Cyan'
if (Test-Path (Join-Path $Root 'build\windows')) {
    Remove-Item -Recurse -Force (Join-Path $Root 'build\windows') -ErrorAction SilentlyContinue
}
if (Test-Path $PackagingWindows) {
    New-Item -ItemType Directory -Path (Join-Path $PackagingWindows 'output') -Force | Out-Null
}

Write-Step '1/6 Syncing packaged backend engine' 'Cyan'
if ($SkipEngineBuild) {
    & (Join-Path $PSScriptRoot 'sync_engine.ps1') -SkipBuild
} else {
    & (Join-Path $PSScriptRoot 'sync_engine.ps1')
}

$engineArtifact = Find-EngineArtifact -SearchRoot $EngineDir
if (-not $engineArtifact) {
    throw "Engine packaging failed. No runnable engine artifact was found under $EngineDir. Rebuild the backend packaging step or provide a packaged executable named cybersentinel_engine.exe or cybersentinel_engine."
}
if (-not (Test-Path $RuntimeConfig)) {
    throw 'Engine packaging failed. Missing engine.env in the bundled runtime folder.'
}

Write-Step '2/6 Syncing Npcap installer' 'Cyan'
if (-not $SkipNpcap) {
    & (Join-Path $PSScriptRoot 'sync_npcap.ps1')
} else {
    Write-Host 'Skipping Npcap sync by request.' -ForegroundColor Yellow
}

Write-Step '3/6 Syncing VC++ runtime' 'Cyan'
if (-not $SkipVCRedist) {
    & (Join-Path $PSScriptRoot 'sync_vcredist.ps1')
} else {
    Write-Host 'Skipping VC++ runtime sync by request.' -ForegroundColor Yellow
}

Write-Step '4/6 Building Flutter Windows release' 'Cyan'
Push-Location $Root
try {
    dart run flutter_launcher_icons 2>$null
    flutter clean
    flutter pub get
    flutter build windows --release
}
finally {
    Pop-Location
}

if (-not (Test-Path (Join-Path $FlutterRelease 'cybersentinel.exe'))) {
    throw "Flutter build failed — missing $FlutterRelease\cybersentinel.exe"
}

Write-Step '5/6 Packaging installer' 'Cyan'
if (-not $SkipInstaller) {
    $iscc = $null
    if (Get-Command iscc -ErrorAction SilentlyContinue) {
        $iscc = (Get-Command iscc).Source
    }
    if (-not $iscc) {
        foreach ($path in @(
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 7\ISCC.exe"
        )) {
            if (Test-Path $path) {
                $iscc = $path
                break
            }
        }
    }

    if (-not $iscc) {
        throw 'Inno Setup was not found. Install Inno Setup or rerun with -SkipInstaller to build only the portable release.'
    }

    $iss = Join-Path $PackagingWindows 'installer.iss'
    Assert-Path -Path $iss -Description 'Installer script' -File

    # Validate all required paths BEFORE calling ISCC to catch errors early
    Write-Host "`nValidating installer prerequisites..." -ForegroundColor Yellow
    $requiredPaths = @(
        @{ Path = $FlutterRelease; Description = "Flutter Release build" },
        @{ Path = (Join-Path $Root "windows\runner\deps\vc_redist.x64.exe"); Description = "VC++ Runtime" },
        @{ Path = (Join-Path $Root "windows\runner\deps\npcap-installer.exe"); Description = "Npcap installer" },
        @{ Path = (Join-Path $Root "windows\runner\engine"); Description = "Bundled engine" }
    )
    
    foreach ($check in $requiredPaths) {
        if (-not (Test-Path $check.Path)) {
            throw "Missing: $($check.Description) at $($check.Path)"
        }
        Write-Host "  ✓ $($check.Description)" -ForegroundColor Green
    }

    Write-Host "`nCompiling installer with Inno Setup..." -ForegroundColor Cyan
    & $iscc "`"$iss`"" "/DFLUTTER_BUILD=`"$FlutterRelease`""
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup compile failed (exit $LASTEXITCODE)"
    }
} else {
    Write-Host 'Skipping installer generation by request.' -ForegroundColor Yellow
}

Write-Step '6/6 Release complete' 'Green'
Write-Host "Portable build: $FlutterRelease" -ForegroundColor Green
if (Test-Path $InstallerOut) {
    Write-Host "Installer: $InstallerOut" -ForegroundColor Green
} else {
    Write-Host 'Installer: not produced (skipped or unavailable).' -ForegroundColor Yellow
}
Write-Host ''
Write-Host 'The Flutter app will launch the bundled backend runtime silently on first startup.' -ForegroundColor Green
