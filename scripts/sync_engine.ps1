# Builds the Python engine from the CyberSentinel backend repo and copies it
# into this Flutter app at windows/runner/engine/
#
# Run from: C:\Users\hamma\OneDrive\Desktop\New folder
#   .\scripts\sync_engine.ps1

param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$FlutterRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendRepo = $null
$envCandidates = @(
    $env:CYBERSENTINEL_BACKEND_REPO,
    $env:CYBERSENTINEL_CHATBOT_REPO,
    'C:\Users\hamma\OneDrive\Desktop\cybersentinel_chatbot-main',
    'C:\Users\hamma\OneDrive\Desktop\cybersentinel',
    (Join-Path $FlutterRoot "..\cybersentinel"),
    (Join-Path $FlutterRoot "..\cybersentinel-backend"),
    (Join-Path $FlutterRoot "..\..\cybersentinel"),
    (Join-Path $PSScriptRoot "..\..\cybersentinel")
)
foreach ($candidate in $envCandidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    $resolved = $candidate
    if (Test-Path $candidate) {
        $resolved = (Resolve-Path $candidate).Path
    }
    if (Test-Path (Join-Path $resolved "packaging\windows\build_engine.ps1")) {
        $BackendRepo = $resolved
        break
    }
}

if ($BackendRepo) {
    Write-Host "Backend repo: $BackendRepo" -ForegroundColor Cyan
} else {
    Write-Warning "Backend repo not found; falling back to the existing engine bundle if it exists."
}

$BuildScript = if ($BackendRepo) { Join-Path $BackendRepo "packaging\windows\build_engine.ps1" } else { $null }
$EngineDist = if ($BackendRepo) { Join-Path $BackendRepo "packaging\windows\dist\CyberSentinelEngine" } else { $null }
$FlutterEngine = Join-Path $FlutterRoot "windows\runner\engine"
$BackendEnv = if ($BackendRepo) { Join-Path $BackendRepo "cybersentinel-backend\.env" } else { $null }

function Find-EngineArtifact {
    param([string]$SearchRoot)

    if (-not $SearchRoot -or -not (Test-Path $SearchRoot)) {
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

function Write-ProductionEngineEnv {
    param(
        [string]$SourceEnv,
        [string]$DestEnv
    )

    $skipKeys = @(
        "SUPERVISED_MODEL_DIR",
        "UNSUPERVISED_MODEL_DIR",
        "CYBERSENTINEL_MASTER_KEY"
    )
    $desktopHost = if ($env:CYBERSENTINEL_HOST) { $env:CYBERSENTINEL_HOST } else { "127.0.0.1" }
    $desktopPort = if ($env:CYBERSENTINEL_PORT) { $env:CYBERSENTINEL_PORT } else { "8000" }
    $overrides = [ordered]@{
        HOST = $desktopHost
        PORT = $desktopPort
        DEBUG = "false"
        RATE_LIMIT_PER_MINUTE = "0"
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $lineIndex = @{}

    if (Test-Path $SourceEnv) {
        foreach ($raw in Get-Content $SourceEnv) {
            $line = $raw.TrimEnd()
            if (-not $line -or $line.StartsWith("#")) {
                $lines.Add($line)
                continue
            }
            if ($line -notmatch "^([^=]+)=(.*)$") { continue }
            $key = $Matches[1].Trim()
            $value = $Matches[2]
            if ($skipKeys -contains $key) { continue }
            if ($overrides.Contains($key)) { continue }
            if ($seen.ContainsKey($key)) {
                $existingLine = $lines[$lineIndex[$key]]
                if ($existingLine -match "^[^=]+=(.*)$") {
                    $existingValue = $Matches[1]
                } else {
                    $existingValue = ''
                }
                if (-not [string]::IsNullOrWhiteSpace($value) -or [string]::IsNullOrWhiteSpace($existingValue)) {
                    $lines[$lineIndex[$key]] = $line
                }
                continue
            }
            $lineIndex[$key] = $lines.Count
            $lines.Add($line)
            $seen[$key] = $true
        }
    }

    $header = @(
        "# CyberSentinel desktop engine config (bundled with installer)",
        "# Model paths are set automatically by cybersentinel_engine.exe",
        ""
    )
    $forced = foreach ($key in $overrides.Keys) {
        "$key=$($overrides[$key])"
    }

    ($header + $forced + "" + $lines) | Set-Content -Path $DestEnv -Encoding UTF8
}

function Copy-EngineBuild {
    param(
        [Parameter(Mandatory=$true)][string]$SourcePath,
        [Parameter(Mandatory=$true)][string]$DestinationDir
    )

    if (-not (Test-Path $SourcePath)) {
        throw "Engine source path not found: $SourcePath"
    }

    if (Test-Path $SourcePath -PathType Container) {
        foreach ($item in Get-ChildItem -Path $SourcePath -Force) {
            $target = Join-Path $DestinationDir $item.Name
            if ($item.PSIsContainer) {
                Copy-Item -Path $item.FullName -Destination $target -Recurse -Force
            } else {
                Copy-Item -Path $item.FullName -Destination $DestinationDir -Force
            }
        }
        return
    }

    if (Test-Path $SourcePath -PathType Leaf) {
        Copy-Item -Path $SourcePath -Destination $DestinationDir -Force
        return
    }

    throw "Unexpected engine source path type: $SourcePath"
}

Write-Host "Flutter app:  $FlutterRoot" -ForegroundColor Cyan
Write-Host "Backend repo: $BackendRepo" -ForegroundColor Cyan

if ($BuildScript -and (Test-Path $BuildScript)) {
    Write-Host "`n==> Building cybersentinel_engine.exe (first run takes several minutes)..." -ForegroundColor Yellow

    if ($SkipBuild -and $EngineDist -and (Test-Path (Join-Path $EngineDist "cybersentinel_engine.exe"))) {
        Write-Host "    Skipping build — using existing engine in $EngineDist" -ForegroundColor Green
    } else {
        $pythonArg = @{}
        foreach ($candidate in @("py -3.12", "py -3.13", "python")) {
            $parts = $candidate -split " "
            $cmd = $parts[0]
            $args = @()
            if ($parts.Length -gt 1) {
                $args = $parts[1..($parts.Length - 1)]
            }
            try {
                & $cmd @args -c "import sys" 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $pythonArg = @{ Python = $candidate }
                    Write-Host "    Using $candidate for engine build"
                    break
                }
            } catch { }
        }

        & $BuildScript @pythonArg
    }

    $legacyDist = if ($BackendRepo) { Join-Path $BackendRepo "cybersentinel-backend\dist\CyberSentinelEngine" } else { $null }
    if ($EngineDist -and -not (Test-Path (Join-Path $EngineDist "cybersentinel_engine.exe")) -and $legacyDist -and (Test-Path (Join-Path $legacyDist "cybersentinel_engine.exe"))) {
        Write-Host "Using legacy engine build at $legacyDist" -ForegroundColor Yellow
        $EngineDist = $legacyDist
    }

    if (-not $EngineDist -or -not (Test-Path (Join-Path $EngineDist "cybersentinel_engine.exe"))) {
        Write-Warning "Engine build was not produced; using the existing Flutter engine bundle if present."
    }
} else {
    Write-Warning "Skipping engine build because no backend build script was found."
}

$engineArtifact = if ($EngineDist) { Find-EngineArtifact -SearchRoot $EngineDist } else { $null }
if ($engineArtifact) {
    Write-Host "`n==> Copying engine into Flutter project..." -ForegroundColor Yellow
    if (Test-Path $FlutterEngine) {
        Remove-Item $FlutterEngine -Recurse -Force
    }
    New-Item -ItemType Directory -Path $FlutterEngine -Force | Out-Null

    $engineSourceDir = if (Test-Path $engineArtifact -PathType Container) {
        $engineArtifact
    } else {
        Split-Path -Parent $engineArtifact
    }
    Copy-EngineBuild -SourcePath $engineSourceDir -DestinationDir $FlutterEngine

    $engineEnv = Join-Path $FlutterEngine "engine.env"
    $distEngineEnv = Join-Path $EngineDist "engine.env"
    if ($BackendEnv -and (Test-Path $BackendEnv)) {
        Write-ProductionEngineEnv -SourceEnv $BackendEnv -DestEnv $engineEnv
        Write-ProductionEngineEnv -SourceEnv $BackendEnv -DestEnv $distEngineEnv
        Write-Host "Synced production engine.env from cybersentinel-backend\.env" -ForegroundColor Green
    } elseif (-not (Test-Path $engineEnv)) {
        Write-Warning "Edit $engineEnv — set DATABASE_URL and JWT_SECRET_KEY before shipping."
    }

    Write-Host "`nDone. Engine installed at:" -ForegroundColor Green
    Write-Host "  $FlutterEngine"
    
        # --- Copy chatbot artifacts if present so the app can start the chatbot without runtime downloads ---
        $chatbotDest = Join-Path $FlutterEngine 'chatbot'
        $chatbotCandidates = @()
        if ($EngineDist -and (Test-Path (Join-Path $EngineDist 'chatbot'))) { $chatbotCandidates += (Join-Path $EngineDist 'chatbot') }
        if ($BackendRepo -and (Test-Path (Join-Path $BackendRepo 'chatbot'))) { $chatbotCandidates += (Join-Path $BackendRepo 'chatbot') }
        # Check env var and hardcoded paths directly as chatbot repo roots (not nested in /chatbot)
        foreach ($cbRepo in @($env:CYBERSENTINEL_CHATBOT_REPO, 'C:\Users\hamma\OneDrive\Desktop\cybersentinel_chatbot-main')) {
            if ($cbRepo -and (Test-Path $cbRepo)) {
                $resolved = (Resolve-Path $cbRepo).Path
                # Accept if main.py or requirements.txt exist (indicates chatbot repo root)
                if ((Test-Path (Join-Path $resolved 'main.py')) -or (Test-Path (Join-Path $resolved 'requirements.txt'))) {
                    if ($chatbotCandidates -notcontains $resolved) {
                        $chatbotCandidates += $resolved
                    }
                }
            }
        }

        foreach ($src in $chatbotCandidates) {
            try {
                if (-not (Test-Path $src)) { continue }
                if (Test-Path $chatbotDest) { Remove-Item $chatbotDest -Recurse -Force }
                Write-Host "Copying chatbot artifacts from $src to $chatbotDest" -ForegroundColor Green
                Copy-Item -Path $src -Destination $chatbotDest -Recurse -Force
                break
            } catch {
                Write-Warning ("Failed to copy chatbot artifacts from {0}: {1}" -f $src, $_)
            }
        }
        
        # --- Write an install-time helper script into the bundled engine so the installer
        #     can perform chatbot setup (install deps, ensure models, start service) ---
        $installScriptPath = Join-Path $FlutterEngine 'install_chatbot.ps1'
        $installScript = @'
$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$chatbotDir = Join-Path $scriptDir 'chatbot'
$port = 19454

Write-Host "Running chatbot install helper in: $scriptDir"

if (-not (Test-Path $chatbotDir)) {
    Write-Host "No chatbot folder found at $chatbotDir; nothing to install." -ForegroundColor Yellow
    exit 0
}

# detect python (prefer py launcher)
$pythonCandidates = @('py -3.13','py -3.12','python')
$pythonCmd = $null
$pythonExtraArgs = @()
foreach ($c in $pythonCandidates) {
    $parts = $c -split ' '
    $cmd = $parts[0]
    $args = if ($parts.Length -gt 1) { $parts[1..($parts.Length-1)] } else { @() }
    try {
        & $cmd @args -c 'import sys' 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $pythonCmd = $cmd; $pythonExtraArgs = $args; break }
    } catch { }
}
# fallback to bundled portable python inside chatbot folder
if (-not $pythonCmd) {
    $bundledPy = Join-Path $chatbotDir 'python\python.exe'
    if (Test-Path $bundledPy) { $pythonCmd = $bundledPy; $pythonExtraArgs = @() }
}

if (-not $pythonCmd) {
    Write-Host "Python 3.12+ was not found. Please install Python 3.12+ or include a portable python in the chatbot bundle." -ForegroundColor Red
    exit 4
}

Write-Host "Using Python: $pythonCmd $($pythonExtraArgs -join ' ')"

# Create or reuse a virtual environment inside the chatbot bundle
$venvDir = Join-Path $chatbotDir 'venv'
$venvPython = if (Test-Path (Join-Path $venvDir 'Scripts\python.exe')) { Join-Path $venvDir 'Scripts\python.exe' } else { $null }
if (-not $venvPython) {
    Write-Host "Creating virtualenv in $venvDir"
    & $pythonCmd @pythonExtraArgs -m venv $venvDir
    $venvPython = Join-Path $venvDir 'Scripts\python.exe'
}

# Ensure pip and install packages
& $venvPython -m pip install --upgrade pip
$reqFile = Join-Path $chatbotDir 'requirements.txt'
if (Test-Path $reqFile) {
    Write-Host "Installing requirements from $reqFile"
    & $venvPython -m pip install -r $reqFile
} else {
    Write-Host "No requirements.txt found; installing default packages: uvicorn, fastapi, transformers, torch, xgboost"
    & $venvPython -m pip install 'uvicorn[standard]' fastapi transformers torch xgboost || Write-Host 'Some packages failed to install; check internet access.' -ForegroundColor Yellow
}

# Prefer a packaged executable if present
$exe = Get-ChildItem -Path $chatbotDir -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'chatbot|uvicorn' } | Select-Object -First 1
if ($exe) {
    Write-Host "Starting chatbot executable: $($exe.FullName)" -ForegroundColor Green
    Start-Process -FilePath $exe.FullName -WindowStyle Hidden
    exit 0
}

# Else run main.py or app.py via the venv python
$mainPy = Join-Path $chatbotDir 'main.py'
$appPy = Join-Path $chatbotDir 'app.py'
if (Test-Path $mainPy) {
    $args = "-m uvicorn main:app --host 127.0.0.1 --port $port"
    Write-Host "Starting chatbot via venv python: $venvPython $args"
    Start-Process -FilePath $venvPython -ArgumentList $args -WorkingDirectory $chatbotDir -WindowStyle Hidden
    exit 0
}
if (Test-Path $appPy) {
    $args = "-m uvicorn app:app --host 127.0.0.1 --port $port"
    Write-Host "Starting chatbot via venv python: $venvPython $args"
    Start-Process -FilePath $venvPython -ArgumentList $args -WorkingDirectory $chatbotDir -WindowStyle Hidden
    exit 0
}

Write-Host "No runnable chatbot artifact found in $chatbotDir" -ForegroundColor Yellow
exit 3
'@

        try {
            $installScript | Set-Content -Path $installScriptPath -Encoding UTF8 -Force
            Write-Host "Wrote install helper script to $installScriptPath" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to write install helper script: $_"
        }
} else {
    if (-not (Test-Path $FlutterEngine)) {
        New-Item -ItemType Directory -Path $FlutterEngine -Force | Out-Null
    }
    Write-Warning "No engine binary was bundled. The installer will still proceed, but the app will need a packaged engine present."
}

Write-Host "`nNext steps:"
Write-Host "  cd `"$FlutterRoot`""
Write-Host "  .\scripts\sync_npcap.ps1"
Write-Host "  flutter pub get"
Write-Host "  flutter run -d windows   # UAC prompt — Administrator required"
