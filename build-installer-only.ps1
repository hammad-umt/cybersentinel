# Build installer only - reuses existing Flutter and engine builds
# Validates all prerequisites BEFORE calling ISCC

$Root = "C:\Users\hamma\OneDrive\Desktop\New folder"
$FlutterRelease = Join-Path $Root 'build\windows\x64\runner\Release'
$iscc = "C:\Users\hamma\AppData\Local\Programs\Inno Setup 6\ISCC.exe"
$iss = Join-Path $Root 'packaging\windows\installer.iss'

Write-Host "==> Validating installer prerequisites..." -ForegroundColor Cyan

# Check all required files exist BEFORE compiling
$checks = @(
    @{ Path = $FlutterRelease; Type = 'Directory'; Desc = "Flutter Release build" },
    @{ Path = (Join-Path $FlutterRelease 'cybersentinel.exe'); Type = 'File'; Desc = "CyberSentinel executable" },
    @{ Path = $iscc; Type = 'File'; Desc = "Inno Setup compiler" },
    @{ Path = $iss; Type = 'File'; Desc = "Installer script" },
    @{ Path = (Join-Path $Root "windows\runner\deps\vc_redist.x64.exe"); Type = 'File'; Desc = "VC++ Runtime installer" },
    @{ Path = (Join-Path $Root "windows\runner\deps\npcap-installer.exe"); Type = 'File'; Desc = "Npcap installer" },
    @{ Path = (Join-Path $Root "windows\runner\engine"); Type = 'Directory'; Desc = "Bundled engine" }
)

$allValid = $true
foreach ($check in $checks) {
    $exists = if ($check.Type -eq 'File') {
        Test-Path $check.Path -PathType Leaf
    } else {
        Test-Path $check.Path -PathType Container
    }
    
    if ($exists) {
        Write-Host "  ✓ $($check.Desc)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ MISSING: $($check.Desc)" -ForegroundColor Red
        Write-Host "    Expected: $($check.Path)" -ForegroundColor Red
        $allValid = $false
    }
}

if (-not $allValid) {
    Write-Host "`n❌ Validation failed. Fix missing files above." -ForegroundColor Red
    exit 1
}

Write-Host "`n==> All prerequisites validated. Building installer..." -ForegroundColor Green
& $iscc "`"$iss`"" "/DFLUTTER_BUILD=`"$FlutterRelease`""

if ($LASTEXITCODE -eq 0) {
    $installerPath = Join-Path $Root 'packaging\windows\output\CyberSentinel-Setup.exe'
    if (Test-Path $installerPath) {
        $size = (Get-Item $installerPath).Length / 1MB
        Write-Host "`n✓ Installer complete!" -ForegroundColor Green
        Write-Host "  Path: $installerPath" -ForegroundColor Green
        Write-Host "  Size: $([math]::Round($size, 2)) MB" -ForegroundColor Green
    }
} else {
    Write-Host "`n❌ ISCC failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}
