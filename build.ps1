# build.ps1 - Phalanx Automated Build Script
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

if ($Clean) {
    Write-Host ">>> [Clean] Removing previous CMake build cache..." -ForegroundColor Yellow
    $cacheDirs = @(
        "out/build/windows-default/CMakeCache.txt",
        "out/build/windows-default/CMakeFiles",
        "out/build/CMakeCache.txt",
        "out/build/CMakeFiles"
    )
    foreach ($dir in $cacheDirs) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force
        }
    }
}

# 1. Locate vcvars64.bat via vswhere
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vcvars = $null

if (Test-Path $vswhere) {
    $vsInstallPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstallPath) {
        $candidate = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $candidate) {
            $vcvars = $candidate
        }
    }
}

if (-not $vcvars) {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
}

if (-not (Test-Path $vcvars)) {
    Write-Error ">>> MSVC 64-bit environment (vcvars64.bat) not found!"
    exit 1
}

Write-Host ">>> [Phalanx] MSVC Developer Environment: $vcvars" -ForegroundColor Cyan
Write-Host ">>> [Phalanx] Configuring CMake with preset 'windows-default'..." -ForegroundColor Cyan

cmd.exe /c "call `"$vcvars`" && cmake --preset windows-default"
if ($LASTEXITCODE -ne 0) {
    Write-Host ">>> [Phalanx] CMake configure failed! (ExitCode: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ">>> [Phalanx] Building targets with Ninja (Release)..." -ForegroundColor Cyan
cmd.exe /c "call `"$vcvars`" && cmake --build out/build/windows-default --config Release"
if ($LASTEXITCODE -ne 0) {
    Write-Host ">>> [Phalanx] Build failed! (ExitCode: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ">>> [Phalanx] Build succeeded! (ExitCode: 0)" -ForegroundColor Green
exit 0
