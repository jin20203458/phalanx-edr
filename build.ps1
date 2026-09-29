# build.ps1 - Phalanx 자동 빌드 스크립트
param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

if ($Clean) {
    Write-Host ">>> [정리] 이전 CMake 빌드 캐시 디렉터리 제거 중..." -ForegroundColor Yellow
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

# 1. vswhere 를 이용한 MSVC x64 빌드 환경(vcvars64.bat) 자동 탐색
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
    Write-Error ">>> MSVC 64-bit 빌드 환경 스크립트(vcvars64.bat)를 찾을 수 없습니다!"
    exit 1
}

Write-Host ">>> [Phalanx] MSVC 개발자 환경: $vcvars" -ForegroundColor Cyan
Write-Host ">>> [Phalanx] CMake 프리셋 구성 중 (preset: windows-default)..." -ForegroundColor Cyan

cmd.exe /c "call `"$vcvars`" && cmake --preset windows-default"
if ($LASTEXITCODE -ne 0) {
    Write-Host ">>> [Phalanx] CMake 구성(Configure) 실패! (ExitCode: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ">>> [Phalanx] Ninja (Release) 타깃 빌드 시작..." -ForegroundColor Cyan
cmd.exe /c "call `"$vcvars`" && cmake --build out/build/windows-default --config Release"
if ($LASTEXITCODE -ne 0) {
    Write-Host ">>> [Phalanx] 빌드 컴파일 실패! (ExitCode: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ">>> [Phalanx] 프로젝트 빌드 성공! (ExitCode: 0)" -ForegroundColor Green
exit 0
