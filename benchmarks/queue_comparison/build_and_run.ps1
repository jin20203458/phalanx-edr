# build_and_run.ps1 - 큐 비교 벤치마크 빌드 및 실행 스크립트
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

$boostInclude = "C:\Users\user\Documents\GitHub\MundusVivens.GameServer.Cpp\out\build\windows-default\vcpkg_installed\x64-windows\include"

Write-Host ">>> MSVC 툴체인 로드 및 벤치마크 바이너리 컴파일 중..." -ForegroundColor Cyan

cmd.exe /c "call `"$vcvars`" && cl.exe /std:c++20 /O2 /MD /EHsc /utf-8 /I `"$boostInclude`" main.cpp /link winmm.lib /OUT:queue_benchmark.exe"

if ($LASTEXITCODE -eq 0) {
    Write-Host ">>> 컴파일 성공! 벤치마크 실행 시작..." -ForegroundColor Green
    .\queue_benchmark.exe
} else {
    Write-Host ">>> 컴파일 실패 (ExitCode: $LASTEXITCODE)" -ForegroundColor Red
}
