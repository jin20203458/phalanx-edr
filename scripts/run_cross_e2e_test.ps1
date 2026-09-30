# ==============================================================================
# PHALANX EDR - C++ ➔ C# Cockpit ➔ C++ 크로스 랭귀지 풀체인 라이브 통합 E2E 테스트 러너
# ==============================================================================
# 1. C# Kestrel Cockpit gRPC 관제 허브 백그라운드 프로세스 기동 (Port 50051)
# 2. Port 50051 수신 대기 확인 (Test-NetConnection)
# 3. C++ 네이티브 바이너리 FullChainCrossE2ETest.exe 실행:
#    - C++ 실제 OS 타깃 프로세스(powershell.exe) 스폰
#    - C++ 24μs 원자적 동결 (NtSuspendProcess)
#    - C++ DoubleBufferedSwapQueue 적재
#    - C++ asio-grpc 스트리밍 클라이언트가 127.0.0.1:50051 C# Cockpit으로 전송
#    - C# PhalanxGrpcService + AutonomousHunterAgent 수사 (FSM/AI)
#    - C# Cockpit이 gRPC를 통해 MitigationCommand(ACTION_KILL) 역전송
#    - C++ GrpcStreamClient 수신 및 ProcessActuator::TerminateTargetProcess 집행
#    - C++ 실제 OS 타깃 프로세스 소멸(ExitCode) 검증
# 4. C# Cockpit 백그라운드 프로세스 안전 종료 및 자원 정리
# ==============================================================================

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot\..

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   PHALANX - C++ ➔ C# Cockpit ➔ C++ 크로스 랭귀지 풀체인 E2E 통합 테스트 러너     " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$cppExe = ".\out\build\windows-default\tests\FullChainCrossE2ETest\FullChainCrossE2ETest.exe"
if (-not (Test-Path $cppExe)) {
    Write-Host "❌ C++ 테스트 실행 파일이 존재하지 않습니다: $cppExe" -ForegroundColor Red
    Write-Host "   먼저 'powershell .\build.ps1'을 실행하여 C++ 프로젝트를 빌드하십시오." -ForegroundColor Red
    exit 1
}

# 기존 50051 포트 점유 프로세스 정리
$existingConn = Get-NetTCPConnection -LocalPort 50051 -ErrorAction SilentlyContinue
if ($existingConn) {
    Write-Host "⚠️ 기존 50051 포트 점유 프로세스(PID: $($existingConn.OwningProcess)) 감지 -> 정리 시도..." -ForegroundColor Yellow
    Stop-Process -Id $existingConn.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Write-Host "`n[1/4] C# Cockpit Kestrel gRPC 관제 서버 백그라운드 구동 (Port: 50051)..." -ForegroundColor Yellow
$cockpitProc = Start-Process -FilePath "dotnet" `
                             -ArgumentList "run --project src/Phalanx.Cockpit --headless" `
                             -PassThru `
                             -NoNewWindow

$portReady = $false
$retries = 0
while ($retries++ -lt 30) {
    Start-Sleep -Milliseconds 300
    if ($cockpitProc.HasExited) {
        Write-Host "❌ C# Cockpit 서버가 비정상 조기 종료되었습니다! ExitCode: $($cockpitProc.ExitCode)" -ForegroundColor Red
        exit 1
    }
    $tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port 50051 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($tcp) {
        $portReady = $true
        break
    }
}

if (-not $portReady) {
    Write-Host "❌ C# Cockpit gRPC 포트(50051) 대기 타임아웃!" -ForegroundColor Red
    if (-not $cockpitProc.HasExited) {
        Stop-Process -Id $cockpitProc.Id -Force -ErrorAction SilentlyContinue
    }
    exit 1
}

Write-Host "✅ [2/4] C# Cockpit Kestrel HTTP/2 gRPC 서버 준비 완료 (127.0.0.1:50051)!" -ForegroundColor Green

$e2eExitCode = 1
try {
    Write-Host "`n[3/4] C++ 네이티브 FullChainCrossE2ETest.exe 기동 및 종단간 폐루프 실측 시작..." -ForegroundColor Yellow
    & $cppExe "127.0.0.1:50051"
    $e2eExitCode = $LASTEXITCODE
}
finally {
    Write-Host "`n[4/4] C# Cockpit 관제 서버 프로세스 정상 정리 중..." -ForegroundColor Yellow
    if (-not $cockpitProc.HasExited) {
        Stop-Process -Id $cockpitProc.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
}

if ($e2eExitCode -eq 0) {
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "🎉 C++ ➔ C# Cockpit ➔ C++ 크로스 랭귀지 풀체인 E2E 통합 테스트 완벽 성공! (Exit Code 0) " -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ C++ ➔ C# Cockpit ➔ C++ 크로스 랭귀지 E2E 테스트 실패! (Exit Code: $e2eExitCode)" -ForegroundColor Red
    exit $e2eExitCode
}
