# ==============================================================================
# PHALANX EDR - 풀체인 E2E 통합 시스템 테스트 러너 (3대 시나리오)
# ==============================================================================
# 시나리오 1: C++ 즉각 처형 (0.1ms 현장 사살, C# AI 수사 바이패스)
# 시나리오 2: C++ 24μs 동결 ➔ C# Gemini LLM 수사 ➔ 50초 연장 티켓 ➔ C++ 사살
# 시나리오 3: C++ 24μs 동결 ➔ C# 로컬 오프라인 23ms 수사 (연장 없음) ➔ C++ 사살
# ==============================================================================

param(
    [switch]$Detailed = $false
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot\..

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   PHALANX EDR - 풀체인 E2E 통합 시스템 테스트 (3대 시나리오 실측 검증)           " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. C# 3대 시나리오 풀체인 시스템 테스트 실행
Write-Host "`n[1/3] C# 관제 콕핏 ➔ AI 위협 헌터 풀체인 3대 시나리오 함수 호출 순서 실측 검증..." -ForegroundColor Yellow
$verb = if ($Detailed) { "detailed" } else { "minimal" }
dotnet test tests/Phalanx.Agent.Tests/ --filter "FullyQualifiedName~FullChainSystemTests" --logger "console;verbosity=$verb"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ FullChainSystemTests 검증 실패! (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# 2. C++ 네이티브 센서 & 엔진 단위/통합 테스트 검증
Write-Host "`n[2/3] C++ 센서 & 액추에이터 24μs 동결 / 0.1ms 사살 검증..." -ForegroundColor Yellow
& .\out\build\windows-default\tests\SensorTests\SensorTests.exe
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ SensorTests.exe 검증 실패! (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

& .\out\build\windows-default\tests\EngineTests\EngineTests.exe
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ EngineTests.exe 검증 실패! (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# 3. C++ gRPC 스트리밍 루프백 IPC 검증
Write-Host "`n[3/5] C++ gRPC 양방향 스트리밍 IPC 파이프라인 검증..." -ForegroundColor Yellow
& .\out\build\windows-default\tests\IpcE2ETest\IpcE2ETest.exe
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ IpcE2ETest.exe 검증 실패! (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# 4. Phase 3.5 실제 OS 프로세스 및 Kestrel gRPC 소켓 인프로세스 검증
Write-Host "`n[4/5] Phase 3.5 실제 OS 프로세스 기동 ➔ 24μs 동결 ➔ HTTP/2 gRPC ➔ AI 수사 ➔ 사살 폐루프 실측 검증..." -ForegroundColor Yellow
dotnet test tests/Phalanx.Agent.Tests/ --filter "FullyQualifiedName~LiveFullChainE2ETests" --logger "console;verbosity=$verb"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ LiveFullChainE2ETests 검증 실패! (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# 5. C++ Native Binary ➔ C# Cockpit ➔ C++ Native Binary 크로스 랭귀지 풀체인 E2E 실측 검증
Write-Host "`n[5/5] C++ Native Binary ➔ C# Cockpit ➔ C++ Native Binary 크로스 랭귀지 풀체인 E2E 실측 검증..." -ForegroundColor Yellow
& powershell -ExecutionPolicy Bypass -File .\scripts\run_cross_e2e_test.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ run_cross_e2e_test.ps1 검증 실패! (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host "🎉 Phalanx 풀체인 Live E2E 통합 시스템 테스트 전원 통과! (Exit Code 0)         " -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
exit 0
