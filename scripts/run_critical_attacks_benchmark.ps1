# ==============================================================================
# PHALANX EDR - 실무 비판적 5대 엔터프라이즈 공격 시나리오 자동화 벤치마크 러너
# ==============================================================================
# 5대 실무 회피 공격을 자동으로 구성 및 테스트하고 결과를 감사 보고서로 출력합니다:
#   [1] LOLBAS 프록시 + 무서명 DLL 로드 + 미등록 외부 C2 (T1218.011)
#   [2] 정상 서명 시스템 바이너리(svchost.exe) 인젝션 / Unbacked 실행 메모리 침투 (T1055.012)
#   [3] 확장자 위장(Disguised PE) 스테가노그래피 드로퍼 (T1036.008)
#   [4] 시스템 핵심 바이너리 경로 위장(Masquerading Dropper) (T1036.005)
#   [5] 사내 정상 파워셸 인벤토리 관리 작업 (False Positive 방어력 검증)
# ==============================================================================

param(
    [switch]$Detailed
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot\..

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   PHALANX EDR - 실무 비판적 5대 엔터프라이즈 공격 자동화 벤치마크               " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$verbosity = if ($Detailed) { "normal" } else { "minimal" }

Write-Host "`n[1/2] 5대 실무 위협 자동화 테스트 하네스 실행 중..." -ForegroundColor Yellow

$testFilter = "FullyQualifiedName~CriticalEnterpriseAttackHarnessTests"
dotnet test tests/Phalanx.Agent.Tests/ --filter $testFilter --logger "console;verbosity=$verbosity"

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n❌ 벤치마크 실행 실패 (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`n[2/2] 생성된 감사 벤치마크 리포트 확인 중..." -ForegroundColor Green

$reportCandidates = @(
    "tests\Phalanx.Agent.Tests\bin\Debug\net9.0-windows\critical_enterprise_benchmark.json",
    "tests\Phalanx.Agent.Tests\bin\Release\net9.0-windows\critical_enterprise_benchmark.json"
)

foreach ($rep in $reportCandidates) {
    if (Test-Path $rep) {
        Write-Host "`n--------------------------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host "   BENCHMARK AUDIT REPORT ($rep)" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan
        Get-Content $rep | Write-Host
        break
    }
}

Write-Host "`n✅ 5대 실무 위협 벤치마크 100% 통과 완료." -ForegroundColor Green
exit 0
