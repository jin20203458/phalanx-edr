# ==============================================================================
# PHALANX EDR - 모의 악성 프로세스 및 텔레메트리 생성기 실행 스크립트
# ==============================================================================
# 사용법:
#   .\scripts\run_attack_simulator.ps1                       # 대화형 CLI 메뉴 모드
#   .\scripts\run_attack_simulator.ps1 -Scenario 1           # 시나리오 1 즉시 실행
#   .\scripts\run_attack_simulator.ps1 -Scenario 8           # 전체 시나리오 순차 자동 실행
# ==============================================================================

param(
    [string]$Scenario = "",
    [string]$Mode = "grpc",
    [string]$Target = "http://127.0.0.1:50051",
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot\..

$argsList = @("--target", $Target, "--mode", $Mode)

if ($Scenario -ne "") {
    $argsList += @("--scenario", $Scenario)
}

if ($NonInteractive) {
    $argsList += @("--non-interactive")
}

dotnet run --project tools/Phalanx.AttackSimulator -- $argsList
exit $LASTEXITCODE
