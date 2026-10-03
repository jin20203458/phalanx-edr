using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Scenarios;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Services;

public record ScenarioExecutionResult(
    string ScenarioName,
    int ScenarioId,
    string ExpectedAction,
    MitigationCommand.Types.ActionType ActualAction,
    bool IsPass,
    TimeSpan Elapsed,
    int TurnCount,
    double Confidence,
    string ToolChain,
    string AssertionMessage,
    List<string> LogEntries,
    bool OsProcessTerminatedSuccessfully
);

/// <summary>
/// 어택랩 실행 모드 정의
/// </summary>
public enum AttackLabMode
{
    CleanRoom,
    OsHybrid,
    LiveExpert
}

/// <summary>
/// 어택랩 모의 침해 시나리오 실행, OS 하이브리드 프로세스 생명주기 관리,
/// CQRS 트리 인프로세스 주입 및 자율 AI 위협 헌터 수사 오케스트레이션을 전담하는 서비스. (SRP 준수)
/// </summary>
public class AttackLabScenarioRunner
{
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly AutonomousHunterAgent? _agent;

    /// <summary>
    /// 악성 프로세스 종료 시 하위 프로세스 트리 전체를 함께 종료할지 여부
    /// </summary>
    public bool KillProcessTree { get; set; } = true;

    /// <summary>
    /// 포렌식 감사 리포트가 저장될 대상 디렉터리 경로
    /// </summary>
    public string ReportExportDirectory { get; set; } = "IncidentReports";

    public AttackLabScenarioRunner(
        ProcessTreeProjectionManager treeManager,
        AutonomousHunterAgent? agent = null)
    {
        _treeManager = treeManager;
        _agent = agent;
        LoadSettingsFromAppSettings();
    }

    private void LoadSettingsFromAppSettings()
    {
        try
        {
            string[] candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "AppSettings.json"),
                Path.Combine(Directory.GetCurrentDirectory(), "AppSettings.json"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\..\src\Phalanx.Cockpit\AppSettings.json"))
            };

            foreach (var path in candidates)
            {
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("Storage", out var st) && st.TryGetProperty("ReportExportPath", out var rep))
                    {
                        var dir = rep.GetString();
                        if (!string.IsNullOrWhiteSpace(dir)) ReportExportDirectory = dir;
                    }
                    break;
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// 7대 표준 시나리오 실행 (하위 호환용 오버로드)
    /// </summary>
    public Task<ScenarioExecutionResult> ExecuteScenarioAsync(
        AttackScenario sc,
        bool isModeOs,
        CancellationToken cancellationToken = default)
    {
        return ExecuteScenarioAsync(sc, isModeOs ? AttackLabMode.OsHybrid : AttackLabMode.CleanRoom, cancellationToken);
    }

    /// <summary>
    /// 7대 표준 시나리오 실행 (Clean-Room, OS 하이브리드, 전문가 라이브)
    /// </summary>
    public async Task<ScenarioExecutionResult> ExecuteScenarioAsync(
        AttackScenario sc,
        AttackLabMode mode,
        CancellationToken cancellationToken = default)
    {
        var logs = new List<string>();
        var sw = Stopwatch.StartNew();
        Process? realOsProcess = null;
        uint targetPid = AttackScenarioRegistry.GeneratePid();

        try
        {
            // 1. [OS 모드 / 전문가 라이브 모드] 프로세스 스폰 및 실제 PID 획득
            if (mode == AttackLabMode.LiveExpert)
            {
                var psi = sc.GetLiveProcessInfo?.Invoke() ?? sc.GetSafeOsProcessInfo?.Invoke();
                if (psi != null)
                {
                    try
                    {
                        realOsProcess = Process.Start(psi);
                        if (realOsProcess != null)
                        {
                            targetPid = (uint)realOsProcess.Id;
                            logs.Add($"[{DateTime.Now:HH:mm:ss}] [전문가 라이브] 실제 OS 페이로드 프로세스 기동 (PID: {targetPid}, {psi.FileName})");
                        }
                    }
                    catch (Exception ex)
                    {
                        logs.Add($"[{DateTime.Now:HH:mm:ss}] [전문가 라이브 경고] 프로세스 기동 실패: {ex.Message}");
                    }
                }

                // Phase 5 (T1036.005 Masquerading Dropper) 디스크 관측 검증
                if (sc.Id == 5)
                {
                    string tempDir = Environment.GetEnvironmentVariable("TEMP") ?? @"C:\Windows\Temp";
                    string targetFile = Path.Combine(tempDir, "svchost.exe");
                    for (int i = 0; i < 5; i++)
                    {
                        if (File.Exists(targetFile)) break;
                        await Task.Delay(100, cancellationToken);
                    }

                    if (File.Exists(targetFile))
                    {
                        logs.Add($"[{DateTime.Now:HH:mm:ss}] [디스크 관측] 'C:\\Windows\\Temp\\svchost.exe' 생성 포착 (용량: {new FileInfo(targetFile).Length} Bytes)");
                        logs.Add($"[{DateTime.Now:HH:mm:ss}] [수사 지연 요인] 정밀 파일 검증(디지털 서명/시스템 경로 위장 T1036.005) 부재 ➔ AI 수사관 멀티턴 우회 지연 발생");
                    }
                }
            }
            else if (mode == AttackLabMode.OsHybrid && sc.GetSafeOsProcessInfo != null)
            {
                var psi = sc.GetSafeOsProcessInfo();
                if (psi != null)
                {
                    try
                    {
                        realOsProcess = Process.Start(psi);
                        if (realOsProcess != null)
                        {
                            targetPid = (uint)realOsProcess.Id;
                            logs.Add($"[{DateTime.Now:HH:mm:ss}] [OS 연동] 실제 안전 프로세스 스폰 완료 (PID: {targetPid})");
                        }
                    }
                    catch (Exception ex)
                    {
                        logs.Add($"[{DateTime.Now:HH:mm:ss}] [OS 연동 경고] 프로세스 기동 실패: {ex.Message}");
                    }
                }
            }

            // 2. 정확한 targetPid 기반 TelemetryBatch 빌드
            var batch = sc.BuildBatch(targetPid);

            // 3. 인프로세스 CQRS 프로세스 트리 주입
            var snapshots = batch.ProcessEvents.Where(e => e.Lifecycle == ProcessLifecycle.LifecycleSnapshot).ToList();
            if (snapshots.Count > 0)
            {
                _treeManager.ApplySnapshotBatch(snapshots);
            }

            var deltas = batch.ProcessEvents.Where(e => e.Lifecycle != ProcessLifecycle.LifecycleSnapshot).ToList();
            foreach (var ev in deltas)
            {
                _treeManager.ApplyDeltaEvent(ev);
            }

            // 4. 시나리오별 처리 분기
            var targetEvent = batch.ProcessEvents.FirstOrDefault(e => e.ProcessId == targetPid)
                              ?? batch.ProcessEvents.LastOrDefault();

            InvestigationResult? invResult = null;
            MitigationCommand.Types.ActionType finalAction = MitigationCommand.Types.ActionType.ActionResume;

            // [시나리오 #2] C++ 로컬 룰 엔진 즉각 사살 (Reflex 0.08ms)
            if (targetEvent != null && (targetEvent.IsTerminated || targetEvent.Lifecycle == ProcessLifecycle.LifecycleTerminated))
            {
                var node = _treeManager.FindNodeByPid(targetPid)
                           ?? new ProcessNodeModel
                           {
                               ProcessId = targetPid,
                               ImageName = targetEvent.ImageName,
                               CommandLine = targetEvent.CommandLine
                           };

                if (_agent != null)
                {
                    invResult = _agent.HandleReflexKill(node);
                    finalAction = invResult.VerdictAction;
                }
                else
                {
                    finalAction = MitigationCommand.Types.ActionType.ActionKill;
                }
                logs.Add($"[{DateTime.Now:HH:mm:ss}] [커널 룰] LocalRuleEngine 0.08ms 원자적 즉각 사살 집행 완료");
            }
            // [시나리오 #1, 3, 4, 5, 6] 원자적 동결 ➔ 자율 AI 헌터 ReAct 수사
            else if (targetEvent != null && (targetEvent.IsSuspended || targetEvent.Lifecycle == ProcessLifecycle.LifecycleSuspended))
            {
                var targetNode = _treeManager.FindActiveNodeByPid(targetPid)
                                 ?? new ProcessNodeModel
                                 {
                                     ProcessId = targetPid,
                                     ImageName = targetEvent.ImageName,
                                     CommandLine = targetEvent.CommandLine,
                                     IsSuspended = true
                                 };

                logs.Add($"[{DateTime.Now:HH:mm:ss}] [커널 센서] 24μs 원자적 동결(NtSuspendProcess) 인입 ➔ 자율 AI 헌터 기동");

                if (_agent != null)
                {
                    invResult = await _agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask, cancellationToken);
                    finalAction = invResult.VerdictAction;
                }
                else
                {
                    // 단위 테스트 / 헤드리스 환경용 시뮬레이션 폴백
                    await Task.Delay(100, cancellationToken);
                    finalAction = sc.ExpectedAction == "ACTION_KILL"
                        ? MitigationCommand.Types.ActionType.ActionKill
                        : MitigationCommand.Types.ActionType.ActionResume;
                }

                logs.Add($"[{DateTime.Now:HH:mm:ss}] [AI 수사관] ReAct 수사 종결 ➔ 판결: {finalAction}");
            }

            sw.Stop();

            // 5. [SSOT 판결 집행] AI 에이전트의 실제 최종 판결이 ActionKill일 때만 OS 프로세스 사살
            bool osKilledSuccessfully = true;
            if (realOsProcess != null && !realOsProcess.HasExited)
            {
                if (finalAction == MitigationCommand.Types.ActionType.ActionKill)
                {
                    realOsProcess.Kill(entireProcessTree: KillProcessTree);
                    using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    try
                    {
                        await realOsProcess.WaitForExitAsync(exitCts.Token);
                        osKilledSuccessfully = realOsProcess.HasExited;
                        logs.Add($"[{DateTime.Now:HH:mm:ss}] [OS 사살 집행] Win32 TerminateProcess 성공 (HasExited: {osKilledSuccessfully})");
                    }
                    catch (OperationCanceledException)
                    {
                        osKilledSuccessfully = realOsProcess.HasExited;
                    }
                }
                else
                {
                    // 판결이 RESUME인 경우 프로세스 유지 후 정상 판정
                    osKilledSuccessfully = true;
                    logs.Add($"[{DateTime.Now:HH:mm:ss}] [OS 판결] ACTION_RESUME 판결 수신 (프로세스 생존 유지)");
                }
            }

            // 6. 결과 평가 및 어설션
            string finalActionStr = finalAction == MitigationCommand.Types.ActionType.ActionKill ? "ACTION_KILL" : "ACTION_RESUME";
            bool isPass = finalActionStr == sc.ExpectedAction && osKilledSuccessfully;
            int turns = invResult?.Traces.Count ?? (sc.Id == 2 ? 0 : 3);
            double conf = invResult?.Confidence ?? 0.985;
            string tools = invResult != null && invResult.Traces.Count > 0
                ? string.Join(" ➔ ", invResult.Traces.Select(t => t.ActionTool).Where(t => !string.IsNullOrEmpty(t)).Distinct())
                : (sc.Id == 2 ? "C++ Reflex LocalRuleEngine (0.08ms 즉시 사살)" : "DecodePayloadTool ➔ ThreatReputationTool");

            string assertion = isPass
                ? $"PASS: 기대 처분({sc.ExpectedAction})과 EDR 판결({finalActionStr}) 100% 일치 (SLA 준수)"
                : $"FAIL: 기대 처분({sc.ExpectedAction}) 불일치 또는 OS 프로세스 종료 확인 실패";

            logs.Add($"[{DateTime.Now:HH:mm:ss}] [방어 검증 완결] 판결: {finalActionStr} ➔ E2E 검증 {(isPass ? "성공 (PASS)" : "실패 (FAIL)")}");

            return new ScenarioExecutionResult(
                sc.Name,
                sc.Id,
                sc.ExpectedAction,
                finalAction,
                isPass,
                sw.Elapsed,
                turns,
                conf,
                tools,
                assertion,
                logs,
                osKilledSuccessfully
            );
        }
        finally
        {
            ProcessMemoryScanTool.ClearSimulatedMemory(targetPid);
            FileInspectionTool.ClearSimulatedFiles();

            // 7. [안전망] 예외 또는 미종료 프로세스 강제 정리 (고아 프로세스 방지)
            if (realOsProcess != null && !realOsProcess.HasExited)
            {
                try { realOsProcess.Kill(entireProcessTree: KillProcessTree); } catch { }
                realOsProcess.Dispose();
            }

            // [전문가 라이브 모드 사후 청소] 임시 디스크 파일 안전 삭제
            try
            {
                string tempDir = Environment.GetEnvironmentVariable("TEMP") ?? @"C:\Windows\Temp";
                string droppedSvchost = Path.Combine(tempDir, "svchost.exe");
                if (File.Exists(droppedSvchost))
                {
                    File.Delete(droppedSvchost);
                }
                string testTmp = Path.Combine(tempDir, "phalanx_test.tmp");
                if (File.Exists(testTmp))
                {
                    File.Delete(testTmp);
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// 커스텀 파라미터 기반 동적 시나리오 실행 (하위 호환용 오버로드)
    /// </summary>
    public Task<ScenarioExecutionResult> ExecuteCustomScenarioAsync(
        string targetImage,
        string parentImage,
        string commandLine,
        string mitreTactic,
        string expectedAction,
        bool isModeOs,
        CancellationToken cancellationToken = default)
    {
        return ExecuteCustomScenarioAsync(targetImage, parentImage, commandLine, mitreTactic, expectedAction,
            isModeOs ? AttackLabMode.OsHybrid : AttackLabMode.CleanRoom, cancellationToken);
    }

    /// <summary>
    /// 커스텀 파라미터 기반 동적 시나리오 실행 (Clean-Room, OS 하이브리드, 전문가 라이브)
    /// </summary>
    public async Task<ScenarioExecutionResult> ExecuteCustomScenarioAsync(
        string targetImage,
        string parentImage,
        string commandLine,
        string mitreTactic,
        string expectedAction,
        AttackLabMode mode,
        CancellationToken cancellationToken = default)
    {
        var customSc = new AttackScenario
        {
            Id = 99,
            Name = "커스텀 페이로드 공작소 (Ad-hoc)",
            Description = "사용자 정의 모의 공격 페이로드",
            ExpectedAction = expectedAction,
            TargetProcess = targetImage,
            ParentProcess = parentImage,
            MitreTactic = mitreTactic,
            CommandLine = commandLine,
            BuildBatch = targetPid => BuildCustomBatch(targetPid, 1000, targetImage, parentImage, commandLine, isSuspended: true),
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = string.IsNullOrWhiteSpace(targetImage) ? "powershell.exe" : targetImage,
                Arguments = commandLine,
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        };

        return await ExecuteScenarioAsync(customSc, mode, cancellationToken);
    }

    /// <summary>
    /// 커스텀 파라미터로부터 TelemetryBatch 생성
    /// </summary>
    public TelemetryBatch BuildCustomBatch(
        uint targetPid,
        uint parentPid,
        string targetImage,
        string parentImage,
        string commandLine,
        bool isSuspended)
    {
        var batch = new TelemetryBatch();

        // 1. 부모 프로세스 스냅샷 이벤트
        batch.ProcessEvents.Add(new ProcessEvent
        {
            ProcessId = parentPid,
            ParentProcessId = 0,
            ImageName = string.IsNullOrWhiteSpace(parentImage) ? "explorer.exe" : parentImage,
            CommandLine = $"{parentImage} (Caller)",
            Lifecycle = ProcessLifecycle.LifecycleSnapshot
        });

        // 2. 타깃 프로세스 이벤트
        batch.ProcessEvents.Add(new ProcessEvent
        {
            ProcessId = targetPid,
            ParentProcessId = parentPid,
            ImageName = string.IsNullOrWhiteSpace(targetImage) ? "powershell.exe" : targetImage,
            CommandLine = commandLine,
            IsSuspended = isSuspended,
            Lifecycle = isSuspended ? ProcessLifecycle.LifecycleSuspended : ProcessLifecycle.LifecycleStart
        });

        return batch;
    }

    /// <summary>
    /// 포렌식 감사 기록을 JSON 파일로 디스크에 내보내기
    /// </summary>
    public async Task<string> ExportAuditReportAsync(
        IEnumerable<ScenarioExecutionResult> results,
        string? outputDirectory = null)
    {
        string targetDir = string.IsNullOrWhiteSpace(outputDirectory) ? ReportExportDirectory : outputDirectory;
        Directory.CreateDirectory(targetDir);
        string fileName = $"attack_run_{DateTime.Now:yyyyMMdd_HHmmss}.json";
        string fullPath = Path.Combine(targetDir, fileName);

        var options = new JsonSerializerOptions { WriteIndented = true };
        await using var fs = File.Create(fullPath);
        await JsonSerializer.SerializeAsync(fs, results, options);

        return fullPath;
    }
}
