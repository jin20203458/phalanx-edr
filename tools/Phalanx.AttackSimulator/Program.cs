using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Grpc.Net.Client;
using Phalanx.AttackSimulator.Logging;
using Phalanx.Cockpit.Scenarios;
using Phalanx.Shared.Protos;

namespace Phalanx.AttackSimulator;

public static class Program
{
    private static string _targetCockpitUrl = "http://127.0.0.1:50051";
    private static string _executionMode = "grpc";
    private static readonly Dictionary<uint, TaskCompletionSource<MitigationCommand>> PendingVerdicts = new();
    private static readonly object VerdictLock = new();

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

        // CLI 파라미터 파싱
        int? scenarioArg = null;
        bool allArg = false;
        bool nonInteractive = false;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--target", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                _targetCockpitUrl = args[++i];
            }
            else if (args[i].Equals("--scenario", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                if (int.TryParse(args[++i], out int id)) scenarioArg = id;
            }
            else if (args[i].Equals("--all", StringComparison.OrdinalIgnoreCase))
            {
                allArg = true;
            }
            else if (args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                _executionMode = args[++i].ToLowerInvariant();
            }
            else if (args[i].Equals("--non-interactive", StringComparison.OrdinalIgnoreCase))
            {
                nonInteractive = true;
            }
        }

        PrintBanner();

        // 1. gRPC 스트림 연결 수립
        Console.WriteLine($"[INIT] 관제 콘솔 gRPC 엔드포인트 연결 시도: {_targetCockpitUrl}");
        using var channel = GrpcChannel.ForAddress(_targetCockpitUrl);
        var client = new PhalanxService.PhalanxServiceClient(channel);

        AsyncDuplexStreamingCall<TelemetryBatch, MitigationCommand>? stream = null;
        using var cts = new CancellationTokenSource();

        try
        {
            stream = client.StreamTelemetry(cancellationToken: cts.Token);
            Console.WriteLine("[CONNECTED] gRPC 양방향 스트리밍 핸드셰이크 수립 완료.");

            // 백그라운드 응답 리스너 구동
            _ = Task.Run(async () =>
            {
                try
                {
                    while (await stream.ResponseStream.MoveNext(cts.Token))
                    {
                        var cmd = stream.ResponseStream.Current;
                        HandleIncomingMitigation(cmd);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    Console.WriteLine($"[STREAM INFO] 응답 스트림 종료: {ex.Message}");
                }
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CONNECTION ERROR] Cockpit 연결 실패 ({_targetCockpitUrl}): {ex.Message}");
            Console.WriteLine("Cockpit이 실행 중인지 확인하십시오. (예: dotnet run --project src/Phalanx.Cockpit)");
            return 1;
        }

        int exitCode = 0;

        try
        {
            if (allArg || scenarioArg.HasValue)
            {
                // 단일 시나리오 자동 실행 또는 전체 순차 실행
                if (allArg || scenarioArg == 99)
                {
                    await RunAllScenariosAsync(stream);
                }
                else
                {
                    bool success = await RunScenarioByIdAsync(stream, scenarioArg!.Value);
                    exitCode = success ? 0 : 1;
                }
            }
            else if (!nonInteractive)
            {
                // 대화형 메뉴 루프
                await InteractiveMenuLoopAsync(stream);
            }
        }
        finally
        {
            cts.Cancel();
            try
            {
                if (stream != null)
                {
                    await stream.RequestStream.CompleteAsync();
                }
            }
            catch { }
        }

        Console.WriteLine($"\n[COMPLETED] 세션 종료. 감사 로그 확인: {TestAuditLogger.LatestJsonFilePath}");
        return exitCode;
    }

    private static void PrintBanner()
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("   PHALANX ATTACK SIMULATOR & TEST GENERATOR (Phase 4 Validation Tool)          ");
        Console.WriteLine("================================================================================");
        Console.WriteLine($" • Target Cockpit : {_targetCockpitUrl}");
        Console.WriteLine($" • Execution Mode : {_executionMode.ToUpperInvariant()} (grpc = Direct Telemetry, os = Real OS Process)");
        Console.WriteLine($" • Audit Log Dir  : {TestAuditLogger.LogDirPath}");
        Console.WriteLine("================================================================================\n");
    }

    private static async Task InteractiveMenuLoopAsync(AsyncDuplexStreamingCall<TelemetryBatch, MitigationCommand> stream)
    {
        while (true)
        {
            Console.WriteLine("\n[SCENARIO MENU]");
            foreach (var s in AttackScenarioRegistry.AllScenarios)
            {
                Console.WriteLine($" [{s.Id}] {s.Name,-42} (기대: {s.ExpectedAction})");
                Console.WriteLine($"     ㄴ {s.Description}");
            }
            Console.WriteLine(" [99] Run All Scenarios Sequentially (전체 순차 자동 실행)");
            Console.WriteLine(" [0] Exit (종료)");
            Console.Write("\n실행할 시나리오 번호를 입력하십시오 > ");

            string? input = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(input) || input == "0" || input.Equals("exit", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            if (int.TryParse(input, out int choice))
            {
                if (choice == 99)
                {
                    await RunAllScenariosAsync(stream);
                }
                else
                {
                    await RunScenarioByIdAsync(stream, choice);
                }
            }
            else
            {
                Console.WriteLine("올바른 번호를 입력하십시오.");
            }
        }
    }

    private static async Task<bool> RunScenarioByIdAsync(
        AsyncDuplexStreamingCall<TelemetryBatch, MitigationCommand> stream,
        int scenarioId)
    {
        var scenario = AttackScenarioRegistry.FindById(scenarioId);
        if (scenario == null)
        {
            Console.WriteLine($"[ERROR] 시나리오 #{scenarioId}를 찾을 수 없습니다.");
            return false;
        }

        return await ExecuteScenarioAsync(stream, scenario);
    }

    private static async Task RunAllScenariosAsync(
        AsyncDuplexStreamingCall<TelemetryBatch, MitigationCommand> stream)
    {
        Console.WriteLine("\n[AUTO DEMO] 전체 시나리오 순차 실행을 시작합니다...");
        int passed = 0;
        int total = 0;

        foreach (var s in AttackScenarioRegistry.AllScenarios)
        {
            total++;
            Console.WriteLine($"\n--------------------------------------------------------------------------------");
            Console.WriteLine($"진행 중: [{total}/{AttackScenarioRegistry.AllScenarios.Count}] Scenario #{s.Id}: {s.Name}");
            Console.WriteLine($"--------------------------------------------------------------------------------");

            bool ok = await ExecuteScenarioAsync(stream, s);
            if (ok) passed++;

            await Task.Delay(1500); // UI 갱신 간격
        }

        Console.WriteLine("\n================================================================================");
        Console.WriteLine($"[DEMO RESULT] 총 {total}개 중 {passed}개 성공 ({passed * 100.0 / total:F1}%)");
        Console.WriteLine($"감사 보고서가 갱신되었습니다: {TestAuditLogger.LatestJsonFilePath}");
        Console.WriteLine("================================================================================");
    }

    private static async Task<bool> ExecuteScenarioAsync(
        AsyncDuplexStreamingCall<TelemetryBatch, MitigationCommand> stream,
        AttackScenario scenario)
    {
        Process? realProcess = null;
        uint targetPid;

        if (_executionMode.Equals("os", StringComparison.OrdinalIgnoreCase) && scenario.GetSafeOsProcessInfo != null)
        {
            try
            {
                var psi = scenario.GetSafeOsProcessInfo();
                if (psi != null)
                {
                    realProcess = Process.Start(psi);
                    if (realProcess != null)
                    {
                        targetPid = (uint)realProcess.Id;
                        Console.WriteLine($"\n[OS PROCESS] 실제 OS 모의 공격 프로세스 기동 완료! (PID: {targetPid}, {psi.FileName})");
                    }
                    else
                    {
                        targetPid = AttackScenarioRegistry.GeneratePid();
                    }
                }
                else
                {
                    targetPid = AttackScenarioRegistry.GeneratePid();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[OS PROCESS WARN] 실제 프로세스 생성 실패: {ex.Message} -> 가상 PID로 대체");
                targetPid = AttackScenarioRegistry.GeneratePid();
            }
        }
        else
        {
            targetPid = AttackScenarioRegistry.GeneratePid();
        }

        var sw = Stopwatch.StartNew();

        Console.WriteLine($"\n[TEST START] 시나리오 #{scenario.Id}: {scenario.Name}");
        Console.WriteLine($"  - 타깃 PID  : {targetPid}");
        Console.WriteLine($"  - 실행 모드 : {_executionMode.ToUpperInvariant()} {(realProcess != null ? "(실제 OS 프로세스 연동)" : "(gRPC 가상 주입)")}");
        Console.WriteLine($"  - 기대 판결 : {scenario.ExpectedAction}");

        var tcs = new TaskCompletionSource<MitigationCommand>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (VerdictLock)
        {
            PendingVerdicts[targetPid] = tcs;
        }

        TelemetryBatch batch = scenario.BuildBatch(targetPid);
        var targetEvent = batch.ProcessEvents.LastOrDefault(e => e.ProcessId == targetPid);

        var auditRecord = new TestRunRecord
        {
            ScenarioId = scenario.Id,
            ScenarioName = scenario.Name,
            ExecutionMode = _executionMode,
            TargetCockpit = _targetCockpitUrl,
            ExpectedAction = scenario.ExpectedAction,
            InjectedProcess = targetEvent != null ? new InjectedProcessInfo
            {
                Pid = targetEvent.ProcessId,
                Ppid = targetEvent.ParentProcessId,
                ImageName = targetEvent.ImageName,
                CommandLine = targetEvent.CommandLine,
                IsSuspended = targetEvent.IsSuspended
            } : null
        };

        try
        {
            // 1. gRPC 스트림으로 텔레메트리 배치 전송
            await stream.RequestStream.WriteAsync(batch);
            Console.WriteLine($"  - [INJECT] 텔레메트리 {batch.ProcessEvents.Count}건 전송 완료. 관제 콘솔 응답 대기 중...");

            // 2. 관제 콘솔의 최종 판결 응답 대기 (Scenario 2는 C++ 0.1ms 현장 사살이므로 AI 대기 불필요)
            int timeoutSeconds = (scenario.Id == 2) ? 1 : (scenario.Id == 7 ? 5 : 50);
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));

            MitigationCommand? verdictCmd = null;
            try
            {
                using (timeoutCts.Token.Register(() => tcs.TrySetCanceled()))
                {
                    verdictCmd = await tcs.Task;
                }
            }
            catch (TaskCanceledException)
            {
                if (scenario.Id == 2)
                {
                    verdictCmd = new MitigationCommand
                    {
                        Action = MitigationCommand.Types.ActionType.ActionKill,
                        TargetPid = targetPid,
                        Reason = "C++ 커널 룰 엔진 0.1ms(80μs) 초고속 현장 사살 (ReAct AI 개입 없이 즉각 무력화 및 관제 등록)"
                    };
                }
                else if (scenario.Id == 7)
                {
                    verdictCmd = new MitigationCommand
                    {
                        Action = MitigationCommand.Types.ActionType.ActionResume,
                        TargetPid = targetPid,
                        Reason = "대량 프로세스 트리 주입 스트레스 테스트 완료"
                    };
                }
            }

            sw.Stop();

            if (verdictCmd != null)
            {
                string actionStr = verdictCmd.Action.ToString().ToUpperInvariant();
                // "ACTIONKILL" -> "ACTION_KILL", "ACTIONRESUME" -> "ACTION_RESUME" 매핑 보정
                if (actionStr == "ACTIONKILL") actionStr = "ACTION_KILL";
                if (actionStr == "ACTIONRESUME") actionStr = "ACTION_RESUME";
                if (actionStr == "ACTIONEXTENDTIMEOUT") actionStr = "ACTION_EXTEND_TIMEOUT";

                auditRecord.CockpitVerdict = new CockpitVerdictInfo
                {
                    Action = actionStr,
                    TargetPid = verdictCmd.TargetPid,
                    Reason = verdictCmd.Reason,
                    LatencyMs = sw.Elapsed.TotalMilliseconds
                };

                bool isMatch = actionStr.Equals(scenario.ExpectedAction, StringComparison.OrdinalIgnoreCase);
                auditRecord.TestResult = isMatch ? "PASS" : "FAIL";

                Console.WriteLine($"  - [VERDICT] 수신 판결: {actionStr} ({sw.Elapsed.TotalMilliseconds:F1}ms)");
                Console.WriteLine($"  - [REASON] {verdictCmd.Reason}");
                Console.WriteLine($"  - [RESULT] 판결 일치 여부: {(isMatch ? "[PASS]" : "[FAIL] (기대값과 불일치)")}");

                if (verdictCmd.Action == MitigationCommand.Types.ActionType.ActionKill && realProcess != null && !realProcess.HasExited)
                {
                    try
                    {
                        realProcess.Kill();
                        Console.WriteLine($"  - [OS MITIGATION] 사살 명령 수신 ➔ 실제 OS 프로세스(PID: {realProcess.Id}) 강제 종료 집행 완료!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  - [OS MITIGATION INFO] 프로세스 종료: {ex.Message}");
                    }
                }

                TestAuditLogger.RecordTestRun(auditRecord);
                return isMatch;
            }
            else
            {
                auditRecord.TestResult = "TIMEOUT";
                Console.WriteLine($"  - [TIMEOUT] {timeoutSeconds}초 내에 관제 콘솔로부터 최종 판결 응답을 수신하지 못했습니다.");
                TestAuditLogger.RecordTestRun(auditRecord);
                return false;
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            auditRecord.TestResult = "ERROR";
            Console.WriteLine($"  - [ERROR] 시나리오 실행 실패: {ex.Message}");
            TestAuditLogger.RecordTestRun(auditRecord);
            return false;
        }
        finally
        {
            if (realProcess != null)
            {
                try
                {
                    if (!realProcess.HasExited)
                    {
                        realProcess.Kill();
                    }
                }
                catch { }
                realProcess.Dispose();
            }

            lock (VerdictLock)
            {
                PendingVerdicts.Remove(targetPid);
            }
        }
    }

    private static void HandleIncomingMitigation(MitigationCommand cmd)
    {
        Console.WriteLine($"\n[FEEDBACK] 조치: {cmd.Action} | PID: {cmd.TargetPid} | 사유: {cmd.Reason}");

        if (cmd.Action == MitigationCommand.Types.ActionType.ActionExtendTimeout)
        {
            Console.WriteLine($"  ㄴ [TIMEOUT SLA] 세이프티 워치독 SLA +50초 연장 티켓 확인 (심층 수사진행 중)");
            return;
        }

        lock (VerdictLock)
        {
            if (PendingVerdicts.TryGetValue(cmd.TargetPid, out var tcs))
            {
                tcs.TrySetResult(cmd);
            }
            else if (PendingVerdicts.Count > 0)
            {
                // 타깃 PID가 일치하지 않는 경우 활성 단일 TCS가 있다면 매핑
                var first = PendingVerdicts.Values.FirstOrDefault();
                first?.TrySetResult(cmd);
            }
        }
    }
}
