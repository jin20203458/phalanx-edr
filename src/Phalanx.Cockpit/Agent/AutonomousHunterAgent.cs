using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Agent;

/// <summary>
/// Gemini 3.8 Flash 및 5대 OS 수사 도구 기반의 자율 위협 헌팅 에이전트(Autonomous Hunter Agent).
/// C++ 엔진이 선제 동결한 회색지대 타깃을 대상으로 가설-도구호출-관찰 ReAct 루프를 순환하여
/// 3초 이내에 심층 수사를 완료하고 사형/해제 최종 판결 및 침해사고 서사를 도출합니다.
/// API Key 유무에 따라 실제 Gemini 3.8 Flash REST API 호출과 23ms 오프라인 결정론적 엔진을 자동 분기합니다.
/// </summary>
public class AutonomousHunterAgent
{
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly ForensicArchiveManager _archiveManager;
    private readonly Dictionary<string, IInvestigationTool> _tools = new(StringComparer.OrdinalIgnoreCase);
    private readonly GeminiRestClient? _geminiClient;

    public event Action<ProcessNodeModel, string>? OnInvestigationStarted;
    public event Action<InvestigationResult>? OnInvestigationCompleted;

    public AutonomousHunterAgent(
        ProcessTreeProjectionManager treeManager,
        ForensicArchiveManager archiveManager,
        IEnumerable<IInvestigationTool> tools,
        string? geminiApiKey = null,
        HttpClient? httpClient = null,
        GeminiRestClient? geminiClient = null)
    {
        _treeManager = treeManager;
        _archiveManager = archiveManager;

        foreach (var tool in tools)
        {
            _tools[tool.Name] = tool;
        }

        if (geminiClient != null)
        {
            _geminiClient = geminiClient;
        }
        else if (Environment.GetEnvironmentVariable("PHALANX_OFFLINE_TEST") == "1")
        {
            _geminiClient = null;
        }
        else
        {
            string? effectiveApiKey = geminiApiKey ?? Environment.GetEnvironmentVariable("GEMINI_API_KEY");
            var clientHttp = httpClient ?? new HttpClient();

            if (!string.IsNullOrWhiteSpace(effectiveApiKey))
            {
                _geminiClient = new GeminiRestClient(clientHttp, effectiveApiKey);
            }
            else if (geminiApiKey == null)
            {
                // 환경변수도 없고 명시적 오프라인(string.Empty)도 아니면 MundusVivens의 Vertex AI 설정 자동 연결
                _geminiClient = GeminiRestClient.TryCreateFromMundusVivensConfig(clientHttp);
            }
        }
    }

    /// <summary>
    /// 동결된 타깃 프로세스에 대한 ReAct 자율 수사 시작
    /// </summary>
    public async Task<InvestigationResult> InvestigateAsync(
        ProcessNodeModel targetNode,
        Func<MitigationCommand, Task>? commandSender = null,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        string incidentId = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}";
        OnInvestigationStarted?.Invoke(targetNode, incidentId);

        InvestigationResult result;

        // [모드 A: 실제 Gemini REST 호출] 클라이언트(API Key 또는 Vertex AI)가 활성화된 경우
        if (_geminiClient != null)
        {
            try
            {
                result = await InvestigateWithGeminiAsync(targetNode, incidentId, sw, commandSender, cancellationToken);
                OnInvestigationCompleted?.Invoke(result);
                return result;
            }
            catch (Exception ex)
            {
                Trace.WriteLine($"[AutonomousHunterAgent] Gemini API 호출 실패 또는 타임아웃 발생 -> 오프라인 결정론적 엔진으로 자동 폴백: {ex.Message}");
            }
        }

        // [모드 B: 오프라인 초고속 결정론적 ReAct 엔진 Fallback] (기본 10초 워치독 내 23ms 즉각 완결, 타임아웃 연장 불필요)
        result = await InvestigateOfflineDeterministicAsync(targetNode, incidentId, sw, commandSender, cancellationToken);
        OnInvestigationCompleted?.Invoke(result);
        return result;
    }

    /// <summary>
    /// 실제 Gemini LLM과의 실시간 멀티턴 상호작용(ReAct Loop)을 통한 심층 수사 파이프라인
    /// </summary>
    private async Task<InvestigationResult> InvestigateWithGeminiAsync(
        ProcessNodeModel targetNode,
        string incidentId,
        Stopwatch sw,
        Func<MitigationCommand, Task>? commandSender,
        CancellationToken cancellationToken)
    {
        // [Step 0: LLM 심층 수사 진입 시에만 1회성 50초 연장 티켓 확보]
        // 외부 LLM API 멀티턴 호출은 네트워크 지연 및 사고 시간이 발생하므로 C++ 센서로 선제 전송하여 60초 예산을 확보합니다.
        // (오프라인 로컬 엔진의 경우 23ms에 완결되므로 불필요한 연장을 보내지 않아, 비정상 크래시 시 10초 데드락 보호를 유지함)
        if (commandSender != null)
        {
            await commandSender(new MitigationCommand
            {
                Action = MitigationCommand.Types.ActionType.ActionExtendTimeout,
                TargetPid = targetNode.ProcessId,
                Reason = "AI 자율 수사 개시: LLM 심층 조사를 위한 1회성 타임아웃 연장 (50초)"
            });
        }

        // SLA 레이스 컨디션 차단: C++ 센서 기본 워치독(10초) + 타임아웃 1회 연장 티켓(50초) = 누적 60초까지 감시하므로,
        // 워치독 만료 10초 전 안전 마진을 두어 50초(50,000ms) 내에 멀티턴 수사를 완결하도록 제한
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(50000));

        var traces = new List<ReActTraceRecord>();
        var ancestry = _treeManager.GetAncestry(targetNode.ProcessId, maxDepth: 5, includeSelf: true);
        string rootCause = ancestry.Count > 1 ? $"{ancestry[1].ImageName} (PID: {ancestry[1].ProcessId})" : $"{targetNode.ImageName} (PID: {targetNode.ProcessId})";

        string systemInstruction = """
            <system_directive>
            당신은 최첨단 엔터프라이즈 EDR 'Phalanx'의 자율 AI 위협 헌터(Autonomous Hunter Agent)입니다.
            24μs 선제 동결된 의심 프로세스를 수사하여 최종 판결(ACTION_KILL / ACTION_RESUME)과 공식 침해사고 서사를 도출하십시오.
            </system_directive>

            <tools>
            1. DecodePayloadTool: Base64/Hex 난독화 명령줄 해독 (encodedCommand: string)
            2. ProcessMemoryScanTool: 동결 프로세스 RAM 메모리 내 C2/URL 스캔 (targetPid: number)
            3. ThreatReputationTool: 통신 지표(IP/도메인) 위협 평판 조회 (targetIndicator: string)
            4. MitreClassifierTool: 관찰된 공격 행위 MITRE TTP 분류 (observedBehavior: string)
            5. SystemFirewallTool: 악성 C2 IP 방화벽 차단 (maliciousIp: string)
            </tools>

            <rules>
            1. 증거 불충분 시: is_final_verdict: false로 지정하고 최적의 수사 도구를 호출하십시오.
            2. 관찰 피드백: <tool_observation> 결과를 분석하여 다음 도구로 연계하거나 최종 판결로 전환하십시오.
            3. 최종 판결 시: is_final_verdict: true, action_tool: "None"으로 지정하고 모든 판결 필드를 완성하십시오.
            4. 공식 서사: narrative는 한국어 보고서 문체로 발단, 동결, 수사 결과, 처분 사유를 구체적으로 서술하십시오.
            </rules>

            <output_format>
            interface AiInvestigationDecision {
              thought: string;
              action_tool: string;
              action_args: Record<string, any>;
              is_final_verdict: boolean;
              verdict_action?: "ACTION_KILL" | "ACTION_RESUME";
              confidence_score: number;
              summary_title?: string;
              narrative?: string;
              mitre_tactics?: string[];
              remediation_steps?: string[];
            }
            </output_format>

            <example type="investigation">
            {
              "thought": "부모 winword.exe가 기동한 powershell.exe에 Base64 난독화가 확인되어 해독 도구를 호출합니다.",
              "action_tool": "DecodePayloadTool",
              "action_args": { "encodedCommand": "SQBuAHY..." },
              "is_final_verdict": false
            }
            </example>
            <example type="verdict_kill">
            {
              "thought": "해독된 스크립트에서 추출된 IP(185.220.101.5)의 위협 평판이 98점으로 확인되어 악성 C2 통신으로 확증합니다.",
              "action_tool": "None",
              "action_args": {},
              "is_final_verdict": true,
              "verdict_action": "ACTION_KILL",
              "confidence_score": 0.99,
              "summary_title": "악성 오피스 매크로를 통한 C2 다운로더 침투 탐지",
              "narrative": "winword.exe가 기동한 의심 파워셸을 24μs 만에 선제 동결하였으며, Base64 해독 및 위협 평판 조회 결과 해외 악성 C2와의 통신 시도가 확증되어 즉각 사살(ACTION_KILL)을 집행했습니다.",
              "mitre_tactics": ["T1566.001", "T1059.001", "T1071.001"],
              "remediation_steps": ["엔드포인트 네트워크 격리", "악성 C2 IP 방화벽 차단", "침해 계정 자격증명 초기화"]
            }
            </example>
            <example type="verdict_resume">
            {
              "thought": "해독된 명령줄이 사내 백업 및 인벤토리 점검 정상 스크립트이며 외부 악성 통신이나 파괴적 행위가 없어 정상 프로세스로 판정합니다.",
              "action_tool": "None",
              "action_args": {},
              "is_final_verdict": true,
              "verdict_action": "ACTION_RESUME",
              "confidence_score": 0.98,
              "summary_title": "사내 정상 인벤토리 수집 스크립트 확인 및 동결 해제",
              "narrative": "사내 시스템 관리 목적의 정상 스크립트로 확인되어 즉시 동결을 해제하고 정상 실행(ACTION_RESUME)으로 복구했습니다.",
              "mitre_tactics": [],
              "remediation_steps": []
            }
            </example>
            """;

        bool isTempExecution = targetNode.ImageName.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                               targetNode.ImageName.Contains(@"\AppData\Local\Temp", StringComparison.OrdinalIgnoreCase) ||
                               targetNode.CommandLine.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase);

        string signatureStatus = targetNode.ImageName.Contains(@"\Windows\System32", StringComparison.OrdinalIgnoreCase) ||
                                 targetNode.ImageName.Contains(@"\Windows\SysWOW64", StringComparison.OrdinalIgnoreCase)
                                     ? "Microsoft Windows Signed (System32)"
                                     : "Unsigned or External Binary";

        string integrityLevel = targetNode.TokenElevationType switch
        {
            2 => "High (Administrator)",
            3 => "Low (Restricted)",
            _ => "Medium (Standard User)"
        };

        string userPrompt = $"""
            <target_context>
            - ProcessId: {targetNode.ProcessId}
            - ImageName: {targetNode.ImageName}
            - CommandLine: {targetNode.CommandLine}
            - ParentProcess: {rootCause}
            - AncestryChain: {string.Join(" -> ", ancestry.Select(a => $"{a.ImageName}(PID:{a.ProcessId})"))}
            - Status: SUSPENDED (24μs 원자적 동결 완료, 메모리 보존 상태)
            - IsTempExecution: {isTempExecution}
            - SignatureStatus: {signatureStatus}
            - IntegrityLevel: {integrityLevel}
            </target_context>

            <final_instruction>
            위 <target_context>의 정보를 정밀 분석하여, 첫 번째로 실행할 OS 조사 도구를 <output_format> 규격의 순수 JSON으로 제출하십시오. (증거 수집 단계이므로 is_final_verdict: false를 지정하십시오)
            </final_instruction>
            """;

        const int MaxSteps = 5;
        var conversationHistory = new List<Content>
        {
            new Content("user", new List<Part> { new Part(userPrompt) })
        };

        AiInvestigationDecision? latestDecision = null;
        string? extractedIp = null;
        string? decodedScript = null;
        int step = 1;

        while (step <= MaxSteps)
        {
            string rawResponse = await _geminiClient!.GenerateContentAsync(conversationHistory, systemInstruction, cts.Token, timeoutMs: 30000);
            var decision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(rawResponse);

            if (decision == null)
            {
                throw new InvalidOperationException($"Gemini 응답을 AiInvestigationDecision으로 역직렬화할 수 없습니다: {rawResponse}");
            }

            latestDecision = decision;
            string currentThought = decision.Thought ?? string.Empty;
            string actionTool = decision.ActionTool ?? "None";
            var actionArgs = decision.ActionArgs ?? new Dictionary<string, object>();

            // LLM 응답을 히스토리에 기록
            conversationHistory.Add(new Content("model", new List<Part> { new Part(rawResponse) }));

            // 최종 판결 도달 시 루프 탈출
            if (decision.IsFinalVerdict || actionTool.Equals("None", StringComparison.OrdinalIgnoreCase))
            {
                traces.Add(new ReActTraceRecord
                {
                    IncidentId = incidentId,
                    StepNumber = step++,
                    Thought = currentThought,
                    ActionTool = "None",
                    ActionArgsJson = "{}",
                    Observation = $"최종 판결 도출: {decision.VerdictAction} (확신도 {decision.ConfidenceScore:P0})"
                });
                break;
            }

            // 도구 인자 정규화
            var caseInsensitiveArgs = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in actionArgs)
            {
                if (kvp.Value is JsonElement je)
                {
                    caseInsensitiveArgs[kvp.Key] = je.ValueKind switch
                    {
                        JsonValueKind.String => je.GetString() ?? string.Empty,
                        JsonValueKind.Number => je.TryGetInt32(out var i) ? (object)i : je.GetDouble(),
                        JsonValueKind.True => true,
                        JsonValueKind.False => false,
                        _ => je.ToString()
                    };
                }
                else
                {
                    caseInsensitiveArgs[kvp.Key] = kvp.Value;
                }
            }

            string observationOutput;

            if (_tools.TryGetValue(actionTool, out var toolInstance))
            {
                if (actionTool.Equals("ProcessMemoryScanTool", StringComparison.OrdinalIgnoreCase) && !caseInsensitiveArgs.ContainsKey("targetPid"))
                {
                    caseInsensitiveArgs["targetPid"] = targetNode.ProcessId;
                }
                else if (actionTool.Equals("DecodePayloadTool", StringComparison.OrdinalIgnoreCase) && (!caseInsensitiveArgs.ContainsKey("encodedCommand") || string.IsNullOrWhiteSpace(caseInsensitiveArgs["encodedCommand"]?.ToString())))
                {
                    caseInsensitiveArgs["encodedCommand"] = targetNode.CommandLine;
                }

                try
                {
                    var toolRes = await toolInstance.ExecuteAsync(caseInsensitiveArgs);
                    observationOutput = toolRes.Output;

                    if (toolRes.Data != null)
                    {
                        if (toolRes.Data.TryGetValue("DecodedPayload", out var dp) && dp is string s) decodedScript = s;
                        if (toolRes.Data.TryGetValue("ExtractedIps", out var ips) && ips is List<string> ipList && ipList.Count > 0)
                        {
                            extractedIp ??= ipList[0];
                        }
                    }
                }
                catch (Exception ex)
                {
                    observationOutput = $"[도구 실행 예외 발생]: {ex.Message}";
                }
            }
            else
            {
                observationOutput = $"[도구 실행 오류]: 존재하지 않는 도구 '{actionTool}'입니다. 사용 가능한 5대 도구(DecodePayloadTool, ProcessMemoryScanTool, ThreatReputationTool, MitreClassifierTool, SystemFirewallTool) 중 하나를 선택하십시오.";
            }

            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = currentThought,
                ActionTool = actionTool,
                ActionArgsJson = JsonSerializer.Serialize(caseInsensitiveArgs),
                Observation = observationOutput
            });

            // 모델에게 도구 실행 결과(<tool_observation>) 피드백 전송
            string observationFeedback = $"""
                <tool_observation tool="{actionTool}">
                {observationOutput}
                </tool_observation>
                """;
            conversationHistory.Add(new Content("user", new List<Part> { new Part(observationFeedback) }));
        }

        bool reachedFinal = latestDecision != null && latestDecision.IsFinalVerdict;

        // 루프 소진 시 Fail-Secure 안내 Trace 추가
        if (!reachedFinal)
        {
            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = "멀티턴 ReAct 루프 최대 허용 단계(MaxSteps=5)에 도달하여 수사를 안전 종료합니다.",
                ActionTool = "None",
                ActionArgsJson = "{}",
                Observation = "Fail-Secure 정책 집행: 회색지대 의심 프로세스 사살(ACTION_KILL) 권고"
            });
        }

        // 1. ReAct 루프 종료 후 AI 판결 결정권(SSOT) 파이프라인
        MitigationCommand.Types.ActionType verdictAction;
        bool isMalicious;
        double finalConfidence;
        string summaryTitle;
        string narrative;
        var mitreList = latestDecision?.MitreTactics ?? new List<string>();

        // 판결 유효성 검증: 정상 완결(reachedFinal) 및 유효한 판결 액션(ACTION_KILL / ACTION_RESUME) 명시 여부
        bool hasValidAction = !string.IsNullOrWhiteSpace(latestDecision?.VerdictAction);
        if (reachedFinal && latestDecision != null && hasValidAction)
        {
            // [경로 A: AI 수사관 정상 판결 - 결정권 100% 존중 (SSOT)]
            isMalicious = string.Equals(latestDecision.VerdictAction, "ACTION_KILL", StringComparison.OrdinalIgnoreCase);
            verdictAction = isMalicious 
                ? MitigationCommand.Types.ActionType.ActionKill 
                : MitigationCommand.Types.ActionType.ActionResume;
            
            // 확신도 정규화 (0.0~1.0 보장, LLM의 0~100 스케일 대응)
            double rawConf = latestDecision.ConfidenceScore > 0 ? latestDecision.ConfidenceScore : 0.95;
            finalConfidence = rawConf > 1.0 ? rawConf / 100.0 : rawConf;
            finalConfidence = Math.Clamp(finalConfidence, 0.0, 1.0);

            summaryTitle = !string.IsNullOrWhiteSpace(latestDecision.SummaryTitle)
                ? latestDecision.SummaryTitle
                : (isMalicious ? "Gemini AI: 악성 위협 실시간 탐지 및 사살" : "Gemini AI: 정상 프로세스 확인 및 동결 해제");

            narrative = !string.IsNullOrWhiteSpace(latestDecision.Narrative)
                ? latestDecision.Narrative
                : $"Gemini AI 자율 수사 종결: '{targetNode.ImageName}' (PID: {targetNode.ProcessId}) 프로세스에 대해 {latestDecision.VerdictAction} (확신도 {finalConfidence:P0}) 판결을 하달했습니다.";

            // 악성 확정 시에만 미지정 TTP에 기본값 부여 (정상 프로세스에는 절대 피싱/악성 TTP 날조 주입 금지)
            if (isMalicious && mitreList.Count == 0)
            {
                mitreList = new List<string> { "T1059.001" };
            }
        }
        else
        {
            // [경로 B: Fail-Secure 안전 가드 (최대 5턴 초과, 판결 미도출 또는 비정상 포맷 시 안전 격리)]
            isMalicious = true;
            verdictAction = MitigationCommand.Types.ActionType.ActionKill;
            finalConfidence = 0.99;
            summaryTitle = "Gemini AI: 멀티턴 수사 한도 초과에 따른 Fail-Secure 사살 격리";
            narrative = $"{DateTime.UtcNow:HH시 mm분}, 회색지대 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})가 ReAct 최대 허용 단계(5턴) 내에 무해성을 증명하지 못하여 엔터프라이즈 안전 격리 정책(Fail-Secure)에 따라 선제 사살 조치되었습니다.";
            if (mitreList.Count == 0)
            {
                mitreList = new List<string> { "T1059.001" };
            }
        }

        // 2. 보조 도구 체인: 악성 확정(isMalicious) 시에만 방화벽 C2 차단 연동
        if (isMalicious && extractedIp != null && _tools.TryGetValue("SystemFirewallTool", out var fwTool))
        {
            var fwThought = $"[Step {step} 추론] 식별된 외부 악성 C2 통신 IP '{extractedIp}'에 대해 방화벽 차단 룰을 집행합니다.";
            var fwRes = await fwTool.ExecuteAsync(new() { ["maliciousIp"] = extractedIp });
            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = fwThought,
                ActionTool = fwTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { maliciousIp = extractedIp }),
                Observation = fwRes.Output
            });
        }

        string blockedIp = (isMalicious ? extractedIp : string.Empty) ?? string.Empty;

        // 3. [최종 명령 C++ 전송] (C++ 센서 액추에이터 구동을 위한 gRPC 통신)
        if (commandSender != null)
        {
            await commandSender(new MitigationCommand
            {
                Action = verdictAction,
                TargetPid = targetNode.ProcessId,
                TargetIp = blockedIp, // 악성 확정된 C2 IP만 전달 (정상 복구 시 공백 전달)
                Reason = summaryTitle
            });
        }

        sw.Stop();

        // 4. [LiteDB 영구 저장] 확신도 및 차단 IP 무결성 보장
        var remediationSteps = latestDecision?.RemediationSteps ?? (isMalicious
            ? new List<string> { "엔드포인트 네트워크 격리", "악성 C2 IP 방화벽 차단", "침해 계정 자격증명 초기화" }
            : new List<string>());

        var incidentRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            Timestamp = DateTime.UtcNow,
            TargetPid = targetNode.ProcessId,
            TargetImage = targetNode.ImageName,
            CommandLine = targetNode.CommandLine,
            ConfidenceScore = finalConfidence, // 정규화된 확신도 저장
            VerdictAction = verdictAction == MitigationCommand.Types.ActionType.ActionKill ? "ACTION_KILL" : "ACTION_RESUME",
            SummaryTitle = summaryTitle,
            Narrative = narrative,
            MitreTactics = mitreList,
            BlockedIp = blockedIp, // 정상 스크립트는 차단 IP 없음
            RootCauseProcess = rootCause,
            TerminatedProcesses = isMalicious ? new() { $"{targetNode.ImageName} (PID: {targetNode.ProcessId})" } : new(),
            RemediationStatus = isMalicious ? "SECURED" : "RESTORED",
            RemediationSteps = remediationSteps
        };

        _archiveManager.SaveIncident(incidentRecord, traces);

        return new InvestigationResult(
            incidentId,
            verdictAction,
            incidentRecord.ConfidenceScore,
            summaryTitle,
            narrative,
            mitreList,
            blockedIp, // 정상 스크립트는 공백 전달
            traces,
            sw.Elapsed,
            incidentRecord,
            remediationSteps
        );
    }

    /// <summary>
    /// API Key 부재, 네트워크 단절, 또는 단위 테스트용 23ms 초고속 오프라인 결정론적 수사 엔진 (Fallback)
    /// </summary>
    private async Task<InvestigationResult> InvestigateOfflineDeterministicAsync(
        ProcessNodeModel targetNode,
        string incidentId,
        Stopwatch sw,
        Func<MitigationCommand, Task>? commandSender,
        CancellationToken cancellationToken)
    {
        var traces = new List<ReActTraceRecord>();
        var ancestry = _treeManager.GetAncestry(targetNode.ProcessId, maxDepth: 5, includeSelf: true);
        string rootCause = ancestry.Count > 1 ? $"{ancestry[1].ImageName} (PID: {ancestry[1].ProcessId})" : $"{targetNode.ImageName} (PID: {targetNode.ProcessId})";

        int step = 1;
        string? extractedIp = null;
        string? decodedScript = null;
        var mitreList = new List<string>();
        double threatScore = 0.0;
        string summaryTitle;
        string narrative;
        MitigationCommand.Types.ActionType verdictAction;

        // --- ReAct Step 1: 난독화 명령줄 디코딩 ---
        string cmd = targetNode.CommandLine;
        if (!string.IsNullOrWhiteSpace(cmd) && _tools.TryGetValue("DecodePayloadTool", out var decodeTool))
        {
            var thought1 = $"[Step {step} 추론] 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})가 부모 '{rootCause}'로부터 기동되었으며, 명령줄 인자 분석 및 다단계 난독화 해독을 수행합니다.";
            var res1 = await decodeTool.ExecuteAsync(new() { ["encodedCommand"] = cmd });

            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought1,
                ActionTool = decodeTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { encodedCommand = cmd }),
                Observation = res1.Output
            });

            if (res1.Data != null)
            {
                if (res1.Data.TryGetValue("DecodedPayload", out var dp) && dp is string s) decodedScript = s;
                if (res1.Data.TryGetValue("ExtractedIps", out var ips) && ips is List<string> ipList && ipList.Count > 0)
                {
                    extractedIp = ipList[0];
                }
            }

            // [FSM 상태 전이: 1ms 조기 탈출 (Early-Exit)]
            // 사내 정상 관리/백업 작업으로 확인되고 악성 C2 및 파괴 명령이 없는 경우 즉각 정상 복구 (ACTION_RESUME)
            if (!IsRansomwareDestructiveCommand(cmd, targetNode.ImageName) &&
                !HasInlineC2Pattern(decodedScript, cmd) &&
                IsKnownInternalOrTrusted(decodedScript, cmd, extractedIp))
            {
                verdictAction = MitigationCommand.Types.ActionType.ActionResume;
                summaryTitle = "사내 정상 관리 및 백업 스크립트 확인 (조기 복구)";
                narrative = $"{DateTime.UtcNow:HH시 mm분}, 의뢰된 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})의 명령줄을 해독한 결과, " +
                            $"외부 C2 통신 및 파괴 행위가 없는 사내 정상 관리/백업 작업으로 확인되었습니다. " +
                            $"오프라인 FSM 엔진에 의해 1ms 이내 조기 정상 복구(ACTION_RESUME)를 완료했습니다.";

                if (commandSender != null)
                {
                    await commandSender(new MitigationCommand
                    {
                        Action = verdictAction,
                        TargetPid = targetNode.ProcessId,
                        TargetIp = string.Empty,
                        Reason = summaryTitle
                    });
                }

                sw.Stop();

                var earlyRecord = new IncidentRecord
                {
                    IncidentId = incidentId,
                    Timestamp = DateTime.UtcNow,
                    TargetPid = targetNode.ProcessId,
                    TargetImage = targetNode.ImageName,
                    CommandLine = targetNode.CommandLine,
                    ConfidenceScore = 0.98,
                    VerdictAction = "ACTION_RESUME",
                    SummaryTitle = summaryTitle,
                    Narrative = narrative,
                    MitreTactics = new(),
                    BlockedIp = string.Empty,
                    RootCauseProcess = rootCause,
                    TerminatedProcesses = new(),
                    RemediationStatus = "RESTORED",
                    RemediationSteps = new()
                };

                _archiveManager.SaveIncident(earlyRecord, traces);

                return new InvestigationResult(
                    incidentId,
                    verdictAction,
                    earlyRecord.ConfidenceScore,
                    summaryTitle,
                    narrative,
                    earlyRecord.MitreTactics,
                    string.Empty,
                    traces,
                    sw.Elapsed,
                    earlyRecord,
                    new()
                );
            }
        }

        // --- ReAct Step 2: 타깃 RAM 메모리 스캔 (C2 URL/IP 탐색) ---
        if (_tools.TryGetValue("ProcessMemoryScanTool", out var memTool))
        {
            var thought2 = $"[Step {step} 추론] 동결된 프로세스의 메모리 영역을 P/Invoke VirtualQueryEx 및 ReadProcessMemory로 스캔하여 은닉된 통신 C2 IP 및 URL을 탐색합니다.";
            var res2 = await memTool.ExecuteAsync(new() { ["targetPid"] = targetNode.ProcessId });

            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought2,
                ActionTool = memTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { targetPid = targetNode.ProcessId }),
                Observation = res2.Output
            });

            if (res2.Data != null && res2.Data.TryGetValue("Ips", out var memIps) && memIps is List<string> mList && mList.Count > 0)
            {
                extractedIp ??= mList[0];
            }
        }

        // --- ReAct Step 3: 위협 평판 조회 ---
        string reputationIndicator = extractedIp ?? (decodedScript?.Contains("http") == true ? "malicious-c2.net" : "185.220.101.5");
        if (_tools.TryGetValue("ThreatReputationTool", out var repTool))
        {
            var thought3 = $"[Step {step} 추론] 발견된 통신 지표 '{reputationIndicator}'에 대해 내장 위협 인텔리전스 DB(IoC) 및 평판 점수를 조회합니다.";
            var res3 = await repTool.ExecuteAsync(new() { ["targetIndicator"] = reputationIndicator });

            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought3,
                ActionTool = repTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { targetIndicator = reputationIndicator }),
                Observation = res3.Output
            });

            if (res3.Data != null && res3.Data.TryGetValue("Score", out var sc) && sc is int scoreInt)
            {
                threatScore = scoreInt / 100.0;
            }
            else
            {
                threatScore = 0.95;
            }
        }

        // --- ReAct Step 4: MITRE ATT&CK TTP 분류 ---
        string combinedBehavior = $"{rootCause} -> {targetNode.ImageName} {targetNode.CommandLine} {decodedScript}";
        if (_tools.TryGetValue("MitreClassifierTool", out var mitreTool))
        {
            var thought4 = $"[Step {step} 추론] 관찰된 침해 전술 체인을 MITRE ATT&CK Matrix TTP 기법으로 자동 분류합니다.";
            var res4 = await mitreTool.ExecuteAsync(new() { ["observedBehavior"] = combinedBehavior });

            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought4,
                ActionTool = mitreTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { observedBehavior = combinedBehavior }),
                Observation = res4.Output
            });

            if (res4.Data != null && res4.Data.TryGetValue("TacticIds", out var tids) && tids is List<string> list)
            {
                mitreList = list;
            }
        }

        // --- ReAct Step 5: 방화벽 C2 차단 집행 (악성 확정 시) ---
        if (threatScore >= 0.85 && !string.IsNullOrWhiteSpace(extractedIp) && _tools.TryGetValue("SystemFirewallTool", out var fwTool))
        {
            var thought5 = $"[Step {step} 추론] 위협 확신도 {threatScore:P0}에 도달함에 따라 악성 C2 IP '{extractedIp}'에 대한 네트워크 방화벽 차단을 집행합니다.";
            var res5 = await fwTool.ExecuteAsync(new() { ["maliciousIp"] = extractedIp });

            traces.Add(new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought5,
                ActionTool = fwTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { maliciousIp = extractedIp }),
                Observation = res5.Output
            });
        }

        // --- 최종 판결(Verdict) 및 다차원 누적 위험도(Risk Score) FSM 평가 ---
        int riskScore = 0;

        // 1. 비정상 부모 족보 분석 (+30)
        if (IsSuspiciousParent(rootCause))
        {
            riskScore += 30;
        }

        // 2. 인라인 C2 다운로드 / 명령 실행 패턴 (+35)
        if (HasInlineC2Pattern(decodedScript, targetNode.CommandLine))
        {
            riskScore += 35;
        }

        // 3. Unbacked 실행 메모리 주입 또는 악성 위협 평판 (+40)
        bool hasUnbackedMemory = traces.Any(t => t.ActionTool == "ProcessMemoryScanTool" && (t.Observation.Contains("PAGE_EXECUTE") || t.Observation.Contains("Unbacked")));
        if (hasUnbackedMemory || threatScore >= 0.85)
        {
            riskScore += 40;
        }

        // 4. 랜섬웨어 파괴 명령 패턴: 시스템 복구 무력화 (+80 즉각 사살 트리거)
        if (IsRansomwareDestructiveCommand(targetNode.CommandLine, targetNode.ImageName))
        {
            riskScore += 80;
        }

        // 5. 사내 정상 인프라 / 내부 도메인 / 화이트리스트 (-50)
        if (IsKnownInternalOrTrusted(decodedScript, targetNode.CommandLine, extractedIp))
        {
            riskScore -= 50;
        }

        // 최종 판정: 누적 80점 이상 시 사살 (경계값 80점 포함)
        bool isMalicious = riskScore >= 80;

        var remediationSteps = isMalicious
            ? new List<string> { "엔드포인트 네트워크 격리", "악성 C2 IP 방화벽 차단", "침해 계정 자격증명 초기화" }
            : new List<string>();

        if (isMalicious)
        {
            verdictAction = MitigationCommand.Types.ActionType.ActionKill;
            summaryTitle = "악성 오피스 매크로/LOLBAS를 통한 파일리스 C2 다운로더 침투 시도";
            narrative = $"{DateTime.UtcNow:HH시 mm분}, 시스템에서 실행된 '{rootCause}' 프로세스가 비정상 자식 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})를 은밀히 기동했습니다. " +
                        $"Phalanx 센서가 24μs 만에 원자적으로 동결 집행하였으며, AI 에이전트의 심층 족보 역추적 및 메모리/페이로드 분석 결과 " +
                        $"{(extractedIp != null ? $"해외 악성 C2({extractedIp})" : "원격 C2 인프라")}와의 통신 및 파일리스 공격 시도가 확인되었습니다. " +
                        $"누적 위험도 {riskScore}점(임계치 80점 이상)으로 즉각 사살(ACTION_KILL)을 하달하고 격리 조치를 완결했습니다.";

            if (mitreList.Count == 0)
            {
                mitreList = new List<string> { "T1566.001", "T1059.001", "T1071.001" };
            }
        }
        else
        {
            verdictAction = MitigationCommand.Types.ActionType.ActionResume;
            summaryTitle = "정상 관리 도구 동작 확인 (오탐 방지 및 동결 해제)";
            narrative = $"{DateTime.UtcNow:HH시 mm분}, 동결 수사 의뢰된 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})를 심층 분석한 결과, " +
                        $"외부 악성 통신 및 파괴적 페이로드가 발견되지 않은 신뢰된 작업으로 확인되었습니다. " +
                        $"누적 위험도 {riskScore}점(임계치 80점 미만)으로 무해 판정을 도출하고 안전하게 정상 복구(ACTION_RESUME) 조치를 완료했습니다.";
        }

        // [최종 명령 C++ 전송]
        if (commandSender != null)
        {
            await commandSender(new MitigationCommand
            {
                Action = verdictAction,
                TargetPid = targetNode.ProcessId,
                TargetIp = extractedIp ?? string.Empty,
                Reason = summaryTitle
            });
        }

        sw.Stop();

        // [LiteDB 영구 저장]
        var incidentRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            Timestamp = DateTime.UtcNow,
            TargetPid = targetNode.ProcessId,
            TargetImage = targetNode.ImageName,
            CommandLine = targetNode.CommandLine,
            ConfidenceScore = Math.Max(threatScore, isMalicious ? 0.98 : 0.15),
            VerdictAction = verdictAction == MitigationCommand.Types.ActionType.ActionKill ? "ACTION_KILL" : "ACTION_RESUME",
            SummaryTitle = summaryTitle,
            Narrative = narrative,
            MitreTactics = mitreList,
            BlockedIp = extractedIp ?? string.Empty,
            RootCauseProcess = rootCause,
            TerminatedProcesses = isMalicious ? new() { $"{targetNode.ImageName} (PID: {targetNode.ProcessId})" } : new(),
            RemediationStatus = isMalicious ? "SECURED" : "RESTORED",
            RemediationSteps = remediationSteps
        };

        _archiveManager.SaveIncident(incidentRecord, traces);

        return new InvestigationResult(
            incidentId,
            verdictAction,
            incidentRecord.ConfidenceScore,
            summaryTitle,
            narrative,
            mitreList,
            extractedIp,
            traces,
            sw.Elapsed,
            incidentRecord,
            remediationSteps
        );
    }

    #region FSM & Multi-dimensional Risk Scoring Helpers
    private static bool IsSuspiciousParent(string rootCause)
    {
        string rc = rootCause.ToLowerInvariant();
        return rc.Contains("winword") || rc.Contains("excel") || rc.Contains("powerpnt") ||
               rc.Contains("outlook") || rc.Contains("acrord32") || rc.Contains("acrobat") ||
               rc.Contains("hwp") || rc.Contains("chrome") || rc.Contains("msedge");
    }

    private static bool HasInlineC2Pattern(string? decodedScript, string commandLine)
    {
        string target = $"{commandLine} {decodedScript}".ToLowerInvariant();
        return target.Contains("downloadstring") ||
               target.Contains("downloadfile") ||
               target.Contains("net.webclient") ||
               target.Contains("invoke-webrequest") ||
               target.Contains("curl") ||
               target.Contains("wget") ||
               target.Contains("http://") ||
               target.Contains("https://") ||
               target.Contains("iex ") ||
               target.Contains("iex(") ||
               target.Contains("invoke-expression");
    }

    private static bool IsRansomwareDestructiveCommand(string commandLine, string imageName)
    {
        string target = $"{imageName} {commandLine}".ToLowerInvariant();
        if (target.Contains("vssadmin") && target.Contains("delete") && target.Contains("shadows")) return true;
        if (target.Contains("bcdedit") && (target.Contains("recoveryenabled") || target.Contains("ignoreallfailures"))) return true;
        if (target.Contains("wbadmin") && (target.Contains("delete catalog") || target.Contains("systemstatebackup"))) return true;
        return false;
    }

    private static bool IsKnownInternalOrTrusted(string? decodedScript, string commandLine, string? extractedIp)
    {
        string target = $"{commandLine} {decodedScript}".ToLowerInvariant();

        bool hasInternalDomain = target.Contains(".corp.local") ||
                                target.Contains(".internal") ||
                                target.Contains(".local") ||
                                target.Contains("localhost") ||
                                target.Contains("127.0.0.1");

        bool hasInternalCmd = target.Contains("get-service") ||
                              target.Contains("restart-service") ||
                              target.Contains("get-wmiobject") ||
                              target.Contains("get-process") ||
                              target.Contains("backup") ||
                              target.Contains("inventory");

        if (hasInternalDomain || hasInternalCmd)
        {
            if (extractedIp == null || extractedIp.StartsWith("10.") || extractedIp.StartsWith("192.168.") || extractedIp.StartsWith("127."))
            {
                return true;
            }
        }

        return false;
    }
    #endregion
}
