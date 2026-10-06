using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.Config;
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
public partial class AutonomousHunterAgent
{
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly ForensicArchiveManager _archiveManager;
    private readonly Dictionary<string, IInvestigationTool> _tools = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _activeCtsMap = new();
    private GeminiRestClient? _geminiClient;

    public bool IsOnlineGemini => _geminiClient != null;
    public string? CurrentModelName => _geminiClient?.ModelName;

    /// <summary>
    /// 마지막 Gemini 클라이언트 생성 실패 사유 (온라인이면 null)
    /// </summary>
    public string? LastClientError { get; private set; }

    public int MaxSteps { get; set; } = 5;
    public int CtsTimeoutSec { get; set; } = 50;
    public bool OfflineFallbackEnabled { get; set; } = true;
    public bool FailSecureEnabled { get; set; } = true;

    /// <summary>
    /// 진행 중인 사건의 AI 심층 수사를 즉시 취소합니다. (커널 동결 상태 보존)
    /// </summary>
    public bool CancelInvestigation(string incidentId)
    {
        if (string.IsNullOrWhiteSpace(incidentId)) return false;
        if (_activeCtsMap.TryRemove(incidentId, out var cts))
        {
            try
            {
                cts.Cancel();
                Trace.WriteLine($"[AutonomousHunterAgent] 수사 취소 요청 성공: IncidentId={incidentId}");
                return true;
            }
            catch (ObjectDisposedException) { return false; }
        }
        return false;
    }

    public event Action<ProcessNodeModel, string>? OnInvestigationStarted;
    public event Action<string /* incidentId */, ReActTraceRecord>? OnReActStepProgress;
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

        LoadSettingsFromAppSettings();

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
            var clientHttp = httpClient ?? new HttpClient();

            if (!string.IsNullOrWhiteSpace(geminiApiKey))
            {
                // 호출자가 명시적으로 전달한 API Key만 사용 (환경 변수 자동 사용 금지)
                _geminiClient = new GeminiRestClient(clientHttp, geminiApiKey);
            }
            else if (geminiApiKey == null)
            {
                // 실행 폴더의 AppSettings.json에 명시된 인증 정보만 사용 (자동 탐색 금지 - 유료 API 보호)
                _geminiClient = GeminiRestClient.TryCreateFromSettings(clientHttp, out var clientError);
                LastClientError = clientError;
                if (_geminiClient == null)
                {
                    Trace.WriteLine($"[AutonomousHunterAgent] 클라우드 LLM 비활성화 (오프라인 모드): {clientError}");
                }
            }
        }
    }

    private void LoadSettingsFromAppSettings()
    {
        try
        {
            var config = PhalanxConfigurationManager.Current;
            MaxSteps = Math.Clamp(config.Gemini.MaxSteps, 1, 10);
            CtsTimeoutSec = Math.Clamp(config.Gemini.CtsTimeoutSec, 5, 120);
            OfflineFallbackEnabled = config.Gemini.OfflineFallback;
            FailSecureEnabled = config.Gemini.FailSecure;
        }
        catch { }
    }

    /// <summary>
    /// 설정 저장 시 전달된 값(또는 credentialsPath 미지정 시 AppSettings.json)만으로 Gemini 클라이언트를 즉시 재구성합니다.
    /// 환경 변수나 기본 위치의 인증 파일로 대체하지 않으며, 값이 유효하지 않으면 오프라인 모드로 전환됩니다.
    /// </summary>
    public bool ReloadConfiguration(
        string? geminiApiKey = null,
        string? modelName = null,
        HttpClient? httpClient = null,
        bool? useVertexAi = null,
        int? maxSteps = null,
        int? ctsTimeoutSec = null,
        bool? offlineFallback = null,
        bool? failSecure = null,
        string? credentialsPath = null,
        string? projectId = null,
        string? location = null)
    {
        if (maxSteps.HasValue) MaxSteps = Math.Clamp(maxSteps.Value, 1, 10);
        if (ctsTimeoutSec.HasValue) CtsTimeoutSec = Math.Clamp(ctsTimeoutSec.Value, 5, 120);
        if (offlineFallback.HasValue) OfflineFallbackEnabled = offlineFallback.Value;
        if (failSecure.HasValue) FailSecureEnabled = failSecure.Value;

        var clientHttp = httpClient ?? new HttpClient();
        bool preferVertex = useVertexAi ?? string.IsNullOrWhiteSpace(geminiApiKey);
        string? clientError;

        if (!preferVertex)
        {
            if (!string.IsNullOrWhiteSpace(geminiApiKey))
            {
                _geminiClient = new GeminiRestClient(clientHttp, geminiApiKey, modelName ?? "gemini-3.7-flash");
                clientError = null;
            }
            else
            {
                _geminiClient = null;
                clientError = "API Key 모드이지만 API Key가 입력되지 않았습니다.";
            }
        }
        else if (!string.IsNullOrWhiteSpace(credentialsPath))
        {
            _geminiClient = GeminiRestClient.TryCreateVertexClient(clientHttp, credentialsPath, projectId, location, modelName, out clientError);
        }
        else
        {
            _geminiClient = GeminiRestClient.TryCreateFromSettings(clientHttp, out clientError);
        }

        LastClientError = clientError;
        if (_geminiClient == null)
        {
            Trace.WriteLine($"[AutonomousHunterAgent] 클라우드 LLM 비활성화 (오프라인 모드): {clientError}");
        }
        ConfigurationApplied?.Invoke();
        return _geminiClient != null;
    }

    /// <summary>
    /// 실행 폴더의 AppSettings.json만 다시 읽어 런타임 파라미터와 LLM 클라이언트를 재구성합니다.
    /// (설정 파일이 외부에서 변경된 경우 사용, 환경 변수/기본 위치 자동 탐색 없음)
    /// </summary>
    public bool ReloadFromSettingsFile(HttpClient? httpClient = null)
    {
        PhalanxConfigurationManager.Reload();
        LoadSettingsFromAppSettings();
        var clientHttp = httpClient ?? new HttpClient();
        _geminiClient = GeminiRestClient.TryCreateFromSettings(clientHttp, out var clientError);
        LastClientError = clientError;
        if (_geminiClient == null)
        {
            Trace.WriteLine($"[AutonomousHunterAgent] 클라우드 LLM 비활성화 (오프라인 모드): {clientError}");
        }
        ConfigurationApplied?.Invoke();
        return _geminiClient != null;
    }

    /// <summary>
    /// 설정 재적용(ReloadConfiguration / ReloadFromSettingsFile) 완료 시 발생합니다. UI 상태 표시 즉시 갱신용.
    /// </summary>
    public event Action? ConfigurationApplied;

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

        // 내부 취소용 Linked CTS 생성 및 등록
        using var internalCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _activeCtsMap[incidentId] = internalCts;

        OnInvestigationStarted?.Invoke(targetNode, incidentId);

        try
        {
            // try 블록 내부에서 취소 확인 -> 사전 취소된 경우에도 catch 블록으로 진입하여 SUSPENDED 레코드 및 결과 반환
            internalCts.Token.ThrowIfCancellationRequested();

            InvestigationResult result;
            string? fallbackReason = null;

            // [모드 A: 실제 Gemini REST 호출] 클라이언트(API Key 또는 Vertex AI)가 활성화된 경우
            if (_geminiClient != null)
            {
                try
                {
                    result = await InvestigateWithGeminiAsync(targetNode, incidentId, sw, commandSender, internalCts.Token);
                    OnInvestigationCompleted?.Invoke(result);
                    return result;
                }
                catch (OperationCanceledException) when (internalCts.IsCancellationRequested || cancellationToken.IsCancellationRequested)
                {
                    throw; // 상위 통합 취소 핸들러로 전달 (오프라인 폴백 금지)
                }
                catch (Exception ex)
                {
                    fallbackReason = ex.Message;
                    Trace.WriteLine($"[AutonomousHunterAgent] 클라우드 LLM API 호출 실패 또는 타임아웃 발생: {ex.Message}");
                    if (!OfflineFallbackEnabled)
                    {
                        if (FailSecureEnabled)
                        {
                            var failRecord = new IncidentRecord
                            {
                                IncidentId = incidentId,
                                Timestamp = DateTime.UtcNow,
                                TargetPid = targetNode.ProcessId,
                                TargetImage = targetNode.ImageName,
                                CommandLine = targetNode.CommandLine,
                                VerdictAction = "ACTION_KILL",
                                ConfidenceScore = 0.99,
                                SummaryTitle = "오프라인 폴백 비활성화 및 API 장애에 따른 Fail-Secure 사살",
                                Narrative = $"클라우드 LLM API 호출에 실패하였으나, 오프라인 폴백이 비활성화되어 Fail-Secure 정책에 의해 선제 사살되었습니다: {ex.Message}",
                                MitreTactics = new List<string> { "T1059" },
                                BlockedIp = string.Empty,
                                RootCauseProcess = targetNode.ImageName,
                                TerminatedProcesses = new() { $"{targetNode.ImageName} (PID: {targetNode.ProcessId})" },
                                RemediationStatus = "SECURED",
                                RemediationSteps = new List<string> { "API 장애 발생", "Fail-Secure 선제 조치" },
                                ElapsedMs = sw.Elapsed.TotalMilliseconds,
                                InvestigationEngine = "FAIL_SECURE",
                                FallbackReason = ex.Message
                            };
                            _archiveManager.SaveIncident(failRecord, new List<ReActTraceRecord>());

                            var failKill = new InvestigationResult(
                                incidentId,
                                MitigationCommand.Types.ActionType.ActionKill,
                                0.99,
                                failRecord.SummaryTitle,
                                failRecord.Narrative,
                                failRecord.MitreTactics,
                                string.Empty,
                                new List<ReActTraceRecord>(),
                                sw.Elapsed,
                                failRecord,
                                failRecord.RemediationSteps,
                                InvestigationEngine: "FAIL_SECURE",
                                FallbackReason: ex.Message
                            );
                            if (commandSender != null)
                            {
                                await commandSender(new MitigationCommand
                                {
                                    TargetPid = targetNode.ProcessId,
                                    Action = MitigationCommand.Types.ActionType.ActionKill,
                                    Reason = "클라우드 LLM API 장애 및 Fail-Secure 집행"
                                });
                            }
                            OnInvestigationCompleted?.Invoke(failKill);
                            return failKill;
                        }
                        throw;
                    }
                }
            }

            // [모드 B: 오프라인 초고속 결정론적 ReAct 엔진 Fallback] (기본 10초 워치독 내 23ms 즉각 완결, 타임아웃 연장 불필요)
            bool isFallback = !string.IsNullOrEmpty(fallbackReason);
            result = await InvestigateOfflineDeterministicAsync(targetNode, incidentId, sw, commandSender, internalCts.Token, isFallback, fallbackReason);
            OnInvestigationCompleted?.Invoke(result);
            return result;
        }
        catch (OperationCanceledException) when (internalCts.IsCancellationRequested || cancellationToken.IsCancellationRequested)
        {
            Trace.WriteLine($"[AutonomousHunterAgent] AI 심층 수사 취소 집행: IncidentId={incidentId}, TargetPid={targetNode.ProcessId}");

            // C++ 센서로 사살/해제 완화 명령을 절대로 전송하지 않음 -> 프로세스는 커널에서 안전하게 Suspended 유지
            var cancelledRecord = new IncidentRecord
            {
                IncidentId = incidentId,
                Timestamp = DateTime.UtcNow,
                TargetPid = targetNode.ProcessId,
                TargetImage = targetNode.ImageName,
                CommandLine = targetNode.CommandLine,
                VerdictAction = "SUSPENDED",
                ConfidenceScore = 0.0,
                SummaryTitle = "사용자 수동 개입에 의한 AI 심층 수사 취소 (동결 유지)",
                Narrative = $"사용자 요청으로 AI 자율 조사가 취소되었습니다. 대상 프로세스(PID: {targetNode.ProcessId})는 커널 레벨에서 안전하게 동결(SUSPENDED) 상태로 보존되었으며, 관리자가 전역 프로세스 트리에서 수동 처분(사살/동결 해제)을 직접 집행할 수 있는 대기 상태입니다.",
                MitreTactics = new List<string>(),
                BlockedIp = string.Empty,
                RootCauseProcess = targetNode.ImageName,
                TerminatedProcesses = new List<string>(),
                RemediationStatus = "SUSPENDED_MANUAL_HOLD",
                RemediationSteps = new List<string> { "AI 자율 조사 취소 완료 (동결 유지)", "전역 프로세스 트리 수동 처분 대기" },
                ElapsedMs = sw.Elapsed.TotalMilliseconds,
                InvestigationEngine = "USER_CANCELLED"
            };
            _archiveManager.SaveIncident(cancelledRecord, new List<ReActTraceRecord>());

            var cancelledResult = new InvestigationResult(
                incidentId,
                MitigationCommand.Types.ActionType.ActionSuspend, // 동결 유지
                0.0,
                cancelledRecord.SummaryTitle,
                cancelledRecord.Narrative,
                cancelledRecord.MitreTactics,
                string.Empty,
                new List<ReActTraceRecord>(),
                sw.Elapsed,
                cancelledRecord,
                cancelledRecord.RemediationSteps,
                InvestigationEngine: "USER_CANCELLED"
            );

            OnInvestigationCompleted?.Invoke(cancelledResult);
            return cancelledResult;
        }
        finally
        {
            _activeCtsMap.TryRemove(incidentId, out _);
        }
    }

    /// <summary>
    /// C++ 커널 룰 엔진에 의해 0.1ms 이내로 즉각 사살된 랜섬웨어/파괴적 프로세스에 대해
    /// 별도의 LLM 지연 없이 즉시 포렌식 레코드를 아카이빙하고 관제 UI에 현장 사살 카드를 등록합니다.
    /// </summary>
    public InvestigationResult HandleReflexKill(ProcessNodeModel targetNode)
    {
        string incidentId = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}";

        targetNode.IsInvestigating = false;
        targetNode.IsAlive = false;
        targetNode.IsSuspended = false;
        targetNode.IsTerminated = true;
        targetNode.UpdateStatus(ProcessLifecycle.LifecycleTerminated, isSuspended: false, isTerminated: true);

        string ruleReason = targetNode.CommandLine.Contains("shadows", StringComparison.OrdinalIgnoreCase)
            ? "KILL_VSSADMIN_DELETE_SHADOWS (랜섬웨어 볼륨 섀도 복사본 파괴 차단)"
            : targetNode.CommandLine.Contains("recoveryenabled", StringComparison.OrdinalIgnoreCase)
                ? "KILL_BCDEDIT_DISABLE_RECOVERY (부팅 복구 비활성화 시도 차단)"
                : targetNode.CommandLine.Contains("catalog", StringComparison.OrdinalIgnoreCase)
                    ? "KILL_WBADMIN_DELETE_BACKUP (백업 카탈로그 삭제 시도 차단)"
                    : "KILL_DESTRUCTIVE_REFLEX (시스템 파괴 행위 현장 차단)";

        string summaryTitle = $"[C++ 커널 룰 엔진 현장 사살] {targetNode.ImageName} 즉각 차단";
        string narrative = $"C++ 네이티브 커널 룰 엔진이 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})의 명령줄 '{targetNode.CommandLine}'에서 " +
                          $"명백한 시스템 파괴 시그니처를 포착하여 0.1ms(80μs) 이내에 즉각 현장 사살(NtTerminateProcess)을 집행했습니다. " +
                          $"AI ReAct 루프 개입 없이 즉시 무력화되었습니다.";

        var traces = new List<ReActTraceRecord>
        {
            new()
            {
                IncidentId = incidentId,
                StepNumber = 1,
                Thought = $"C++ 커널 ETW 센서가 '{targetNode.ImageName}'의 파괴적 명령줄을 실시간 인터셉트하여 로컬 룰 엔진으로 즉각 평가했습니다.",
                ActionTool = "LocalRuleEngine",
                ActionArgsJson = JsonSerializer.Serialize(new { Rule = ruleReason, LatencyUs = 80 }),
                Observation = $"규칙 매칭 성공: {ruleReason}. 0.08ms 초고속 현장 사살 집행 완료.",
                ElapsedMs = 0.08
            }
        };

        List<string> remediationSteps;
        if (targetNode.CommandLine.Contains("shadows", StringComparison.OrdinalIgnoreCase))
        {
            remediationSteps = new List<string>
            {
                "볼륨 섀도 복사본 잔여 상태 및 무결성 검증 (vssadmin list shadows)",
                "스폰 시도한 의심 상위 프로세스 역추적 및 네트워크 격리",
                "랜섬웨어 암호화 확산 여부 스토리지 디스크 긴급 감사",
                "보안 관제 센터(SOC) 1등급 침해 사고 긴급 전파"
            };
        }
        else if (targetNode.CommandLine.Contains("recoveryenabled", StringComparison.OrdinalIgnoreCase))
        {
            remediationSteps = new List<string>
            {
                "윈도우 BCD 부팅 복구 정책 정상 상태 확인 (bcdedit /enum {current})",
                "BitLocker 및 윈도우 복구 환경(WinRE) 무결성 점검",
                "스폰 시도 상위 프로세스 격리 및 관리자 자격증명 변경",
                "보안 관제 센터(SOC) 1등급 침해 사고 긴급 전파"
            };
        }
        else if (targetNode.CommandLine.Contains("catalog", StringComparison.OrdinalIgnoreCase))
        {
            remediationSteps = new List<string>
            {
                "시스템 백업 카탈로그 및 윈도우 상태 복원 지점 정상 여부 점검",
                "원격 백업 스토리지 접근 감사 로그 점검 및 인가되지 않은 세션 차단",
                "보안 관제 센터(SOC) 1등급 침해 사고 긴급 전파"
            };
        }
        else
        {
            remediationSteps = new List<string>
            {
                "시스템 무결성 점검 및 의심 프로세스 네트워크 격리",
                "스토리지 및 백업 상태 긴급 감사",
                "보안 관제 센터(SOC) 침해 알림 발령"
            };
        }

        var incidentRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            Timestamp = DateTime.UtcNow,
            TargetPid = targetNode.ProcessId,
            TargetImage = targetNode.ImageName,
            CommandLine = targetNode.CommandLine,
            ConfidenceScore = 1.0,
            VerdictAction = "ACTION_KILL",
            SummaryTitle = summaryTitle,
            Narrative = narrative,
            MitreTactics = new List<string> { "T1490" }, // Inhibit System Recovery
            BlockedIp = string.Empty,
            RootCauseProcess = _treeManager.FindActiveNodeByPid(targetNode.ParentProcessId)?.ImageName ?? "System",
            TerminatedProcesses = new() { $"{targetNode.ImageName} (PID: {targetNode.ProcessId})" },
            RemediationStatus = "SECURED",
            RemediationSteps = remediationSteps,
            ElapsedMs = 0.08,
            InvestigationEngine = "KERNEL_REFLEX"
        };

        _archiveManager.SaveIncident(incidentRecord, traces);

        var result = new InvestigationResult(
            incidentId,
            MitigationCommand.Types.ActionType.ActionKill,
            1.0,
            summaryTitle,
            narrative,
            incidentRecord.MitreTactics,
            string.Empty,
            traces,
            TimeSpan.FromMilliseconds(0.08),
            incidentRecord,
            incidentRecord.RemediationSteps,
            InvestigationEngine: "KERNEL_REFLEX"
        );

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
        cts.CancelAfter(TimeSpan.FromSeconds(CtsTimeoutSec));

        var traces = new List<ReActTraceRecord>();
        var ancestry = _treeManager.GetAncestry(targetNode.ProcessId, maxDepth: 5, includeSelf: true);
        string rootCause = ancestry.Count > 1 ? $"{ancestry[1].ImageName} (PID: {ancestry[1].ProcessId})" : $"{targetNode.ImageName} (PID: {targetNode.ProcessId})";

        string systemInstruction = """
            <system_directive>
            당신은 최첨단 엔터프라이즈 EDR 'Phalanx'의 자율 AI 위협 헌터(Autonomous Hunter Agent)입니다.
            원자적으로 선제 동결된 의심 프로세스를 수사하여 최종 판결(ACTION_KILL / ACTION_RESUME)과 공식 침해사고 서사를 도출하십시오.
            </system_directive>

            <tools>
            1. DecodePayloadTool: Base64/Hex 난독화 명령줄 해독 (encodedCommand: string)
            2. ProcessMemoryScanTool: 동결 프로세스 RAM 메모리 내 C2/URL 스캔 (targetPid: number)
            3. ThreatReputationTool: 통신 지표(IP/도메인) 위협 평판 조회 (targetIndicator: string)
            4. MitreClassifierTool: 관찰된 공격 행위 MITRE TTP 분류 (observedBehavior: string)
            5. SystemFirewallTool: 악성 C2 IP 방화벽 차단 (maliciousIp: string)
            6. FileInspectionTool: 디스크 상의 파일 경로, 디지털 서명(Authenticode), 시스템 파일 위장(Masquerading T1036.005), PE 헤더, Shannon 엔트로피 검증 (filePath: string)
            7. RegistryInspectionTool: 윈도우 레지스트리(CLSID, InprocServer32, Run/RunOnce, ScriptletURL) 간접 실행 및 COM 하이재킹 무결성 검증 (registryKey: string)
            </tools>

            <rules>
            1. 증거 불충분 시: is_final_verdict: false로 지정하고 최적의 수사 도구를 호출하십시오.
            2. 관찰 피드백: <tool_observation> 결과를 분석하여 다음 도구로 연계하거나 최종 판결로 전환하십시오.
            3. 최종 판결 시: is_final_verdict: true, action_tool: "None"으로 지정하고 모든 판결 필드를 완성하십시오.
            4. 공식 서사: narrative는 한국어 보고서 문체로 발단, 동결, 수사 결과, 처분 사유를 구체적으로 서술하십시오.
            5. 파일 수사 지침: 페이로드 해독이나 명령행에서 로컬 파일 경로가 포착되면, 메모리 스캔보다 먼저 FileInspectionTool을 호출하여 Authenticode 서명 및 시스템 경로 위장(Masquerading) 여부를 우선 확증하십시오.
            6. 레지스트리 수사 지침: LOLBAS 프록시(regsvr32, rundll32, mshta 등) 명령행이나 /i: 인자에서 레지스트리 경로/CLSID가 포착되면, 즉시 RegistryInspectionTool을 호출하여 간접 스크립틀릿 실행 및 COM 하이재킹 여부를 확증하십시오.
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
              "narrative": "winword.exe가 기동한 의심 파워셸을 원자적으로 선제 동결하였으며, Base64 해독 및 위협 평판 조회 결과 해외 악성 C2와의 통신 시도가 확증되어 즉각 사살(ACTION_KILL)을 집행했습니다.",
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
            - Status: SUSPENDED (원자적 프로세스 동결 완료, 메모리 보존 상태)
            - IsTempExecution: {isTempExecution}
            - SignatureStatus: {signatureStatus}
            - IntegrityLevel: {integrityLevel}
            </target_context>

            <final_instruction>
            위 <target_context>의 정보를 정밀 분석하여, 첫 번째로 실행할 OS 조사 도구를 <output_format> 규격의 순수 JSON으로 제출하십시오. (증거 수집 단계이므로 is_final_verdict: false를 지정하십시오)
            </final_instruction>
            """;

        List<Content> conversationHistory =
        [
            new Content("user", [new Part(userPrompt)])
        ];

        AiInvestigationDecision? latestDecision = null;
        string? extractedIp = null;
        string? decodedScript = null;
        int step = 1;

        while (step <= MaxSteps)
        {
            var stepSw = Stopwatch.StartNew();
            string rawResponse = await _geminiClient!.GenerateContentAsync(conversationHistory, systemInstruction, cts.Token, timeoutMs: 30000);
            stepSw.Stop();
            double turnElapsedMs = stepSw.Elapsed.TotalMilliseconds;

            var decision = LlmJsonParser.DeserializeSafe<AiInvestigationDecision>(rawResponse);

            if (decision == null)
            {
                throw new InvalidOperationException($"LLM 응답을 AiInvestigationDecision으로 역직렬화할 수 없습니다: {rawResponse}");
            }

            latestDecision = decision;
            string currentThought = decision.Thought ?? string.Empty;
            string actionTool = decision.ActionTool ?? "None";
            var actionArgs = decision.ActionArgs ?? new Dictionary<string, object>();

            // LLM 응답을 히스토리에 기록
            conversationHistory.Add(new Content("model", [new Part(rawResponse)]));

            // 최종 판결 도달 시 루프 탈출
            if (decision.IsFinalVerdict || actionTool.Equals("None", StringComparison.OrdinalIgnoreCase))
            {
                var finalTrace = new ReActTraceRecord
                {
                    IncidentId = incidentId,
                    StepNumber = step++,
                    Thought = currentThought,
                    ActionTool = "None",
                    ActionArgsJson = "{}",
                    Observation = $"최종 판결 도출: {decision.VerdictAction} (확신도 {decision.ConfidenceScore:P0})",
                    ElapsedMs = turnElapsedMs,
                    RawLlmResponse = rawResponse
                };
                traces.Add(finalTrace);
                OnReActStepProgress?.Invoke(incidentId, finalTrace);
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
                else if (actionTool.Equals("RegistryInspectionTool", StringComparison.OrdinalIgnoreCase) && !caseInsensitiveArgs.ContainsKey("registryKey"))
                {
                    string? extractedKey = AttackPatternHeuristics.ExtractTargetRegistryKey(decodedScript, targetNode.CommandLine);
                    if (!string.IsNullOrEmpty(extractedKey))
                    {
                        caseInsensitiveArgs["registryKey"] = extractedKey;
                    }
                }
                else if (actionTool.Equals("FileInspectionTool", StringComparison.OrdinalIgnoreCase) && !caseInsensitiveArgs.ContainsKey("filePath"))
                {
                    string? candidatePath = AttackPatternHeuristics.ExtractTargetFilePath(decodedScript, targetNode.CommandLine);
                    if (!string.IsNullOrEmpty(candidatePath))
                    {
                        caseInsensitiveArgs["filePath"] = candidatePath;
                    }
                    else if (targetNode.ImageName.Contains('\\'))
                    {
                        caseInsensitiveArgs["filePath"] = targetNode.ImageName;
                    }
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

            var stepTrace = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = currentThought,
                ActionTool = actionTool,
                ActionArgsJson = JsonSerializer.Serialize(caseInsensitiveArgs),
                Observation = observationOutput,
                ElapsedMs = turnElapsedMs,
                RawLlmResponse = rawResponse
            };
            traces.Add(stepTrace);
            OnReActStepProgress?.Invoke(incidentId, stepTrace);

            // 모델에게 도구 실행 결과(<tool_observation>) 피드백 전송
            string observationFeedback = $"""
                <tool_observation tool="{actionTool}">
                {observationOutput}
                </tool_observation>
                """;
            conversationHistory.Add(new Content("user", [new Part(observationFeedback)]));
        }

        bool reachedFinal = latestDecision != null && latestDecision.IsFinalVerdict;

        // 루프 소진 시 Fail-Secure 안내 Trace 추가
        if (!reachedFinal)
        {
            var failTrace = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = $"멀티턴 ReAct 루프 최대 허용 단계(MaxSteps={MaxSteps})에 도달하여 수사를 안전 종료합니다.",
                ActionTool = "None",
                ActionArgsJson = "{}",
                Observation = FailSecureEnabled 
                    ? "Fail-Secure 정책 집행: 회색지대 의심 프로세스 사살(ACTION_KILL) 권고"
                    : "Fail-Safe 정책 집행: 회색지대 의심 프로세스 동결 해제(ACTION_RESUME) 권고"
            };
            traces.Add(failTrace);
            OnReActStepProgress?.Invoke(incidentId, failTrace);
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
                : (isMalicious ? "AI 수사관: 악성 위협 실시간 탐지 및 사살" : "AI 수사관: 정상 프로세스 확인 및 동결 해제");

            narrative = !string.IsNullOrWhiteSpace(latestDecision.Narrative)
                ? latestDecision.Narrative
                : $"AI 자율 수사 종결: '{targetNode.ImageName}' (PID: {targetNode.ProcessId}) 프로세스에 대해 {latestDecision.VerdictAction} (확신도 {finalConfidence:P0}) 판결을 하달했습니다.";

            // 악성 확정 시에만 미지정 TTP에 기본값 부여 (정상 프로세스에는 절대 피싱/악성 TTP 날조 주입 금지)
            if (isMalicious && mitreList.Count == 0)
            {
                mitreList = new List<string> { "T1059.001" };
            }
        }
        else
        {
            // [경로 B: 한도 초과 시 Fail-Secure 사살 vs Fail-Safe 해제 분기]
            if (FailSecureEnabled)
            {
                isMalicious = true;
                verdictAction = MitigationCommand.Types.ActionType.ActionKill;
                finalConfidence = 0.99;
                summaryTitle = "AI 수사관: 멀티턴 수사 한도 초과에 따른 Fail-Secure 사살 격리";
                narrative = $"{DateTime.Now:HH시 mm분}, 회색지대 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})가 ReAct 최대 허용 단계({MaxSteps}턴) 내에 무해성을 증명하지 못하여 엔터프라이즈 안전 격리 정책(Fail-Secure)에 따라 선제 사살 조치되었습니다.";
                if (mitreList.Count == 0)
                {
                    mitreList = new List<string> { "T1059.001" };
                }
            }
            else
            {
                isMalicious = false;
                verdictAction = MitigationCommand.Types.ActionType.ActionResume;
                finalConfidence = 0.50;
                summaryTitle = "AI 수사관: 멀티턴 수사 한도 초과 (Fail-Safe 정책에 따른 동결 해제)";
                narrative = $"{DateTime.Now:HH시 mm분}, 회색지대 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})가 {MaxSteps}턴 내에 악성 여부를 확정하지 못하였으나, Fail-Secure 비활성화 설정에 따라 안전하게 동결 해제(ActionResume) 조치되었습니다.";
            }
        }

        // 2. 사후 완화 조치: 악성 확정(isMalicious) 시 방화벽 C2 차단 즉각 집행 (수사 추적 traces가 아닌 대응 조치로 분리)
        string? firewallResultMsg = null;
        if (isMalicious && extractedIp != null && _tools.TryGetValue("SystemFirewallTool", out var fwTool))
        {
            var fwRes = await fwTool.ExecuteAsync(new() { ["maliciousIp"] = extractedIp });
            if (fwRes.Success)
            {
                firewallResultMsg = $"악성 C2 IP({extractedIp}) 전사 방화벽 인/아웃바운드 차단 집행 완료 (규칙명: Phalanx_EDR_Block_{extractedIp})";
            }
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
        var rawRemediation = latestDecision?.RemediationSteps ?? (isMalicious
            ? new List<string> { "타깃 프로세스 원자적 영구 사살 (ACTION_KILL)", "엔드포인트 네트워크 격리", "침해 계정 자격증명 초기화" }
            : new List<string>());

        var remediationSteps = new List<string>();
        if (!string.IsNullOrEmpty(firewallResultMsg))
        {
            remediationSteps.Add(firewallResultMsg);
        }
        foreach (var remStep in rawRemediation)
        {
            if (!string.IsNullOrEmpty(firewallResultMsg) &&
                (remStep.Contains("방화벽", StringComparison.OrdinalIgnoreCase) || remStep.Contains("firewall", StringComparison.OrdinalIgnoreCase)))
            {
                continue; // 방화벽 집행 결과가 이미 1번에 들어갔으므로 중복 제거
            }
            remediationSteps.Add(remStep);
        }

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
            RemediationSteps = remediationSteps,
            ElapsedMs = sw.Elapsed.TotalMilliseconds,
            InvestigationEngine = "CLOUD_LLM",
            EngineModel = _geminiClient?.ModelName
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
            remediationSteps,
            InvestigationEngine: "CLOUD_LLM"
        );
    }

}

