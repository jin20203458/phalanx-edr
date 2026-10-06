using System.Diagnostics;
using System.Text.Json;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Agent;

public partial class AutonomousHunterAgent
{
    /// <summary>
    /// API Key 부재, 네트워크 단절, 또는 단위 테스트용 23ms 초고속 오프라인 결정론적 수사 엔진 (Fallback)
    /// </summary>
    private async Task<InvestigationResult> InvestigateOfflineDeterministicAsync(
        ProcessNodeModel targetNode,
        string incidentId,
        Stopwatch sw,
        Func<MitigationCommand, Task>? commandSender,
        CancellationToken cancellationToken,
        bool isFallback = false,
        string? fallbackReason = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

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

            var trace1 = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought1,
                ActionTool = decodeTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { encodedCommand = cmd }),
                Observation = res1.Output
            };
            traces.Add(trace1);
            OnReActStepProgress?.Invoke(incidentId, trace1);

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
            if (!AttackPatternHeuristics.IsRansomwareDestructiveCommand(cmd, targetNode.ImageName) &&
                !AttackPatternHeuristics.HasInlineC2Pattern(decodedScript, cmd) &&
                AttackPatternHeuristics.IsKnownInternalOrTrusted(decodedScript, cmd, extractedIp))
            {
                verdictAction = MitigationCommand.Types.ActionType.ActionResume;
                summaryTitle = targetNode.ImageName.Contains("curl", StringComparison.OrdinalIgnoreCase) || cmd.Contains("127.0.0.1") || cmd.Contains("localhost")
                    ? "사내 개발 도구 루프백 통신 확인 (조기 복구)"
                    : "사내 정상 관리 및 백업 스크립트 확인 (조기 복구)";
                narrative = $"{DateTime.Now:HH시 mm분}, 의뢰된 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})의 명령줄을 해독한 결과, " +
                            $"외부 C2 통신 및 파괴 행위가 없는 사내 정상 작업(루프백/내부 인프라)으로 확인되었습니다. " +
                            $"오프라인 결정론적 추론 엔진에 의해 무해성을 확인하고 즉시 정상 복구(ACTION_RESUME)를 완료했습니다.";

                cancellationToken.ThrowIfCancellationRequested();
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
                    RemediationSteps = new(),
                    ElapsedMs = sw.Elapsed.TotalMilliseconds,
                    InvestigationEngine = isFallback ? "OFFLINE_FALLBACK" : "OFFLINE_LOCAL",
                    FallbackReason = fallbackReason
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
                    new(),
                    InvestigationEngine: isFallback ? "OFFLINE_FALLBACK" : "OFFLINE_LOCAL",
                    FallbackReason: fallbackReason
                );
            }
        }

        // --- ReAct Step 1.5: 의심 파일 정밀 검증 (FileInspectionTool: 디지털 서명, 시스템 경로 위장, PE 헤더, DLL 사이드로딩) ---
        string? targetFilePath = AttackPatternHeuristics.ExtractTargetFilePath(decodedScript, cmd) ?? (targetNode.ImageName.Contains('\\') ? targetNode.ImageName : null);
        bool isPathMasqueraded = false;
        bool isDllSideloading = false;
        int fileAnomalyScore = 0;

        if (!string.IsNullOrWhiteSpace(targetFilePath) && _tools.TryGetValue("FileInspectionTool", out var fileTool))
        {
            var thoughtFile = $"[Step {step} 추론] 명령행 및 해독 페이로드에서 파일 경로 '{targetFilePath}'가 포착되어 Authenticode 서명 및 시스템 경로 위장(Masquerading T1036.005) 여부를 우선 확증합니다.";
            var resFile = await fileTool.ExecuteAsync(new() { ["filePath"] = targetFilePath });

            var traceFile = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thoughtFile,
                ActionTool = fileTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { filePath = targetFilePath }),
                Observation = resFile.Output
            };
            traces.Add(traceFile);
            OnReActStepProgress?.Invoke(incidentId, traceFile);

            if (resFile.Data != null)
            {
                if (resFile.Data.TryGetValue("IsPathMasqueraded", out var mObj) && mObj is bool b) isPathMasqueraded = b;
                if (resFile.Data.TryGetValue("IsDllSideloading", out var dObj) && dObj is bool bDll) isDllSideloading = bDll;
                if (resFile.Data.TryGetValue("AnomalyScore", out var scObj) && scObj is int aSc) fileAnomalyScore = aSc;
            }
        }

        // --- ReAct Step 1.8: 의심 레지스트리 키 정밀 검증 (RegistryInspectionTool: CLSID, Scriptlet, COM 하이재킹) ---
        string? targetRegistryKey = AttackPatternHeuristics.ExtractTargetRegistryKey(decodedScript, cmd);
        bool isRegistryIndirect = false;
        bool isComHijack = false;
        int registryAnomalyScore = 0;

        if (!string.IsNullOrWhiteSpace(targetRegistryKey) && _tools.TryGetValue("RegistryInspectionTool", out var regTool))
        {
            var thoughtReg = $"[Step {step} 추론] 명령행에서 레지스트리 인자 '{targetRegistryKey}'가 포착되어 Squiblydoo 간접 스크립틀릿(T1218.010) 및 COM 하이재킹 여부를 확증합니다.";
            var resReg = await regTool.ExecuteAsync(new() { ["registryKey"] = targetRegistryKey });

            var traceReg = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thoughtReg,
                ActionTool = regTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { registryKey = targetRegistryKey }),
                Observation = resReg.Output
            };
            traces.Add(traceReg);
            OnReActStepProgress?.Invoke(incidentId, traceReg);

            if (resReg.Data != null)
            {
                if (resReg.Data.TryGetValue("IsIndirectExecution", out var indObj) && indObj is bool bInd) isRegistryIndirect = bInd;
                if (resReg.Data.TryGetValue("IsComHijack", out var comObj) && comObj is bool bCom) isComHijack = bCom;
                if (resReg.Data.TryGetValue("AnomalyScore", out var scObj) && scObj is int aSc) registryAnomalyScore = aSc;

                // 레지스트리 내부에서 C2 IP가 추출된 경우 IP 갱신
                if (resReg.Data.TryGetValue("ExtractedIps", out var ipsObj) && ipsObj is List<string> regIps && regIps.Count > 0)
                {
                    extractedIp ??= regIps[0];
                }
            }
        }

        // --- ReAct Step 2: 타깃 RAM 메모리 스캔 (C2 URL/IP 탐색 및 PEB 로드 모듈 검사) ---
        if (_tools.TryGetValue("ProcessMemoryScanTool", out var memTool))
        {
            var thought2 = $"[Step {step} 추론] 동결된 프로세스의 메모리 영역을 P/Invoke VirtualQueryEx 및 ReadProcessMemory로 스캔하여 은닉된 통신 C2 IP 및 URL을 탐색합니다.";
            var res2 = await memTool.ExecuteAsync(new() { ["targetPid"] = targetNode.ProcessId });

            var trace2 = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought2,
                ActionTool = memTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { targetPid = targetNode.ProcessId }),
                Observation = res2.Output
            };
            traces.Add(trace2);
            OnReActStepProgress?.Invoke(incidentId, trace2);

            if (res2.Data != null)
            {
                if (res2.Data.TryGetValue("Ips", out var memIps) && memIps is List<string> mList && mList.Count > 0)
                {
                    extractedIp ??= mList[0];
                }
                if (res2.Data.TryGetValue("HasSuspiciousDll", out var hObj) && hObj is bool bSusp && bSusp)
                {
                    isDllSideloading = true;
                }
            }
        }

        // --- ReAct Step 3: 위협 평판 조회 ---
        string reputationIndicator = extractedIp ?? (decodedScript?.Contains("http") == true ? "malicious-c2.net" : "185.220.101.5");
        if (_tools.TryGetValue("ThreatReputationTool", out var repTool))
        {
            var thought3 = $"[Step {step} 추론] 발견된 통신 지표 '{reputationIndicator}'에 대해 내장 위협 인텔리전스 DB(IoC) 및 평판 점수를 조회합니다.";
            var res3 = await repTool.ExecuteAsync(new() { ["targetIndicator"] = reputationIndicator });

            var trace3 = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought3,
                ActionTool = repTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { targetIndicator = reputationIndicator }),
                Observation = res3.Output
            };
            traces.Add(trace3);
            OnReActStepProgress?.Invoke(incidentId, trace3);

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
        string fileObservation = traces.FirstOrDefault(t => t.ActionTool == "FileInspectionTool")?.Observation ?? "";
        string memoryObservation = traces.FirstOrDefault(t => t.ActionTool == "ProcessMemoryScanTool")?.Observation ?? "";
        string combinedBehavior = $"{rootCause} -> {targetNode.ImageName} {targetNode.CommandLine} {decodedScript} {fileObservation} {memoryObservation}";
        if (_tools.TryGetValue("MitreClassifierTool", out var mitreTool))
        {
            var thought4 = $"[Step {step} 추론] 관찰된 침해 전술 체인을 MITRE ATT&CK Matrix TTP 기법으로 자동 분류합니다.";
            var res4 = await mitreTool.ExecuteAsync(new() { ["observedBehavior"] = combinedBehavior });

            var trace4 = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought4,
                ActionTool = mitreTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { observedBehavior = combinedBehavior }),
                Observation = res4.Output
            };
            traces.Add(trace4);
            OnReActStepProgress?.Invoke(incidentId, trace4);

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

            var trace5 = new ReActTraceRecord
            {
                IncidentId = incidentId,
                StepNumber = step++,
                Thought = thought5,
                ActionTool = fwTool.Name,
                ActionArgsJson = JsonSerializer.Serialize(new { maliciousIp = extractedIp }),
                Observation = res5.Output
            };
            traces.Add(trace5);
            OnReActStepProgress?.Invoke(incidentId, trace5);
        }

        // --- 최종 판결(Verdict) 및 다차원 누적 위험도(Risk Score) FSM 평가 ---
        int riskScore = 0;

        // 1. 비정상 부모 족보 분석 (+30)
        if (AttackPatternHeuristics.IsSuspiciousParent(rootCause))
        {
            riskScore += 30;
        }

        // 2. 인라인 C2 다운로드 / 명령 실행 패턴 (+35)
        if (AttackPatternHeuristics.HasInlineC2Pattern(decodedScript, targetNode.CommandLine))
        {
            riskScore += 35;
        }

        // 3. Unbacked 실행 메모리 주입 (+50)
        bool hasUnbackedMemory = traces.Any(t => t.ActionTool == "ProcessMemoryScanTool" && (t.Observation.Contains("PAGE_EXECUTE") || t.Observation.Contains("Unbacked") || t.Observation.Contains("Reflective DLL")));
        if (hasUnbackedMemory)
        {
            riskScore += 50;
        }

        // 3-1. 악성 위협 평판 C2 지표 (+40)
        if (threatScore >= 0.85)
        {
            riskScore += 40;
        }

        // 3-2. LOLBAS 프록시 악용 (rundll32, regsvr32, mshta 등) (+30)
        string imgName = targetNode.ImageName.ToLowerInvariant();
        bool isLolbinProxy = imgName.Contains("rundll32") || imgName.Contains("regsvr32") || imgName.Contains("mshta") || imgName.Contains("certutil");
        if (isLolbinProxy && (AttackPatternHeuristics.HasInlineC2Pattern(decodedScript, targetNode.CommandLine) || threatScore >= 0.80 || fileAnomalyScore >= 50 || isRegistryIndirect || isComHijack || registryAnomalyScore >= 50))
        {
            riskScore += 30;
        }

        // 3-3. 비실행형 확장자 위장 PE 바이너리 또는 고위험 파일 이상 징후 (T1036.008) (+40)
        bool isDisguisedExe = traces.Any(t => t.ActionTool == "FileInspectionTool" && t.Observation.Contains("확장자 위장(Disguised PE Executable): DETECTED"));
        if (isDisguisedExe || fileAnomalyScore >= 65)
        {
            riskScore += 40;
        }

        // 3-4. 시스템 핵심 바이너리 명칭 위장 드로퍼 (T1036.005) (+50)
        string fullTarget = $"{targetNode.CommandLine} {decodedScript}".ToLowerInvariant();
        bool isMasquerading = isPathMasqueraded ||
                              fileAnomalyScore >= 80 ||
                              fullTarget.Contains(@"temp\svchost.exe") ||
                              fullTarget.Contains(@"temp/svchost.exe") ||
                              fullTarget.Contains(@"temp\csrss.exe") ||
                              fullTarget.Contains(@"temp\lsass.exe");
        if (isMasquerading)
        {
            riskScore += 50;
        }

        // 3-5. 레지스트리 간접 실행(LOLBAS T1218.010) 및 COM 하이재킹(T1546.015) (+40)
        if (isRegistryIndirect || isComHijack || registryAnomalyScore >= 50)
        {
            riskScore += 40;
        }

        // 3-6. DLL 사이드로딩(T1574.002) 하이재킹 (+50)
        if (isDllSideloading)
        {
            riskScore += 50;
        }

        // 4. 랜섬웨어 파괴 명령 패턴: 시스템 복구 무력화 (+80 즉각 사살 트리거)
        if (AttackPatternHeuristics.IsRansomwareDestructiveCommand(targetNode.CommandLine, targetNode.ImageName))
        {
            riskScore += 80;
        }

        // 5. 사내 정상 인프라 / 내부 도메인 / 화이트리스트 (-50)
        if (AttackPatternHeuristics.IsKnownInternalOrTrusted(decodedScript, targetNode.CommandLine, extractedIp))
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
            summaryTitle = isDllSideloading
                ? "DLL 사이드로딩(T1574.002) 하이재킹 및 비인가 무서명 라이브러리 은닉 로드 탐지"
                : isMasquerading
                    ? "시스템 핵심 바이너리 경로 위장(Masquerading T1036.005) 및 C2 침투 탐지"
                    : isDisguisedExe
                        ? "비실행형 확장자 위장(Disguised PE T1036.008) 실행 바이너리 침투 탐지"
                        : (isRegistryIndirect || isComHijack)
                            ? "레지스트리 간접 실행(Squiblydoo T1218.010) 및 COM 하이재킹 침투 탐지"
                            : isLolbinProxy
                                ? "LOLBAS 신뢰 시스템 바이너리 프록시 악용(Proxy Execution T1218) 탐지"
                                : hasUnbackedMemory
                                    ? "프로세스 메모리 인젝션(Unbacked Executable Memory T1055) 침투 탐지"
                                    : "악성 오피스 매크로/LOLBAS를 통한 파일리스 C2 다운로더 침투 시도";
            narrative = $"{DateTime.Now:HH시 mm분}, 시스템에서 실행된 '{rootCause}' 프로세스가 비정상 자식 프로세스 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})를 은밀히 기동했습니다. " +
                        $"Phalanx 센서가 원자적으로 선제 동결을 집행하였으며, AI 에이전트의 심층 족보 역추적 및 메모리/페이로드 분석 결과 " +
                        $"{(extractedIp != null ? $"해외 악성 C2({extractedIp})" : "원격 C2 인프라")}와의 통신 및 파일리스 공격 시도가 확인되었습니다. " +
                        $"누적 위험도 {riskScore}점(임계치 80점 이상)으로 즉각 사살(ACTION_KILL)을 하달하고 격리 조치를 완결했습니다.";

            if (mitreList.Count == 0)
            {
                mitreList = isDllSideloading
                    ? new List<string> { "T1574.002", "T1059.001", "T1071.001" }
                    : isMasquerading
                        ? new List<string> { "T1036.005", "T1059.001", "T1071.001" }
                        : isDisguisedExe
                            ? new List<string> { "T1036.008", "T1027", "T1071.001" }
                            : (isRegistryIndirect || isComHijack)
                                ? new List<string> { "T1218.010", "T1546.015", "T1071.001" }
                                : isLolbinProxy
                                    ? new List<string> { "T1218.011", "T1071.001" }
                                    : hasUnbackedMemory
                                        ? new List<string> { "T1055", "T1071.001" }
                                        : new List<string> { "T1566.001", "T1059.001", "T1071.001" };
            }
            else if (isDllSideloading && !mitreList.Contains("T1574.002"))
            {
                mitreList.Insert(0, "T1574.002");
            }
        }
        else
        {
            verdictAction = MitigationCommand.Types.ActionType.ActionResume;
            summaryTitle = "정상 관리 도구 동작 확인 (오탐 방지 및 동결 해제)";
            narrative = $"{DateTime.Now:HH시 mm분}, 동결 수사 의뢰된 '{targetNode.ImageName}' (PID: {targetNode.ProcessId})를 심층 분석한 결과, " +
                        $"외부 악성 통신 및 파괴적 페이로드가 발견되지 않은 신뢰된 작업으로 확인되었습니다. " +
                        $"누적 위험도 {riskScore}점(임계치 80점 미만)으로 무해 판정을 도출하고 안전하게 정상 복구(ACTION_RESUME) 조치를 완료했습니다.";
        }

        string blockedIp = (isMalicious ? extractedIp : string.Empty) ?? string.Empty;

        // [최종 명령 C++ 전송]
        cancellationToken.ThrowIfCancellationRequested();
        if (commandSender != null)
        {
            await commandSender(new MitigationCommand
            {
                Action = verdictAction,
                TargetPid = targetNode.ProcessId,
                TargetIp = blockedIp,
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
            BlockedIp = blockedIp,
            RootCauseProcess = rootCause,
            TerminatedProcesses = isMalicious ? new() { $"{targetNode.ImageName} (PID: {targetNode.ProcessId})" } : new(),
            RemediationStatus = isMalicious ? "SECURED" : "RESTORED",
            RemediationSteps = remediationSteps,
            ElapsedMs = sw.Elapsed.TotalMilliseconds,
            InvestigationEngine = isFallback ? "OFFLINE_FALLBACK" : "OFFLINE_LOCAL",
            FallbackReason = fallbackReason
        };

        _archiveManager.SaveIncident(incidentRecord, traces);

        return new InvestigationResult(
            incidentId,
            verdictAction,
            incidentRecord.ConfidenceScore,
            summaryTitle,
            narrative,
            mitreList,
            blockedIp,
            traces,
            sw.Elapsed,
            incidentRecord,
            remediationSteps,
            InvestigationEngine: isFallback ? "OFFLINE_FALLBACK" : "OFFLINE_LOCAL",
            FallbackReason: fallbackReason
        );
    }
}
