using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

public class ToolInvocationTraceAuditingTests : IDisposable
{
    private readonly ITestOutputHelper _output;

    public ToolInvocationTraceAuditingTests(ITestOutputHelper output)
    {
        _output = output;
    }

    public void Dispose()
    {
        FileInspectionTool.ClearSimulatedFiles();
        RegistryInspectionTool.ClearSimulatedKeys();
        ProcessMemoryScanTool.ClearSimulatedMemory(2006);
        ProcessMemoryScanTool.ClearSimulatedMemory(2007);
        ProcessMemoryScanTool.ClearSimulatedMemory(2008);
        ProcessMemoryScanTool.ClearSimulatedMemory(2009);
    }

    private static (ProcessTreeProjectionManager Tree, ForensicArchiveManager Archive, AutonomousHunterAgent Agent) CreateHarness()
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
            new FileInspectionTool(),
            new RegistryInspectionTool()
        };
        var agent = new AutonomousHunterAgent(tree, archive, tools, geminiApiKey: string.Empty);
        return (tree, archive, agent);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task Audit_Scenario08_RegistryInspectionTool_ActuallyInvoked_And_EvidenceCaptured()
    {
        _output.WriteLine("=========================================================================================");
        _output.WriteLine("[정밀 검증] 시나리오 08: RegistryInspectionTool 실제 호출 및 Squiblydoo 간접 실행 증거 포착");
        _output.WriteLine("=========================================================================================");

        var (tree, archive, agent) = CreateHarness();
        uint parentPid = 1008;
        uint targetPid = 2008;

        string mockClsidKey = @"Software\Classes\CLSID\{F0001111-0000-0000-0000-000000000001}";
        RegistryInspectionTool.RegisterSimulatedKey(
            mockClsidKey,
            RegistryInspectionTool.CreateSimulatedEntry(
                keyPath: mockClsidKey,
                exists: true,
                defaultValue: "Malicious Squiblydoo Component",
                values: new Dictionary<string, object>
                {
                    ["ScriptletURL"] = "http://185.220.101.5/payload.sct",
                    ["InprocServer32"] = @"C:\Windows\System32\scrobj.dll"
                },
                subKeys: new List<string> { "InprocServer32" }
            )
        );

        tree.ApplySnapshotBatch(new[]
        {
            new ProcessEvent { ProcessId = parentPid, ImageName = "cmd.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
        });

        tree.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = targetPid,
            ParentProcessId = parentPid,
            ImageName = "regsvr32.exe",
            CommandLine = @"regsvr32.exe /s /u /i:Software\Classes\CLSID\{F0001111-0000-0000-0000-000000000001} scrobj.dll",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var target = tree.FindActiveNodeByPid(targetPid);
        Assert.NotNull(target);

        // Act
        var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

        // 정밀 단언 및 콘솔 증거 출력
        _output.WriteLine($"최종 판결: {res.VerdictAction} | 확신도: {res.Confidence:P0} | 소요시간: {res.Elapsed.TotalMilliseconds:F2}ms");
        _output.WriteLine($"사건 타이틀: {res.SummaryTitle}");
        _output.WriteLine($"차단된 C2 IP: {res.BlockedIp}");
        _output.WriteLine($"실행된 전체 턴 수: {res.Traces.Count}");
        _output.WriteLine("--- [ReAct 수사관 전체 실행 트레이스 (Turn-by-Turn Evidence)] ---");

        foreach (var t in res.Traces)
        {
            _output.WriteLine($"[Step {t.StepNumber}] 도구: {t.ActionTool}");
            _output.WriteLine($"  - 추론(Thought): {t.Thought}");
            _output.WriteLine($"  - 인자(Args): {t.ActionArgsJson}");
            _output.WriteLine($"  - 관측(Observation):\n{Indent(t.Observation, "    | ")}");
        }

        // Assert 1: 신규 도구 RegistryInspectionTool이 실제 호출되었는가?
        var regTrace = res.Traces.FirstOrDefault(t => t.ActionTool == "RegistryInspectionTool");
        Assert.NotNull(regTrace);
        Assert.Contains("{F0001111-0000-0000-0000-000000000001}", regTrace.ActionArgsJson);
        Assert.Contains("Squiblydoo", regTrace.Observation);
        Assert.Contains("185.220.101.5", regTrace.Observation);

        // Assert 2: 후속 조치로 SystemFirewallTool이 추출된 C2 IP를 차단했는가?
        var fwTrace = res.Traces.FirstOrDefault(t => t.ActionTool == "SystemFirewallTool");
        Assert.NotNull(fwTrace);
        Assert.Contains("185.220.101.5", fwTrace.ActionArgsJson);

        // Assert 3: 최종 사살 집행 확인
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
        Assert.Contains("T1218.010", res.MitreTactics);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task Audit_Scenario06_FileInspectionTool_DllSideloading_ActuallyInvoked_And_EvidenceCaptured()
    {
        _output.WriteLine("=========================================================================================");
        _output.WriteLine("[정밀 검증] 시나리오 06: FileInspectionTool 실제 호출 및 DLL 사이드로딩(T1574.002) 증거 포착");
        _output.WriteLine("=========================================================================================");

        var (tree, archive, agent) = CreateHarness();
        uint parentPid = 1006;
        uint targetPid = 2006;

        string publicDir = @"C:\Users\Public\OneDrive";
        string exePath = Path.Combine(publicDir, "OneDriveUpdate.exe");
        string dllPath = Path.Combine(publicDir, "version.dll");

        FileInspectionTool.RegisterSimulatedFile(exePath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 204800L,
            Sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Entropy: 6.3210,
            IsSigned: true,
            SignerSubject: "CN=Microsoft Corporation, O=Microsoft Corporation",
            SignatureStatus: "Valid (Signed by Microsoft)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 0,
            DiagnosticReason: "정상 디지털 서명 검증됨 (Microsoft Corporation)"
        ));

        FileInspectionTool.RegisterSimulatedFile(dllPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 65536L,
            Sha256: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            Entropy: 5.6012,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 60,
            DiagnosticReason: "비표준 디렉터리 내 시스템 라이브러리 사이드로딩(T1574.002) 포착: 'version.dll' (무서명)"
        ));

        tree.ApplySnapshotBatch(new[]
        {
            new ProcessEvent { ProcessId = parentPid, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
        });

        tree.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = targetPid,
            ParentProcessId = parentPid,
            ImageName = exePath,
            CommandLine = $@"{exePath} /background",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var target = tree.FindActiveNodeByPid(targetPid);
        Assert.NotNull(target);

        // Act
        var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

        // 정밀 단언 및 콘솔 증거 출력
        _output.WriteLine($"최종 판결: {res.VerdictAction} | 확신도: {res.Confidence:P0} | 소요시간: {res.Elapsed.TotalMilliseconds:F2}ms");
        _output.WriteLine($"사건 타이틀: {res.SummaryTitle}");
        _output.WriteLine($"실행된 전체 턴 수: {res.Traces.Count}");
        _output.WriteLine("--- [ReAct 수사관 전체 실행 트레이스 (Turn-by-Turn Evidence)] ---");

        foreach (var t in res.Traces)
        {
            _output.WriteLine($"[Step {t.StepNumber}] 도구: {t.ActionTool}");
            _output.WriteLine($"  - 추론(Thought): {t.Thought}");
            _output.WriteLine($"  - 인자(Args): {t.ActionArgsJson}");
            _output.WriteLine($"  - 관측(Observation):\n{Indent(t.Observation, "    | ")}");
        }

        // Assert 1: FileInspectionTool이 실제 호출되었는가?
        var fileTrace = res.Traces.FirstOrDefault(t => t.ActionTool == "FileInspectionTool");
        Assert.NotNull(fileTrace);
        Assert.Contains("OneDriveUpdate.exe", fileTrace.ActionArgsJson);
        Assert.Contains("DLL 사이드로딩(T1574.002): DETECTED", fileTrace.Observation);
        Assert.Contains("version.dll", fileTrace.Observation);

        // Assert 2: ProcessMemoryScanTool도 수사 체인에서 호출되었는가?
        var memTrace = res.Traces.FirstOrDefault(t => t.ActionTool == "ProcessMemoryScanTool");
        Assert.NotNull(memTrace);

        // Assert 3: 최종 사살 및 MITRE T1574.002 등록 확인
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
        Assert.Contains("T1574.002", res.MitreTactics);
        Assert.Contains("DLL 사이드로딩", res.SummaryTitle);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task Audit_Scenario09_FileInspectionTool_UnicodeHomoglyph_ActuallyInvoked_And_EvidenceCaptured()
    {
        _output.WriteLine("=========================================================================================");
        _output.WriteLine("[정밀 검증] 시나리오 09: FileInspectionTool 실제 호출 및 UTR #39 키릴 자모 위장 증거 포착");
        _output.WriteLine("=========================================================================================");

        var (tree, archive, agent) = CreateHarness();
        uint parentPid = 1009;
        uint targetPid = 2009;

        string homoglyphExe = "svch\u043Est.exe"; // Cyrillic Small Letter O (U+043E)
        string homoglyphPath = $@"C:\Windows\System32\{homoglyphExe}";

        FileInspectionTool.RegisterSimulatedFile(homoglyphPath, FileInspectionTool.CreateSimulatedEntry(
            filePath: homoglyphPath,
            exists: true,
            fileSizeBytes: 204800L,
            sha256: "9999999999999999999999999999999999999999999999999999999999999999",
            entropy: 6.8421,
            isSigned: false,
            signerSubject: string.Empty,
            signatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)"
        ));

        tree.ApplySnapshotBatch(new[]
        {
            new ProcessEvent { ProcessId = parentPid, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
        });

        tree.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = targetPid,
            ParentProcessId = parentPid,
            ImageName = homoglyphPath,
            CommandLine = $@"{homoglyphPath} -k DcomLaunch",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var target = tree.FindActiveNodeByPid(targetPid);
        Assert.NotNull(target);

        // Act
        var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);

        // 정밀 단언 및 콘솔 증거 출력
        _output.WriteLine($"최종 판결: {res.VerdictAction} | 확신도: {res.Confidence:P0} | 소요시간: {res.Elapsed.TotalMilliseconds:F2}ms");
        _output.WriteLine($"사건 타이틀: {res.SummaryTitle}");
        _output.WriteLine($"실행된 전체 턴 수: {res.Traces.Count}");
        _output.WriteLine("--- [ReAct 수사관 전체 실행 트레이스 (Turn-by-Turn Evidence)] ---");

        foreach (var t in res.Traces)
        {
            _output.WriteLine($"[Step {t.StepNumber}] 도구: {t.ActionTool}");
            _output.WriteLine($"  - 추론(Thought): {t.Thought}");
            _output.WriteLine($"  - 인자(Args): {t.ActionArgsJson}");
            _output.WriteLine($"  - 관측(Observation):\n{Indent(t.Observation, "    | ")}");
        }

        // Assert 1: FileInspectionTool이 호출되었는가?
        var fileTrace = res.Traces.FirstOrDefault(t => t.ActionTool == "FileInspectionTool");
        Assert.NotNull(fileTrace);
        Assert.Contains("CRITICAL DETECTED", fileTrace.Observation);
        Assert.Contains("UTR #39", fileTrace.Observation);

        // Assert 2: 최종 사살 및 MITRE T1036.005 확인
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
        Assert.Contains("T1036.005", res.MitreTactics);
    }

    private static string Indent(string text, string prefix)
    {
        if (string.IsNullOrEmpty(text)) return prefix;
        return string.Join(Environment.NewLine, text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None).Select(line => prefix + line));
    }
}
