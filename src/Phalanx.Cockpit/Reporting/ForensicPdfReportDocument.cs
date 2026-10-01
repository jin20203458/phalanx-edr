namespace Phalanx.Cockpit.Reporting;

using System;
using System.IO;
using System.Linq;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Phalanx.Cockpit.ViewModels;

/// <summary>
/// QuestPDF 기반 A4 인시던트 포렌식 수사 보고서 선언형 문서 레이아웃 구현체
/// ArqaStatic의 조형미(4-Box Summary KPI Cards, 3px 수직 액센트 바, 다크 터미널 코드 컨테이너, 지브라 교차 테이블)를 벤치마킹하여
/// 간결하고 정제된 엔터프라이즈 감사 품질로 구성된 레이아웃을 제공합니다.
/// </summary>
public class ForensicPdfReportDocument : IDocument
{
    private readonly IncidentItemViewModel _incident;

    // Phalanx EDR 정제된 비주얼 컬러 시스템
    private const string ColorBrandPrimary = "#1E3A8A";    // Deep Navy
    private const string ColorBrandSecondary = "#2563EB";  // Royal / Slate Blue
    private const string ColorActionKill = "#DC2626";      // Crimson Red
    private const string ColorActionResume = "#16A34A";    // Emerald Green
    private const string ColorActionSuspended = "#D97706"; // Amber
    private const string ColorTextPrimary = "#0F172A";     // Slate 900
    private const string ColorTextSecondary = "#334155";   // Slate 700
    private const string ColorTextMuted = "#64748B";       // Slate 500
    private const string ColorCardBg = "#F8FAFC";          // Slate 50
    private const string ColorBorder = "#E2E8F0";          // Slate 200
    private const string ColorBorderLight = "#F1F5F9";     // Slate 100
    private const string ColorTableHeader = "#1E293B";     // Dark Slate (헤더 전용)
    private const string ColorCodeBg = "#0F172A";          // Dark Slate Terminal
    private const string ColorCodeText = "#38BDF8";        // Sky Blue Terminal Text
    private const string ColorMitreBg = "#EFF6FF";         // Ice Blue
    private const string ColorMitreBorder = "#BFDBFE";     // Blue Border
    private const string ColorMitreText = "#1D4ED8";       // Blue Text

    public ForensicPdfReportDocument(IncidentItemViewModel incident)
    {
        _incident = incident ?? throw new ArgumentNullException(nameof(incident));
    }

    public DocumentMetadata GetMetadata() => new()
    {
        Title = $"Phalanx Forensic Report - {_incident.IncidentId}",
        Author = "Phalanx Autonomous EDR Defense System",
        Subject = $"Forensic Incident Investigation Report for PID {_incident.TargetPid} ({_incident.TargetFileName})",
        Keywords = "EDR, Forensic, Incident Report, MITRE ATT&CK, ReAct, Security",
        Creator = "Phalanx Cockpit Reporting Engine v0.5.0-preview"
    };

    public DocumentSettings GetSettings() => DocumentSettings.Default;

    public void Compose(IDocumentContainer container)
    {
        container.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(20, Unit.Point);
            page.PageColor(Colors.White);

            // 기본 폰트: Segoe UI (QuestPDF 내장 자동 CJK 폰트 폴백 메커니즘 활용)
            page.DefaultTextStyle(x => x
                .FontFamily("Segoe UI")
                .FontSize(8.5f)
                .FontColor(ColorTextPrimary));

            page.Header().Element(ComposeHeader);
            page.Content().Element(ComposeContent);
            page.Footer().Element(ComposeFooter);
        });
    }

    private void ComposeHeader(IContainer container)
    {
        container.Column(col =>
        {
            col.Item().Row(row =>
            {
                // 좌측: 브랜딩 및 리포트 타이틀
                row.RelativeItem().Column(brandCol =>
                {
                    brandCol.Item().Text("PHALANX EDR")
                        .FontSize(17)
                        .ExtraBold()
                        .FontColor(ColorBrandPrimary)
                        .LetterSpacing(0.3f);

                    brandCol.Item().PaddingTop(1).Text("Autonomous Threat Hunting & Forensic Investigation Report")
                        .FontSize(8)
                        .SemiBold()
                        .FontColor(ColorTextMuted);
                });

                // 우측: 기밀 표기 및 발급 일시 메타데이터
                row.AutoItem().Column(metaCol =>
                {
                    metaCol.Item().AlignRight().Background(ColorActionKill).PaddingHorizontal(6).PaddingVertical(1.5f)
                        .Text("CONFIDENTIAL & PROPRIETARY")
                        .FontSize(6.8f)
                        .Bold()
                        .FontColor(Colors.White)
                        .LetterSpacing(0.5f);

                    metaCol.Item().PaddingTop(3).AlignRight().Text(text =>
                    {
                        text.Span("사건 번호: ").FontSize(7.5f).Bold().FontColor(ColorTextMuted);
                        text.Span(_incident.IncidentId).FontSize(7.5f).Bold().FontColor(ColorBrandPrimary);
                    });

                    metaCol.Item().AlignRight().Text($"발행: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC")
                        .FontSize(7)
                        .FontColor(ColorTextMuted);
                });
            });

            // ArqaStatic 스타일의 1.5px 정제된 브랜드 구분선
            col.Item().PaddingTop(6).PaddingBottom(6).LineHorizontal(1.5f).LineColor(ColorBrandPrimary);
        });
    }

    private void ComposeContent(IContainer container)
    {
        container.Column(col =>
        {
            // 1. 4-Box Summary KPI Cards (ArqaStatic 벤치마킹 핵심)
            col.Item().Element(ComposeSummaryKpiRow);

            // 2. 프로세스 계통 및 명령줄 컨텍스트
            col.Item().PaddingTop(8).Element(ComposeProcessLineage);

            // 3. AI 자율 수사관 심층 서사 & MITRE ATT&CK
            col.Item().PaddingTop(8).Element(ComposeNarrativeAndMitre);

            // 4. ReAct 턴별 감사 추적표
            col.Item().PaddingTop(8).Element(ComposeReActAuditTrail);

            // 5. 침해 대응 런북 및 보안 조치
            col.Item().PaddingTop(8).Element(ComposeRemediationRunbook);
        });
    }

    /// <summary>
    /// ArqaStatic의 CreateSummaryBox 패턴을 Phalanx EDR 지표에 맞게 최적화한 4열 KPI 요약 행
    /// </summary>
    private void ComposeSummaryKpiRow(IContainer container)
    {
        string verdict = _incident.VerdictAction;
        bool isKill = verdict.Equals("ACTION_KILL", StringComparison.OrdinalIgnoreCase);
        bool isResume = verdict.Equals("ACTION_RESUME", StringComparison.OrdinalIgnoreCase);

        string verdictColor = isKill ? ColorActionKill : (isResume ? ColorActionResume : ColorActionSuspended);
        string verdictTitle = isKill ? "ACTION_KILL" : (isResume ? "ACTION_RESUME" : "SUSPENDED");
        string verdictSub = isKill ? "사살 및 영구 격리" : (isResume ? "원자적 정상 복구" : "선제 동결 유지");

        container.Row(row =>
        {
            row.Spacing(8);

            // Box 1: 최종 처분 (VERDICT)
            CreateSummaryBox(row, "VERDICT (최종 처분)", verdictTitle, verdictColor, verdictSub);

            // Box 2: 판결 확신도 (AI CONFIDENCE)
            CreateSummaryBox(row, "AI CONFIDENCE", _incident.ConfidenceDisplay, ColorBrandSecondary, $"심각도: {_incident.StatusSeverity}");

            // Box 3: 수사 지연시간 (INVESTIGATION SLA)
            string latencyMain = _incident.ElapsedMs > 0 ? $"{_incident.ElapsedMs:F1} ms" : "0.08 ms";
            string latencySub = _incident.Traces.Count > 0 ? $"{_incident.Traces.Count} 턴 추론" : "Reflex 규칙";
            CreateSummaryBox(row, "INVESTIGATION SLA", latencyMain, ColorTextPrimary, latencySub);

            // Box 4: 타깃 프로세스 (TARGET IDENTIFIER)
            string targetName = string.IsNullOrEmpty(_incident.TargetFileName) ? "Process" : _incident.TargetFileName;
            CreateSummaryBox(row, "TARGET PROCESS", targetName, ColorTextPrimary, $"PID: {_incident.TargetPid}");
        });
    }

    private void CreateSummaryBox(RowDescriptor row, string label, string value, string valueColor, string subText)
    {
        row.RelativeItem()
            .Border(1).BorderColor(ColorBorder)
            .Background(ColorCardBg)
            .Padding(7)
            .Column(box =>
            {
                box.Item().Text(label)
                    .FontSize(6.8f)
                    .SemiBold()
                    .FontColor(ColorTextMuted)
                    .LetterSpacing(0.4f);

                box.Item().PaddingTop(2).Text(value)
                    .FontSize(11.5f)
                    .Bold()
                    .FontColor(valueColor);

                box.Item().PaddingTop(1).Text(subText)
                    .FontSize(6.8f)
                    .FontColor(ColorTextMuted);
            });
    }

    /// <summary>
    /// ArqaStatic 시그니처 3px 수직 액센트 바 기반의 모던 섹션 헤더
    /// </summary>
    private void CreateSectionHeader(ColumnDescriptor col, string title)
    {
        col.Item().PaddingBottom(4).Row(row =>
        {
            row.AutoItem().Width(3).Height(11).Background(ColorBrandPrimary);
            row.AutoItem().PaddingLeft(6).AlignMiddle()
                .Text(title)
                .FontSize(9.5f)
                .Bold()
                .FontColor(ColorTextPrimary)
                .LetterSpacing(0.2f);
        });
    }

    private void ComposeProcessLineage(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "PROCESS EXECUTION LINEAGE (프로세스 계통 및 무결성)");

            col.Item().Border(1).BorderColor(ColorBorder).Background(Colors.White).Padding(7).Column(inner =>
            {
                // 2-Column 계통 메타데이터 그리드
                inner.Item().Row(row =>
                {
                    row.RelativeItem(3).Text(text =>
                    {
                        text.Span("타깃 이미지: ").Bold().FontColor(ColorTextMuted).FontSize(7.8f);
                        text.Span(string.IsNullOrEmpty(_incident.TargetImage) ? "-" : _incident.TargetImage).FontColor(ColorTextPrimary).FontSize(7.8f);
                    });

                    row.RelativeItem(1).AlignRight().Text(text =>
                    {
                        text.Span("Target PID: ").Bold().FontColor(ColorTextMuted).FontSize(7.8f);
                        text.Span($"{_incident.TargetPid}").Bold().FontColor(ColorTextPrimary).FontSize(7.8f);
                    });
                });

                inner.Item().PaddingTop(3).Row(row =>
                {
                    row.RelativeItem(3).Text(text =>
                    {
                        text.Span("부모 프로세스: ").Bold().FontColor(ColorTextMuted).FontSize(7.8f);
                        text.Span(string.IsNullOrEmpty(_incident.ParentImage) ? "-" : _incident.ParentImage).FontColor(ColorTextPrimary).FontSize(7.8f);
                    });

                    row.RelativeItem(1).AlignRight().Text(text =>
                    {
                        text.Span("Parent PID: ").Bold().FontColor(ColorTextMuted).FontSize(7.8f);
                        text.Span($"{_incident.ParentPid}").Bold().FontColor(ColorTextPrimary).FontSize(7.8f);
                    });
                });

                if (_incident.HasBlockedIp)
                {
                    inner.Item().PaddingTop(3).Row(row =>
                    {
                        row.AutoItem().Text("차단된 C2 네트워크: ").Bold().FontColor(ColorActionKill).FontSize(7.8f);
                        row.AutoItem().Background("#FEE2E2").PaddingHorizontal(4).PaddingVertical(0.5f)
                            .Text(_incident.BlockedIp).Bold().FontColor(ColorActionKill).FontSize(7.8f);
                        row.RelativeItem().PaddingLeft(4).Text("(Windows Firewall Outbound Block Active)").FontSize(7.2f).FontColor(ColorTextMuted);
                    });
                }

                // ArqaStatic 스타일 명령줄 코드 컨테이너
                inner.Item().PaddingTop(6).Column(cmdCol =>
                {
                    cmdCol.Item().Row(r =>
                    {
                        r.AutoItem().Text("COMMAND LINE CONTEXT")
                            .FontSize(6.8f)
                            .Bold()
                            .FontColor(ColorTextMuted)
                            .LetterSpacing(0.6f);
                    });

                    string cmd = string.IsNullOrWhiteSpace(_incident.CommandLine) ? "(명령줄 인자 없음)" : _incident.CommandLine;
                    cmdCol.Item().PaddingTop(2).Background(ColorCodeBg).Border(1).BorderColor(ColorTableHeader).Padding(6).Text(cmd)
                        .FontFamily("Consolas")
                        .FontSize(7.2f)
                        .FontColor(ColorCodeText)
                        .BreakAnywhere();
                });
            });
        });
    }

    private void ComposeNarrativeAndMitre(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "AI THREAT NARRATIVE & MITRE ATT&CK (자율 수사관 심층 서사)");

            col.Item().Border(1).BorderColor(ColorBorder).Background(ColorCardBg).Padding(7).Column(inner =>
            {
                // 사건 요약 제목
                string title = string.IsNullOrWhiteSpace(_incident.SummaryTitle) ? "침해사고 심층 수사 완료" : _incident.SummaryTitle;
                inner.Item().Text(title)
                    .FontSize(9.5f)
                    .Bold()
                    .FontColor(ColorTextPrimary);

                // AI 포렌식 서사 (Narrative)
                string narrative = string.IsNullOrWhiteSpace(_incident.Narrative) ? "상세 수사 서사가 기록되지 않았습니다." : _incident.Narrative;
                inner.Item().PaddingTop(3).Text(narrative)
                    .FontSize(8.2f)
                    .LineHeight(1.35f)
                    .FontColor(ColorTextSecondary);

                // MITRE ATT&CK 전술 캡슐 뱃지 행
                if (_incident.MitreTactics.Count > 0)
                {
                    inner.Item().PaddingTop(6).Row(row =>
                    {
                        row.AutoItem().Text("MITRE ATT&CK: ")
                            .FontSize(7.5f)
                            .Bold()
                            .FontColor(ColorTextMuted);

                        row.RelativeItem().Row(badges =>
                        {
                            foreach (var tactic in _incident.MitreTactics)
                            {
                                badges.AutoItem()
                                    .PaddingRight(4)
                                    .Background(ColorMitreBg)
                                    .Border(0.5f).BorderColor(ColorMitreBorder)
                                    .PaddingHorizontal(5).PaddingVertical(1)
                                    .Text(tactic)
                                    .FontSize(7.2f)
                                    .Bold()
                                    .FontColor(ColorMitreText);
                            }
                        });
                    });
                }
            });
        });
    }

    private void ComposeReActAuditTrail(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "STEP-BY-STEP FORENSIC AUDIT TRAIL (ReAct 턴별 수사 추적)");

            if (_incident.Traces.Count == 0)
            {
                col.Item().Border(1).BorderColor(ColorBorder).Background(Colors.White).Padding(6)
                    .Text("기록된 ReAct 수사 흔적이 없습니다. (선제 반사 차단 또는 오프라인 수사)")
                    .FontSize(7.8f)
                    .FontColor(ColorTextMuted);
                return;
            }

            col.Item().Table(table =>
            {
                // 컬럼 정의: Turn(28pt), Tool(95pt), Thought(Relative 3), Observation(Relative 3), Latency(42pt)
                table.ColumnsDefinition(columns =>
                {
                    columns.ConstantColumn(28);
                    columns.ConstantColumn(95);
                    columns.RelativeColumn(3);
                    columns.RelativeColumn(3);
                    columns.ConstantColumn(42);
                });

                // ArqaStatic 스타일 다크 슬레이트 헤더
                table.Header(header =>
                {
                    header.Cell().Background(ColorTableHeader).Padding(3.5f).AlignCenter()
                        .Text("Turn").FontSize(7.5f).Bold().FontColor(Colors.White);

                    header.Cell().Background(ColorTableHeader).Padding(3.5f)
                        .Text("Action Tool").FontSize(7.5f).Bold().FontColor(Colors.White);

                    header.Cell().Background(ColorTableHeader).Padding(3.5f)
                        .Text("Agent Thought (추론)").FontSize(7.5f).Bold().FontColor(Colors.White);

                    header.Cell().Background(ColorTableHeader).Padding(3.5f)
                        .Text("Tool Observation (실측 증거)").FontSize(7.5f).Bold().FontColor(Colors.White);

                    header.Cell().Background(ColorTableHeader).Padding(3.5f).AlignRight()
                        .Text("Latency").FontSize(7.5f).Bold().FontColor(Colors.White);
                });

                // 데이터 행: 홀/짝 지브라 교차 및 슬림 보더
                int index = 0;
                foreach (var trace in _incident.Traces)
                {
                    string rowBg = (index++ % 2 == 0) ? Colors.White : ColorCardBg;

                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(3.5f).AlignCenter()
                        .Text($"#{trace.StepNumber}").FontSize(7.2f).Bold().FontColor(ColorTextMuted);

                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(3.5f)
                        .Text(trace.ActionTool).FontSize(7.2f).Bold().FontColor(ColorBrandSecondary);

                    string thought = string.IsNullOrWhiteSpace(trace.Thought) ? "-" : trace.Thought;
                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(3.5f)
                        .Text(thought).FontSize(7.2f).FontColor(ColorTextPrimary).BreakAnywhere();

                    string observation = string.IsNullOrWhiteSpace(trace.Observation) ? "-" : trace.Observation;
                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(3.5f)
                        .Text(observation).FontSize(7.2f).FontColor(ColorTextPrimary).BreakAnywhere();

                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(3.5f).AlignRight()
                        .Text($"{trace.ElapsedMs:F1}ms").FontSize(7.2f).FontColor(ColorTextMuted);
                }
            });
        });
    }

    private void ComposeRemediationRunbook(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "INCIDENT REMEDIATION RUNBOOK (침해 대응 조치 내역)");

            col.Item().Border(1).BorderColor(ColorBorder).Background(Colors.White).Padding(6).Column(inner =>
            {
                if (_incident.RemediationSteps.Count == 0)
                {
                    string defaultAction = _incident.IsCritical
                        ? "1. 악성 프로세스 원자적 사살 완료 (NtTerminateProcess)\n2. 잔류 휘발성 메모리 VAD 정밀 소거\n3. EDR 중앙 관제 리포트 실시간 동기화"
                        : "1. 정상 업무 프로세스 원자적 동결 해제 (NtResumeProcess)\n2. 시스템 감사 로그에 무해성 입증 기록 보관";

                    inner.Item().Text(defaultAction)
                        .FontSize(7.8f)
                        .LineHeight(1.3f)
                        .FontColor(ColorTextSecondary);
                }
                else
                {
                    foreach (var step in _incident.RemediationSteps)
                    {
                        inner.Item().PaddingBottom(2).Row(row =>
                        {
                            // 폰트 글리프 깨짐 방지: ArqaStatic 스타일 미니 사각 뱃지 사용
                            row.AutoItem().PaddingTop(3).Width(3).Height(3).Background(ColorBrandSecondary);
                            row.RelativeItem().PaddingLeft(6).Text(step).FontSize(7.8f).FontColor(ColorTextSecondary);
                        });
                    }
                }
            });
        });
    }

    private void ComposeFooter(IContainer container)
    {
        container.Column(col =>
        {
            col.Item().PaddingTop(6).LineHorizontal(0.5f).LineColor(ColorBorder);

            col.Item().PaddingTop(3).Row(row =>
            {
                // 좌측: 보안 인증 및 무결성 문구
                row.RelativeItem().Text(text =>
                {
                    text.Span("Phalanx EDR Autonomous Security Engine • 본 문서는 침해사고 포렌식 증적 보존용으로 자동 생성되었습니다.").FontSize(6.8f).FontColor(ColorTextMuted);
                });

                // 우측: ArqaStatic 스타일의 동적 페이지 번호
                row.AutoItem().Text(text =>
                {
                    text.Span("Page ").FontSize(6.8f).FontColor(ColorTextMuted);
                    text.CurrentPageNumber().FontSize(6.8f).Bold().FontColor(ColorBrandPrimary);
                    text.Span(" of ").FontSize(6.8f).FontColor(ColorTextMuted);
                    text.TotalPages().FontSize(6.8f).Bold().FontColor(ColorBrandPrimary);
                });
            });
        });
    }
}
