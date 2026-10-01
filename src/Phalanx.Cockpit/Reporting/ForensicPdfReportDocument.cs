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
/// </summary>
public class ForensicPdfReportDocument : IDocument
{
    private readonly IncidentItemViewModel _incident;

    // Phalanx Cockpit 브랜딩 컬러 팔레트
    private const string ColorBrandPrimary = "#1E3A8A"; // Deep Navy
    private const string ColorBrandSecondary = "#2563EB"; // Royal Blue
    private const string ColorActionKill = "#DC2626"; // Crimson Red
    private const string ColorActionResume = "#16A34A"; // Emerald Green
    private const string ColorActionSuspended = "#D97706"; // Amber
    private const string ColorTextPrimary = "#0F172A"; // Slate 900
    private const string ColorTextMuted = "#64748B"; // Slate 500
    private const string ColorCardBackground = "#F8FAFC"; // Slate 50
    private const string ColorBorder = "#E2E8F0"; // Slate 200
    private const string ColorCodeBg = "#0F172A"; // Dark Slate
    private const string ColorCodeText = "#38BDF8"; // Sky Blue

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
            page.Margin(24, Unit.Point);
            page.PageColor(Colors.White);

            // 기본 폰트: Segoe UI (QuestPDF 엔진의 내장 자동 CJK 폰트 폴백 메커니즘 활용)
            page.DefaultTextStyle(x => x
                .FontFamily("Segoe UI")
                .FontSize(9)
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
                // 좌측: 시스템 및 보고서 타이틀
                row.RelativeItem().Column(titleCol =>
                {
                    titleCol.Item().Text("PHALANX EDR — AUTONOMOUS INCIDENT REPORT")
                        .FontSize(15)
                        .ExtraBold()
                        .FontColor(ColorBrandPrimary);

                    titleCol.Item().PaddingTop(2).Text("Endpoint Detection & Response • Autonomous Threat Hunting & ReAct Forensics")
                        .FontSize(8)
                        .SemiBold()
                        .FontColor(ColorTextMuted);
                });

                // 우측: 기밀 표기 및 발급 일시
                row.AutoItem().Column(metaCol =>
                {
                    metaCol.Item().AlignRight().Text("CONFIDENTIAL & PROPRIETARY")
                        .FontSize(8)
                        .Bold()
                        .FontColor(ColorActionKill);

                    metaCol.Item().PaddingTop(2).AlignRight().Text($"발행: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC")
                        .FontSize(7.5f)
                        .FontColor(ColorTextMuted);

                    metaCol.Item().AlignRight().Text($"문서 번호: {_incident.IncidentId}")
                        .FontSize(7.5f)
                        .FontColor(ColorTextMuted);
                });
            });

            col.Item().PaddingTop(6).PaddingBottom(8).LineHorizontal(1.5f).LineColor(ColorBrandPrimary);
        });
    }

    private void ComposeContent(IContainer container)
    {
        container.Column(col =>
        {
            // 1. 섹션 1: 인시던트 개요 및 최종 판결 배너
            col.Item().Element(ComposeVerdictBanner);

            // 2. 섹션 2: 타깃 프로세스 메타데이터 및 명령줄
            col.Item().PaddingTop(10).Element(ComposeProcessLineage);

            // 3. 섹션 3: AI 자율 수사관 심층 서사 및 MITRE ATT&CK
            col.Item().PaddingTop(10).Element(ComposeNarrativeAndMitre);

            // 4. 섹션 4: ReAct 턴별 수사 추적표 (Audit Trail)
            col.Item().PaddingTop(10).Element(ComposeReActAuditTrail);

            // 5. 섹션 5: 침해 대응 런북 및 보안 조치
            col.Item().PaddingTop(10).Element(ComposeRemediationRunbook);
        });
    }

    private void ComposeVerdictBanner(IContainer container)
    {
        string verdict = _incident.VerdictAction;
        bool isKill = verdict.Equals("ACTION_KILL", StringComparison.OrdinalIgnoreCase);
        bool isResume = verdict.Equals("ACTION_RESUME", StringComparison.OrdinalIgnoreCase);

        string badgeBg = isKill ? ColorActionKill : (isResume ? ColorActionResume : ColorActionSuspended);
        string verdictText = isKill ? "ACTION_KILL (사살 / 영구 격리)" : (isResume ? "ACTION_RESUME (원자적 복구)" : "SUSPENDED (선제 동결 유지)");

        container.Border(1).BorderColor(ColorBorder).Background(ColorCardBackground).Padding(10).Column(col =>
        {
            col.Item().Row(row =>
            {
                // 좌측: 사건 기본 식별
                row.RelativeItem().Column(subCol =>
                {
                    subCol.Item().Text(text =>
                    {
                        text.Span("사건 식별자: ").Bold().FontColor(ColorTextMuted);
                        text.Span(_incident.IncidentId).Bold().FontColor(ColorBrandPrimary);
                    });

                    subCol.Item().PaddingTop(2).Text(text =>
                    {
                        text.Span("발생 시각: ").FontColor(ColorTextMuted);
                        text.Span($"{_incident.FormattedTime} ({_incident.RelativeTime})").FontColor(ColorTextPrimary);
                    });

                    subCol.Item().PaddingTop(2).Text(text =>
                    {
                        text.Span("타깃 프로세스: ").FontColor(ColorTextMuted);
                        text.Span($"{_incident.TargetFileName} (PID: {_incident.TargetPid})").Bold().FontColor(ColorTextPrimary);
                    });
                });

                // 우측: 대형 처분 뱃지 및 메트릭
                row.AutoItem().Column(badgeCol =>
                {
                    badgeCol.Item().AlignRight().Background(badgeBg).PaddingHorizontal(12).PaddingVertical(5).Text(verdictText)
                        .FontSize(11)
                        .ExtraBold()
                        .FontColor(Colors.White);

                    badgeCol.Item().PaddingTop(4).AlignRight().Text(text =>
                    {
                        text.Span("AI 확신도: ").FontColor(ColorTextMuted);
                        text.Span(_incident.ConfidenceDisplay).Bold().FontColor(badgeBg);
                        text.Span("  •  수사 소요: ").FontColor(ColorTextMuted);
                        text.Span(_incident.FormattedLatency).FontColor(ColorTextPrimary);
                    });
                });
            });
        });
    }

    private void ComposeProcessLineage(IContainer container)
    {
        container.Column(col =>
        {
            col.Item().Text("1. 프로세스 계통 및 실행 무결성 (Process Execution Lineage)")
                .FontSize(10)
                .Bold()
                .FontColor(ColorBrandPrimary);

            col.Item().PaddingTop(4).Border(1).BorderColor(ColorBorder).Background(Colors.White).Padding(8).Column(innerCol =>
            {
                innerCol.Item().Row(row =>
                {
                    row.RelativeItem().Text(text =>
                    {
                        text.Span("타깃 이미지: ").Bold().FontColor(ColorTextMuted);
                        text.Span(string.IsNullOrEmpty(_incident.TargetImage) ? "-" : _incident.TargetImage).FontColor(ColorTextPrimary);
                    });

                    row.AutoItem().Text(text =>
                    {
                        text.Span("PID: ").Bold().FontColor(ColorTextMuted);
                        text.Span($"{_incident.TargetPid}").FontColor(ColorTextPrimary);
                    });
                });

                innerCol.Item().PaddingTop(3).Row(row =>
                {
                    row.RelativeItem().Text(text =>
                    {
                        text.Span("부모 프로세스: ").Bold().FontColor(ColorTextMuted);
                        text.Span(string.IsNullOrEmpty(_incident.ParentImage) ? "-" : _incident.ParentImage).FontColor(ColorTextPrimary);
                    });

                    row.AutoItem().Text(text =>
                    {
                        text.Span("PPID: ").Bold().FontColor(ColorTextMuted);
                        text.Span($"{_incident.ParentPid}").FontColor(ColorTextPrimary);
                    });
                });

                if (_incident.HasBlockedIp)
                {
                    innerCol.Item().PaddingTop(3).Text(text =>
                    {
                        text.Span("차단된 C2 네트워크: ").Bold().FontColor(ColorActionKill);
                        text.Span(_incident.BlockedIp).Bold().FontColor(ColorActionKill);
                        text.Span(" (Windows Firewall Outbound Block Rule Active)").FontSize(8).FontColor(ColorTextMuted);
                    });
                }

                // 전체 명령줄 (Command Line): 다크 모노스페이스 박스
                innerCol.Item().PaddingTop(6).Text("실행 명령줄 (Command Line)").FontSize(8).Bold().FontColor(ColorTextMuted);

                string cmd = string.IsNullOrWhiteSpace(_incident.CommandLine) ? "(명령줄 인자 없음)" : _incident.CommandLine;
                innerCol.Item().PaddingTop(2).Background(ColorCodeBg).Padding(6).Text(cmd)
                    .FontFamily("Consolas")
                    .FontSize(7.5f)
                    .FontColor(ColorCodeText)
                    .BreakAnywhere();
            });
        });
    }

    private void ComposeNarrativeAndMitre(IContainer container)
    {
        container.Column(col =>
        {
            col.Item().Text("2. AI 자율 수사관 심층 서사 & MITRE ATT&CK (Threat Narrative)")
                .FontSize(10)
                .Bold()
                .FontColor(ColorBrandPrimary);

            col.Item().PaddingTop(4).Border(1).BorderColor(ColorBorder).Background(ColorCardBackground).Padding(8).Column(innerCol =>
            {
                // 사건 요약 제목
                string title = string.IsNullOrWhiteSpace(_incident.SummaryTitle) ? "침해사고 수사 완료" : _incident.SummaryTitle;
                innerCol.Item().Text(title)
                    .FontSize(9.5f)
                    .Bold()
                    .FontColor(ColorTextPrimary);

                // AI 포렌식 서사 (Narrative)
                string narrative = string.IsNullOrWhiteSpace(_incident.Narrative) ? "상세 수사 서사가 기록되지 않았습니다." : _incident.Narrative;
                innerCol.Item().PaddingTop(4).Text(narrative)
                    .FontSize(8.5f)
                    .LineHeight(1.3f)
                    .FontColor(ColorTextPrimary);

                // MITRE ATT&CK 전술 뱃지
                if (_incident.MitreTactics.Count > 0)
                {
                    innerCol.Item().PaddingTop(6).Row(row =>
                    {
                        row.AutoItem().Text("MITRE ATT&CK 전술: ")
                            .FontSize(8)
                            .Bold()
                            .FontColor(ColorTextMuted);

                        row.RelativeItem().Row(badgesRow =>
                        {
                            foreach (var tactic in _incident.MitreTactics)
                            {
                                badgesRow.AutoItem().PaddingRight(4).Background("#EEF2F6").PaddingHorizontal(5).PaddingVertical(1).Text(tactic)
                                    .FontSize(7.5f)
                                    .SemiBold()
                                    .FontColor(ColorBrandSecondary);
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
            col.Item().Text("3. ReAct 턴별 수사 추적 및 도구 실측 기록 (Forensic Audit Trail)")
                .FontSize(10)
                .Bold()
                .FontColor(ColorBrandPrimary);

            if (_incident.Traces.Count == 0)
            {
                col.Item().PaddingTop(4).Border(1).BorderColor(ColorBorder).Padding(6).Text("기록된 ReAct 수사 흔적이 없습니다. (선제 반사 차단 또는 오프라인 수사)")
                    .FontSize(8)
                    .FontColor(ColorTextMuted);
                return;
            }

            col.Item().PaddingTop(4).Table(table =>
            {
                // 컬럼 정의: Turn(35pt), Tool(100pt), Thought(180pt), Observation(Rest), Latency(45pt)
                table.ColumnsDefinition(columns =>
                {
                    columns.ConstantColumn(35);
                    columns.ConstantColumn(110);
                    columns.RelativeColumn(3);
                    columns.RelativeColumn(3);
                    columns.ConstantColumn(45);
                });

                // 헤더 행
                table.Header(header =>
                {
                    header.Cell().Background(ColorBrandPrimary).Padding(4).AlignCenter().Text("Turn").FontSize(8).Bold().FontColor(Colors.White);
                    header.Cell().Background(ColorBrandPrimary).Padding(4).Text("Action Tool").FontSize(8).Bold().FontColor(Colors.White);
                    header.Cell().Background(ColorBrandPrimary).Padding(4).Text("Agent Thought (추론)").FontSize(8).Bold().FontColor(Colors.White);
                    header.Cell().Background(ColorBrandPrimary).Padding(4).Text("Tool Observation (실측 증거)").FontSize(8).Bold().FontColor(Colors.White);
                    header.Cell().Background(ColorBrandPrimary).Padding(4).AlignRight().Text("Latency").FontSize(8).Bold().FontColor(Colors.White);
                });

                // 데이터 행들
                int index = 0;
                foreach (var trace in _incident.Traces)
                {
                    string rowBg = (index++ % 2 == 0) ? Colors.White : ColorCardBackground;

                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(4).AlignCenter()
                        .Text($"#{trace.StepNumber}").FontSize(7.5f).Bold().FontColor(ColorTextMuted);

                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(4)
                        .Text(trace.ActionTool).FontSize(7.5f).Bold().FontColor(ColorBrandSecondary);

                    string thought = string.IsNullOrWhiteSpace(trace.Thought) ? "-" : trace.Thought;
                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(4)
                        .Text(thought).FontSize(7.5f).FontColor(ColorTextPrimary).BreakAnywhere();

                    string observation = string.IsNullOrWhiteSpace(trace.Observation) ? "-" : trace.Observation;
                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(4)
                        .Text(observation).FontSize(7.5f).FontColor(ColorTextPrimary).BreakAnywhere();

                    table.Cell().Background(rowBg).BorderBottom(0.5f).BorderColor(ColorBorder).Padding(4).AlignRight()
                        .Text($"{trace.ElapsedMs:F1}ms").FontSize(7.5f).FontColor(ColorTextMuted);
                }
            });
        });
    }

    private void ComposeRemediationRunbook(IContainer container)
    {
        container.Column(col =>
        {
            col.Item().Text("4. 침해 대응 런북 및 보안 조치 결과 (Remediation Runbook)")
                .FontSize(10)
                .Bold()
                .FontColor(ColorBrandPrimary);

            col.Item().PaddingTop(4).Border(1).BorderColor(ColorBorder).Background(Colors.White).Padding(8).Column(innerCol =>
            {
                if (_incident.RemediationSteps.Count == 0)
                {
                    string defaultAction = _incident.IsCritical
                        ? "1. 악성 프로세스 원자적 사살 완료 (NtTerminateProcess)\n2. 잔류 휘발성 메모리 VAD 정밀 소거\n3. EDR 중앙 관제 리포트 실시간 동기화"
                        : "1. 정상 업무 프로세스 원자적 동결 해제 (NtResumeProcess)\n2. 시스템 감사 로그에 무해성 입증 기록 보관";

                    innerCol.Item().Text(defaultAction)
                        .FontSize(8)
                        .LineHeight(1.3f)
                        .FontColor(ColorTextPrimary);
                }
                else
                {
                    foreach (var step in _incident.RemediationSteps)
                    {
                        innerCol.Item().PaddingBottom(2).Row(row =>
                        {
                            row.AutoItem().Text("• ").Bold().FontColor(ColorBrandSecondary);
                            row.RelativeItem().Text(step).FontSize(8).FontColor(ColorTextPrimary);
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
            col.Item().PaddingTop(8).LineHorizontal(0.5f).LineColor(ColorBorder);

            col.Item().PaddingTop(4).Row(row =>
            {
                // 좌측: 보안 인증 및 무결성 문구
                row.RelativeItem().Text(text =>
                {
                    text.Span("Phalanx EDR Autonomous Security Engine • 본 문서는 침해사고 포렌식 증적 보존용으로 자동 생성되었습니다.").FontSize(7).FontColor(ColorTextMuted);
                });

                // 우측: 동적 페이지 번호
                row.AutoItem().Text(text =>
                {
                    text.Span("Page ").FontSize(7).FontColor(ColorTextMuted);
                    text.CurrentPageNumber().FontSize(7).Bold().FontColor(ColorBrandPrimary);
                    text.Span(" of ").FontSize(7).FontColor(ColorTextMuted);
                    text.TotalPages().FontSize(7).Bold().FontColor(ColorBrandPrimary);
                });
            });
        });
    }
}
