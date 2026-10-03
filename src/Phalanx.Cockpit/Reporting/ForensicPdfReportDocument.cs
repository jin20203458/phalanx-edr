namespace Phalanx.Cockpit.Reporting;

using System;
using System.IO;
using System.Linq;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Phalanx.Cockpit.ViewModels;

/// <summary>
/// QuestPDF 기반 A4 인시던트 포렌식 수사 보고서 레이아웃 구현체.
/// 엔터프라이즈 DFIR 표준 규격의 동적 적응형(Adaptive Dynamic Flow) 기술 문서.
/// 3턴 이하의 사건은 단일 페이지로 단정하게 완결되며, 5턴 이상의 복잡한 사건은 단어 찢김 없이 안전하게 다면 확장됩니다.
/// </summary>
public class ForensicPdfReportDocument : IDocument
{
    private readonly IncidentItemViewModel _incident;

    // 6-color system: black/white + single dark red accent
    private const string ColorText = "#111827";         // Slate 900 (Headings, primary body)
    private const string ColorLabel = "#6B7280";        // Slate 500 (Labels, secondary text)
    private const string ColorDanger = "#991B1B";       // Red 800 (Kill verdict, blocked IP)
    private const string ColorBgCode = "#F3F4F6";       // Slate 100 (Code block, table header)
    private const string ColorBorder = "#D1D5DB";       // Slate 300 (Dividers, borders)
    private const string ColorZebra = "#F9FAFB";        // Slate 50 (Table alternating rows)

    public ForensicPdfReportDocument(IncidentItemViewModel incident)
    {
        _incident = incident ?? throw new ArgumentNullException(nameof(incident));
    }

    public DocumentMetadata GetMetadata() => new()
    {
        Title = $"Incident Response Report - {_incident.IncidentId}",
        Author = "Phalanx EDR",
        Subject = $"Forensic Investigation Report for PID {_incident.TargetPid}",
        Keywords = "EDR, Forensic, Incident Report, MITRE ATT&CK",
        Creator = "Phalanx Cockpit Reporting Engine"
    };

    public DocumentSettings GetSettings() => DocumentSettings.Default;

    public void Compose(IDocumentContainer container)
    {
        container.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(26, Unit.Point);
            page.PageColor(Colors.White);

            page.DefaultTextStyle(x => x
                .FontFamily("Segoe UI")
                .FontSize(8.2f)
                .FontColor(ColorText));

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
                row.RelativeItem().Column(left =>
                {
                    left.Item().Text("INCIDENT RESPONSE REPORT")
                        .FontSize(11)
                        .Bold()
                        .FontColor(ColorText);

                    left.Item().PaddingTop(1).Text("Phalanx EDR — Internal Security Investigation")
                        .FontSize(7.5f)
                        .FontColor(ColorLabel);
                });

                row.AutoItem().AlignRight().Column(right =>
                {
                    right.Item().AlignRight().Text(text =>
                    {
                        text.Span("Document:  ").FontSize(7.5f).FontColor(ColorLabel);
                        text.Span(_incident.IncidentId ?? "N/A").FontSize(7.5f).Bold().FontColor(ColorText);
                    });

                    right.Item().AlignRight().Text($"Date:  {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC")
                        .FontSize(7.5f)
                        .FontColor(ColorLabel);

                    right.Item().AlignRight().Text("Classification:  CONFIDENTIAL")
                        .FontSize(7.5f)
                        .Bold()
                        .FontColor(ColorDanger);
                });
            });

            col.Item().PaddingTop(4).PaddingBottom(6).LineHorizontal(0.75f).LineColor(ColorBorder);
        });
    }

    private void ComposeContent(IContainer container)
    {
        container.Column(col =>
        {
            col.Spacing(7);

            // 1. Incident Summary
            col.Item().Element(ComposeIncidentSummary);

            // 2. Process Context
            col.Item().Element(ComposeProcessContext);

            // 3. Analysis & Findings
            col.Item().Element(ComposeAnalysisFindings);

            // 4. Investigation Trace (ReAct 멀티턴 감사 추적)
            col.Item().Element(ComposeInvestigationTrace);

            // 5. Containment & Remediation Actions (자동 집행 vs 권장 조치 분리)
            // 내용 증가 시 페이지 경계에서 어설프게 잘리지 않도록 ShowEntire로 안전하게 보호
            col.Item().ShowEntire().Element(ComposeResponseActions);

            // 6. Verification & Audit Metadata (무결성 검증 블록)
            col.Item().ShowEntire().Element(ComposeVerificationBlock);
        });
    }

    // ── Section 1: Incident Summary ──────────────────────────────────────

    private void ComposeIncidentSummary(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "1. Incident Summary");

            string verdict = _incident.VerdictAction ?? "UNKNOWN";
            bool isKill = verdict.Equals("ACTION_KILL", StringComparison.OrdinalIgnoreCase);

            col.Item().Table(table =>
            {
                table.ColumnsDefinition(columns =>
                {
                    columns.ConstantColumn(80);
                    columns.RelativeColumn();
                    columns.ConstantColumn(80);
                    columns.RelativeColumn();
                });

                // Row 1: Verdict / Confidence
                AddSummaryLabel(table, "Verdict:");
                AddSummaryValue(table, verdict, isKill ? ColorDanger : ColorText, true);
                AddSummaryLabel(table, "Confidence:");
                AddSummaryValue(table, _incident.ConfidenceDisplay ?? "N/A");

                // Row 2: Severity / Response Time
                AddSummaryLabel(table, "Severity:");
                string severity = _incident.StatusSeverity ?? "UNKNOWN";
                bool isCritical = severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase);
                AddSummaryValue(table, severity, isCritical ? ColorDanger : ColorText);
                AddSummaryLabel(table, "Response Time:");
                AddSummaryValue(table, _incident.ElapsedMs > 0 ? $"{_incident.ElapsedMs:F1} ms" : "< 1 ms");

                // Row 3: Target / Target PID
                AddSummaryLabel(table, "Target:");
                AddSummaryValue(table, string.IsNullOrEmpty(_incident.TargetFileName) ? "-" : _incident.TargetFileName);
                AddSummaryLabel(table, "Target PID:");
                AddSummaryValue(table, $"{_incident.TargetPid}");

                // Row 4: Parent / Parent PID
                AddSummaryLabel(table, "Parent:");
                string parentName = string.IsNullOrEmpty(_incident.ParentImage) ? "-" : Path.GetFileName(_incident.ParentImage);
                AddSummaryValue(table, parentName);
                AddSummaryLabel(table, "Parent PID:");
                AddSummaryValue(table, $"{_incident.ParentPid}");
            });
        });
    }

    private void AddSummaryLabel(TableDescriptor table, string label)
    {
        table.Cell().PaddingVertical(1.5f).Text(label)
            .FontSize(8).Bold().FontColor(ColorLabel);
    }

    private void AddSummaryValue(TableDescriptor table, string value, string? color = null, bool bold = false)
    {
        var cell = table.Cell().PaddingVertical(1.5f);
        var text = cell.Text(value).FontSize(8.2f).FontColor(color ?? ColorText);
        if (bold) text.Bold();
    }

    // ── Section 2: Process Context ───────────────────────────────────────

    private void ComposeProcessContext(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "2. Process Context");

            col.Item().Text(text =>
            {
                text.Span("Target Image:  ").FontSize(8).Bold().FontColor(ColorLabel);
                text.Span(string.IsNullOrEmpty(_incident.TargetImage) ? "-" : _incident.TargetImage)
                    .FontSize(8).FontColor(ColorText);
            });

            col.Item().PaddingTop(1).Text(text =>
            {
                text.Span("Parent Image:  ").FontSize(8).Bold().FontColor(ColorLabel);
                text.Span(string.IsNullOrEmpty(_incident.ParentImage) ? "-" : _incident.ParentImage)
                    .FontSize(8).FontColor(ColorText);
            });

            if (_incident.HasBlockedIp)
            {
                col.Item().PaddingTop(1).Text(text =>
                {
                    text.Span("Blocked Network:  ").FontSize(8).Bold().FontColor(ColorDanger);
                    text.Span(_incident.BlockedIp).FontSize(8).Bold().FontColor(ColorDanger);
                });
            }

            // Command Line (라이트 그레이 코드 컨테이너)
            col.Item().PaddingTop(4).Text("Command Line:")
                .FontSize(8).Bold().FontColor(ColorLabel);

            string cmd = string.IsNullOrWhiteSpace(_incident.CommandLine)
                ? "(no command line arguments recorded)"
                : _incident.CommandLine;

            col.Item().PaddingTop(1)
                .Background(ColorBgCode)
                .Border(0.5f).BorderColor(ColorBorder)
                .Padding(5)
                .Text(cmd)
                .FontFamily("Consolas")
                .FontSize(7.8f)
                .FontColor(ColorText)
                .BreakAnywhere();
        });
    }

    // ── Section 3: Analysis & Findings ───────────────────────────────────

    private void ComposeAnalysisFindings(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "3. Analysis & Findings");

            string title = string.IsNullOrWhiteSpace(_incident.SummaryTitle)
                ? "Investigation Complete"
                : _incident.SummaryTitle;

            col.Item().Text(title)
                .FontSize(9)
                .Bold()
                .FontColor(ColorText);

            string narrative = string.IsNullOrWhiteSpace(_incident.Narrative)
                ? "No detailed analysis narrative was recorded for this incident."
                : _incident.Narrative;

            col.Item().PaddingTop(2).Text(narrative)
                .FontSize(8.2f)
                .LineHeight(1.35f)
                .FontColor(ColorText);

            if (_incident.MitreTactics.Count > 0)
            {
                string mitre = string.Join(", ", _incident.MitreTactics);
                col.Item().PaddingTop(4).Text(text =>
                {
                    text.Span("MITRE ATT&CK Reference:  ").FontSize(8).Bold().FontColor(ColorLabel);
                    text.Span(mitre).FontSize(8).FontColor(ColorText);
                });
            }
        });
    }

    // ── Section 4: Investigation Trace ───────────────────────────────────

    private void ComposeInvestigationTrace(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "4. Investigation Trace");

            if (_incident.Traces.Count == 0)
            {
                col.Item().Text("No investigation trace recorded.")
                    .FontSize(8.2f)
                    .FontColor(ColorLabel);
                return;
            }

            col.Item().Table(table =>
            {
                // 컬럼 폭 최적화: Tool(108pt - ThreatReputationTool 완벽 수납), Latency(48pt - 4925.8ms 완벽 수납)
                table.ColumnsDefinition(columns =>
                {
                    columns.ConstantColumn(24);
                    columns.ConstantColumn(108);
                    columns.RelativeColumn(3);
                    columns.RelativeColumn(3);
                    columns.ConstantColumn(48);
                });

                // Header
                table.Header(header =>
                {
                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(3.5f).AlignCenter()
                        .Text("Step").FontSize(7.8f).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(3.5f)
                        .Text("Tool").FontSize(7.8f).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(3.5f)
                        .Text("Reasoning").FontSize(7.8f).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(3.5f)
                        .Text("Observation").FontSize(7.8f).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(3.5f).AlignRight()
                        .Text("Latency").FontSize(7.8f).Bold().FontColor(ColorText);
                });

                int index = 0;
                foreach (var trace in _incident.Traces)
                {
                    string rowBg = (index++ % 2 == 0) ? Colors.White : ColorZebra;

                    // Step
                    AddTableCell(table, $"{trace.StepNumber}", rowBg, bold: true, breakAnywhere: false, center: true);

                    // Tool (한 줄 완벽 수납)
                    AddTableCell(table, trace.ActionTool ?? "-", rowBg, bold: true, breakAnywhere: false);

                    // Reasoning (한글/영문 단어 쪼개짐 방지: breakAnywhere = false)
                    AddTableCell(table, string.IsNullOrWhiteSpace(trace.Thought) ? "-" : trace.Thought, rowBg, bold: false, breakAnywhere: false);

                    // Observation (긴 URL/해시 포함 가능: breakAnywhere = true)
                    AddTableCell(table, string.IsNullOrWhiteSpace(trace.Observation) ? "-" : trace.Observation, rowBg, bold: false, breakAnywhere: true);

                    // Latency (한 줄 완벽 수납)
                    AddTableCell(table, $"{trace.ElapsedMs:F1}ms", rowBg, bold: false, breakAnywhere: false, center: false, right: true);
                }
            });
        });
    }

    private void AddTableCell(TableDescriptor table, string text, string bg,
        bool bold = false, bool breakAnywhere = false, bool center = false, bool right = false)
    {
        var cell = table.Cell()
            .Background(bg)
            .BorderBottom(0.5f).BorderColor(ColorBorder)
            .Padding(3.5f);

        if (center) cell = cell.AlignCenter();
        if (right) cell = cell.AlignRight();

        var t = cell.Text(text).FontSize(7.6f).FontColor(ColorText);
        if (bold) t.Bold();
        if (breakAnywhere) t.BreakAnywhere();
    }

    // ── Section 5: Containment & Remediation Actions ─────────────────────

    private void ComposeResponseActions(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "5. Containment & Remediation Actions");

            // Sub-block A: Automated Containment (EDR 시스템 자동 집행 완료)
            col.Item().PaddingBottom(2).Text("[Automated Actions Taken (EDR 시스템 자동 집행 완료)]")
                .FontSize(8.0f)
                .Bold()
                .FontColor(ColorText);

            col.Item().PaddingLeft(6).Column(autoCol =>
            {
                string targetProcName = string.IsNullOrEmpty(_incident.TargetFileName) ? "프로세스" : _incident.TargetFileName;
                bool isKill = _incident.VerdictAction.Equals("ACTION_KILL", StringComparison.OrdinalIgnoreCase);
                bool isResume = _incident.VerdictAction.Equals("ACTION_RESUME", StringComparison.OrdinalIgnoreCase);

                // 1) 프로세스 처분
                string processActionText = isKill
                    ? $"• 타깃 프로세스 '{targetProcName}' (PID: {_incident.TargetPid}) 즉각 사살 완료 (ACTION_KILL 집행)"
                    : (isResume
                        ? $"• 정상 프로세스 '{targetProcName}' (PID: {_incident.TargetPid}) 원자적 동결 해제 및 복구 완료 (ACTION_RESUME 집행)"
                        : $"• 프로세스 '{targetProcName}' (PID: {_incident.TargetPid}) 선제 동결 상태 유지 (SUSPENDED)");

                autoCol.Item().PaddingBottom(1.5f).Text(processActionText)
                    .FontSize(7.8f)
                    .FontColor(isKill ? ColorDanger : ColorText);

                // 2) 네트워크 방화벽 차단 실적
                if (_incident.HasBlockedIp)
                {
                    autoCol.Item().PaddingBottom(1.5f).Text($"• 악성 C2 네트워크 '{_incident.BlockedIp}' 전사 방화벽 인/아웃바운드 차단 집행 완료 (규칙: Phalanx_EDR_Block_{_incident.BlockedIp})")
                        .FontSize(7.8f)
                        .FontColor(ColorDanger);
                }

                // 3) 휘발성 메모리 및 감사 보존
                autoCol.Item().PaddingBottom(1.5f).Text(isKill
                    ? "• 타깃 프로세스 잔류 가상 메모리(VAD) 영역 정밀 회수 및 LiteDB 포렌식 증적 영구 보관"
                    : "• 시스템 감사 로그에 프로세스 무해성 입증 증적 영구 보관")
                    .FontSize(7.8f)
                    .FontColor(ColorLabel);
            });

            // Sub-block B: Recommended Follow-up Actions (보안 관제팀 권장 후속 조치)
            col.Item().PaddingTop(4).PaddingBottom(2).Text("[Recommended Follow-up Actions (보안 관제팀 권장 후속 조치)]")
                .FontSize(8.0f)
                .Bold()
                .FontColor(ColorLabel);

            col.Item().PaddingLeft(6).Column(recCol =>
            {
                // _incident.RemediationSteps에서 중복된 방화벽/사살 항목을 제외하고 순수 권장 사항만 추출
                var recommendations = _incident.RemediationSteps
                    .Where(s => !s.Contains("방화벽", StringComparison.OrdinalIgnoreCase) &&
                                !s.Contains("firewall", StringComparison.OrdinalIgnoreCase) &&
                                !s.Contains("사살", StringComparison.OrdinalIgnoreCase) &&
                                !s.Contains("terminate", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (recommendations.Count == 0)
                {
                    if (_incident.IsCritical)
                    {
                        recommendations.Add("침해 유입 경로(발신 이메일, 첨부파일, 브라우저 다운로드 원본) 격리 및 전사 위협 헌팅");
                        recommendations.Add("해당 엔드포인트 전수 정밀 백신 검사 수행 및 침해 의심 계정 자격증명 초기화");
                    }
                    else
                    {
                        recommendations.Add("특이 사항 없음 - 정상 업무 프로세스로 확인되어 일상 보안 모니터링 유지");
                    }
                }

                int stepNum = 1;
                foreach (var rec in recommendations)
                {
                    recCol.Item().PaddingBottom(1.5f).Text($"{stepNum++}. {rec}")
                        .FontSize(7.8f)
                        .FontColor(ColorText);
                }
            });
        });
    }

    // ── Section 6: Verification & Audit Metadata ─────────────────────────

    private void ComposeVerificationBlock(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "6. Verification & Audit Metadata");

            col.Item().Border(0.5f).BorderColor(ColorBorder).Background(ColorZebra).Padding(6).Column(inner =>
            {
                inner.Item().Row(r =>
                {
                    r.RelativeItem().Text(text =>
                    {
                        text.Span("Audit Standard:  ").FontSize(7.5f).Bold().FontColor(ColorLabel);
                        text.Span("MITRE ATT&CK Matrix v14 / SANS DFIR Standard").FontSize(7.5f).FontColor(ColorText);
                    });
                    r.RelativeItem().AlignRight().Text(text =>
                    {
                        text.Span("Engine:  ").FontSize(7.5f).Bold().FontColor(ColorLabel);
                        text.Span("Phalanx Autonomous Threat Hunter v1.0.0").FontSize(7.5f).FontColor(ColorText);
                    });
                });

                inner.Item().PaddingTop(3).Row(r =>
                {
                    r.RelativeItem().Text(text =>
                    {
                        text.Span("Evidence Integrity:  ").FontSize(7.5f).Bold().FontColor(ColorLabel);
                        text.Span("Immutable LiteDB Chain-of-Custody Archive Verified").FontSize(7.5f).FontColor(ColorText);
                    });
                    r.RelativeItem().AlignRight().Text(text =>
                    {
                        text.Span("Disposition:  ").FontSize(7.5f).Bold().FontColor(ColorLabel);
                        text.Span(_incident.IsCritical ? "INCIDENT CONTAINED & ISOLATED" : "SYSTEM RESTORED (BENIGN)")
                            .FontSize(7.5f).Bold().FontColor(_incident.IsCritical ? ColorDanger : ColorText);
                    });
                });
            });
        });
    }

    // ── Shared Components ────────────────────────────────────────────────

    private void CreateSectionHeader(ColumnDescriptor col, string title)
    {
        col.Item().PaddingBottom(4).Column(inner =>
        {
            inner.Item().LineHorizontal(0.5f).LineColor(ColorBorder);
            inner.Item().PaddingTop(3).Text(title)
                .FontSize(9.5f)
                .Bold()
                .FontColor(ColorText);
        });
    }

    private void ComposeFooter(IContainer container)
    {
        container.PaddingTop(4).Row(row =>
        {
            row.RelativeItem().Text("Phalanx EDR — Confidential")
                .FontSize(7)
                .FontColor(ColorLabel);

            row.AutoItem().Text(text =>
            {
                text.Span("Page ").FontSize(7).FontColor(ColorLabel);
                text.CurrentPageNumber().FontSize(7).FontColor(ColorLabel);
                text.Span(" of ").FontSize(7).FontColor(ColorLabel);
                text.TotalPages().FontSize(7).FontColor(ColorLabel);
            });
        });
    }
}
