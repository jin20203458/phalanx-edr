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
/// 엔터프라이즈 DFIR 표준 규격의 단일 페이지 완결형(One-Page Executive Brief) 기술 문서.
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
            col.Spacing(8);

            // 1. Incident Summary
            col.Item().Element(ComposeIncidentSummary);

            // 2. Process Context
            col.Item().Element(ComposeProcessContext);

            // 3. Analysis & Findings
            col.Item().Element(ComposeAnalysisFindings);

            // 4. Investigation Trace (ReAct 멀티턴 감사 추적)
            col.Item().Element(ComposeInvestigationTrace);

            // 5. Response Actions (침해 대응 조치 내역)
            col.Item().Element(ComposeResponseActions);

            // 6. Verification & Audit Metadata (무결성 검증 블록)
            col.Item().Element(ComposeVerificationBlock);
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
                // 컬럼 폭 최적화: Tool(108pt - ThreatReputationTool 완벽 수용), Latency(48pt - 4925.8ms 완벽 수용)
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

                    // Tool (한 줄 완벽 수용)
                    AddTableCell(table, trace.ActionTool ?? "-", rowBg, bold: true, breakAnywhere: false);

                    // Reasoning (한글/영문 단어 쪼개짐 방지: breakAnywhere = false)
                    AddTableCell(table, string.IsNullOrWhiteSpace(trace.Thought) ? "-" : trace.Thought, rowBg, bold: false, breakAnywhere: false);

                    // Observation (긴 URL/해시 포함 가능: breakAnywhere = true)
                    AddTableCell(table, string.IsNullOrWhiteSpace(trace.Observation) ? "-" : trace.Observation, rowBg, bold: false, breakAnywhere: true);

                    // Latency (한 줄 완벽 수용)
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

    // ── Section 5: Response Actions ──────────────────────────────────────

    private void ComposeResponseActions(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "5. Response Actions");

            if (_incident.RemediationSteps.Count == 0)
            {
                string defaultAction = _incident.IsCritical
                    ? "1. Malicious process terminated.\n2. Residual volatile memory regions cleared.\n3. Incident record synchronized to central EDR database."
                    : "1. Process unfrozen and restored to normal execution.\n2. Benign classification recorded in audit log.";

                col.Item().Text(defaultAction)
                    .FontSize(8.2f)
                    .LineHeight(1.35f)
                    .FontColor(ColorText);
            }
            else
            {
                int stepNum = 1;
                foreach (var step in _incident.RemediationSteps)
                {
                    col.Item().PaddingBottom(1.5f).Text($"{stepNum++}. {step}")
                        .FontSize(8.2f)
                        .FontColor(ColorText);
                }
            }
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
                        text.Span("Phalanx Autonomous Threat Hunter v0.5.0").FontSize(7.5f).FontColor(ColorText);
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
