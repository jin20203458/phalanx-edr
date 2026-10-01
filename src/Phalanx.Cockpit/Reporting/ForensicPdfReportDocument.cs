namespace Phalanx.Cockpit.Reporting;

using System;
using System.Linq;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Phalanx.Cockpit.ViewModels;

/// <summary>
/// QuestPDF 기반 A4 인시던트 포렌식 수사 보고서 레이아웃 구현체.
/// CrowdStrike/Mandiant/SANS DFIR 실무 보고서 표준에 준하는 간결한 기술 문서 형식.
/// </summary>
public class ForensicPdfReportDocument : IDocument
{
    private readonly IncidentItemViewModel _incident;

    // 6-color system: black/white + single accent
    private const string ColorText = "#111827";         // Body text, headings
    private const string ColorLabel = "#6B7280";        // Labels, secondary text
    private const string ColorDanger = "#991B1B";       // Kill verdict, blocked IP
    private const string ColorBgCode = "#F3F4F6";       // Code block, table header
    private const string ColorBorder = "#D1D5DB";       // Dividers, borders
    private const string ColorZebra = "#F9FAFB";        // Table alternating rows

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
            page.Margin(40, Unit.Point);
            page.PageColor(Colors.White);

            page.DefaultTextStyle(x => x
                .FontFamily("Segoe UI")
                .FontSize(9)
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

                    left.Item().PaddingTop(1).Text("Phalanx EDR — Internal Use Only")
                        .FontSize(8)
                        .FontColor(ColorLabel);
                });

                row.AutoItem().AlignRight().Column(right =>
                {
                    right.Item().AlignRight().Text(text =>
                    {
                        text.Span("Document:  ").FontSize(8).FontColor(ColorLabel);
                        text.Span(_incident.IncidentId ?? "N/A").FontSize(8).FontColor(ColorText);
                    });

                    right.Item().AlignRight().Text($"Date:  {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC")
                        .FontSize(8)
                        .FontColor(ColorLabel);

                    right.Item().AlignRight().Text("Classification:  CONFIDENTIAL")
                        .FontSize(8)
                        .Bold()
                        .FontColor(ColorDanger);
                });
            });

            col.Item().PaddingTop(6).PaddingBottom(8).LineHorizontal(1).LineColor(ColorBorder);
        });
    }

    private void ComposeContent(IContainer container)
    {
        container.Column(col =>
        {
            col.Spacing(14);

            col.Item().Element(ComposeIncidentSummary);
            col.Item().Element(ComposeProcessContext);
            col.Item().Element(ComposeAnalysisFindings);
            col.Item().Element(ComposeInvestigationTrace);
            col.Item().Element(ComposeResponseActions);
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
                string parentName = string.IsNullOrEmpty(_incident.ParentImage) ? "-" : System.IO.Path.GetFileName(_incident.ParentImage);
                AddSummaryValue(table, parentName);
                AddSummaryLabel(table, "Parent PID:");
                AddSummaryValue(table, $"{_incident.ParentPid}");
            });
        });
    }

    private void AddSummaryLabel(TableDescriptor table, string label)
    {
        table.Cell().PaddingVertical(2).Text(label)
            .FontSize(8.5f).Bold().FontColor(ColorLabel);
    }

    private void AddSummaryValue(TableDescriptor table, string value, string? color = null, bool bold = false)
    {
        var cell = table.Cell().PaddingVertical(2);
        var text = cell.Text(value).FontSize(9).FontColor(color ?? ColorText);
        if (bold) text.Bold();
    }

    // ── Section 2: Process Context ───────────────────────────────────────

    private void ComposeProcessContext(IContainer container)
    {
        container.Column(col =>
        {
            CreateSectionHeader(col, "2. Process Context");

            // Target image full path
            col.Item().Text(text =>
            {
                text.Span("Target Image:  ").FontSize(8.5f).Bold().FontColor(ColorLabel);
                text.Span(string.IsNullOrEmpty(_incident.TargetImage) ? "-" : _incident.TargetImage)
                    .FontSize(8.5f).FontColor(ColorText);
            });

            col.Item().PaddingTop(2).Text(text =>
            {
                text.Span("Parent Image:  ").FontSize(8.5f).Bold().FontColor(ColorLabel);
                text.Span(string.IsNullOrEmpty(_incident.ParentImage) ? "-" : _incident.ParentImage)
                    .FontSize(8.5f).FontColor(ColorText);
            });

            // Blocked IP (if present)
            if (_incident.HasBlockedIp)
            {
                col.Item().PaddingTop(2).Text(text =>
                {
                    text.Span("Blocked Network:  ").FontSize(8.5f).Bold().FontColor(ColorDanger);
                    text.Span(_incident.BlockedIp).FontSize(8.5f).FontColor(ColorDanger);
                });
            }

            // Command line in light gray code block
            col.Item().PaddingTop(6).Text("Command Line:")
                .FontSize(8.5f).Bold().FontColor(ColorLabel);

            string cmd = string.IsNullOrWhiteSpace(_incident.CommandLine)
                ? "(no command line arguments recorded)"
                : _incident.CommandLine;

            col.Item().PaddingTop(2)
                .Background(ColorBgCode)
                .Border(0.5f).BorderColor(ColorBorder)
                .Padding(8)
                .Text(cmd)
                .FontFamily("Consolas")
                .FontSize(8.5f)
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

            // Finding title
            string title = string.IsNullOrWhiteSpace(_incident.SummaryTitle)
                ? "Investigation Complete"
                : _incident.SummaryTitle;

            col.Item().Text(title)
                .FontSize(10)
                .Bold()
                .FontColor(ColorText);

            // Analysis narrative
            string narrative = string.IsNullOrWhiteSpace(_incident.Narrative)
                ? "No detailed analysis narrative was recorded for this incident."
                : _incident.Narrative;

            col.Item().PaddingTop(4).Text(narrative)
                .FontSize(9)
                .LineHeight(1.4f)
                .FontColor(ColorText);

            // MITRE ATT&CK references (plain inline text)
            if (_incident.MitreTactics.Count > 0)
            {
                string mitre = string.Join(", ", _incident.MitreTactics);
                col.Item().PaddingTop(6).Text(text =>
                {
                    text.Span("MITRE ATT&CK Reference:  ").FontSize(8.5f).Bold().FontColor(ColorLabel);
                    text.Span(mitre).FontSize(8.5f).FontColor(ColorText);
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
                    .FontSize(9)
                    .FontColor(ColorLabel);
                return;
            }

            col.Item().Table(table =>
            {
                table.ColumnsDefinition(columns =>
                {
                    columns.ConstantColumn(28);
                    columns.ConstantColumn(90);
                    columns.RelativeColumn(3);
                    columns.RelativeColumn(3);
                    columns.ConstantColumn(40);
                });

                // Light header
                table.Header(header =>
                {
                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(4).AlignCenter()
                        .Text("Step").FontSize(8).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(4)
                        .Text("Tool").FontSize(8).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(4)
                        .Text("Reasoning").FontSize(8).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(4)
                        .Text("Observation").FontSize(8).Bold().FontColor(ColorText);

                    header.Cell().Background(ColorBgCode).BorderBottom(1).BorderColor(ColorBorder).Padding(4).AlignRight()
                        .Text("Latency").FontSize(8).Bold().FontColor(ColorText);
                });

                int index = 0;
                foreach (var trace in _incident.Traces)
                {
                    string rowBg = (index++ % 2 == 0) ? Colors.White : ColorZebra;

                    AddTableCell(table, $"{trace.StepNumber}", rowBg, true, false, true);
                    AddTableCell(table, trace.ActionTool ?? "-", rowBg, true);
                    AddTableCell(table, string.IsNullOrWhiteSpace(trace.Thought) ? "-" : trace.Thought, rowBg);
                    AddTableCell(table, string.IsNullOrWhiteSpace(trace.Observation) ? "-" : trace.Observation, rowBg);
                    AddTableCell(table, $"{trace.ElapsedMs:F1}ms", rowBg, false, false, false, true);
                }
            });
        });
    }

    private void AddTableCell(TableDescriptor table, string text, string bg,
        bool bold = false, bool breakAnywhere = true, bool center = false, bool right = false)
    {
        var cell = table.Cell()
            .Background(bg)
            .BorderBottom(0.5f).BorderColor(ColorBorder)
            .Padding(4);

        if (center) cell = cell.AlignCenter();
        if (right) cell = cell.AlignRight();

        var t = cell.Text(text).FontSize(8).FontColor(ColorText);
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
                    .FontSize(9)
                    .LineHeight(1.4f)
                    .FontColor(ColorText);
            }
            else
            {
                int stepNum = 1;
                foreach (var step in _incident.RemediationSteps)
                {
                    col.Item().PaddingBottom(2).Text($"{stepNum++}. {step}")
                        .FontSize(9)
                        .FontColor(ColorText);
                }
            }
        });
    }

    // ── Shared Components ────────────────────────────────────────────────

    private void CreateSectionHeader(ColumnDescriptor col, string title)
    {
        col.Item().PaddingBottom(6).Column(inner =>
        {
            inner.Item().LineHorizontal(0.5f).LineColor(ColorBorder);
            inner.Item().PaddingTop(4).Text(title)
                .FontSize(10.5f)
                .Bold()
                .FontColor(ColorText);
        });
    }

    private void ComposeFooter(IContainer container)
    {
        container.PaddingTop(6).Row(row =>
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
