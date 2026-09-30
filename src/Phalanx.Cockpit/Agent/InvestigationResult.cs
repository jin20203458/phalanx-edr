using Phalanx.Cockpit.Storage;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Agent;

public record InvestigationResult(
    string IncidentId,
    MitigationCommand.Types.ActionType VerdictAction,
    double Confidence,
    string SummaryTitle,
    string Narrative,
    List<string> MitreTactics,
    string? BlockedIp,
    List<ReActTraceRecord> Traces,
    TimeSpan Elapsed,
    IncidentRecord Record,
    List<string>? RemediationSteps = null
);
