using LiteDB;

namespace Phalanx.Cockpit.Storage;

/// <summary>
/// LiteDB에 영구 저장되는 침해사고 공식 서사 및 조사 결과 레코드
/// </summary>
public class IncidentRecord
{
    [BsonId]
    public ObjectId Id { get; set; } = ObjectId.NewObjectId();

    public string IncidentId { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public uint TargetPid { get; set; }
    public string TargetImage { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public double ConfidenceScore { get; set; }
    public string VerdictAction { get; set; } = string.Empty; // ACTION_KILL or ACTION_RESUME
    public string SummaryTitle { get; set; } = string.Empty;
    public string Narrative { get; set; } = string.Empty;
    public List<string> MitreTactics { get; set; } = new();
    public string BlockedIp { get; set; } = string.Empty;
    public string RootCauseProcess { get; set; } = string.Empty;
    public List<string> TerminatedProcesses { get; set; } = new();
    public string RemediationStatus { get; set; } = "SECURED";
}

/// <summary>
/// ReAct 추론 루프 단계별 추적 기록 (Thought / Action / Observation)
/// </summary>
public class ReActTraceRecord
{
    [BsonId]
    public ObjectId Id { get; set; } = ObjectId.NewObjectId();

    public string IncidentId { get; set; } = string.Empty;
    public int StepNumber { get; set; }
    public string Thought { get; set; } = string.Empty;
    public string ActionTool { get; set; } = string.Empty;
    public string ActionArgsJson { get; set; } = string.Empty;
    public string Observation { get; set; } = string.Empty;
    public DateTime StepTimestamp { get; set; } = DateTime.UtcNow;
}
