using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Phalanx.Cockpit.ViewModels;

/// <summary>
/// EDR 관제 화면의 개별 침해사고/수사 사건 카드 및 상세 인스펙터 바인딩 뷰모델
/// </summary>
public partial class IncidentItemViewModel : ObservableObject
{
    [ObservableProperty]
    private string _incidentId = string.Empty;

    [ObservableProperty]
    private DateTime _timestamp = DateTime.UtcNow;

    [ObservableProperty]
    private uint _targetPid;

    [ObservableProperty]
    private string _targetImage = string.Empty;

    [ObservableProperty]
    private string _commandLine = string.Empty;

    [ObservableProperty]
    private uint _parentPid;

    [ObservableProperty]
    private string _parentImage = string.Empty;

    [ObservableProperty]
    private string _verdictAction = "SUSPENDED";

    [ObservableProperty]
    private string _statusSeverity = "SUSPENDED"; // CRITICAL, BENIGN, SUSPENDED, REFLEX

    [ObservableProperty]
    private double _confidenceScore;

    [ObservableProperty]
    private string _summaryTitle = string.Empty;

    [ObservableProperty]
    private string _narrative = string.Empty;

    [ObservableProperty]
    private string _blockedIp = string.Empty;

    [ObservableProperty]
    private double _elapsedMs;

    [ObservableProperty]
    private ObservableCollection<string> _mitreTactics = new();

    [ObservableProperty]
    private ObservableCollection<string> _remediationSteps = new();

    [ObservableProperty]
    private ObservableCollection<ReActStepViewModel> _traces = new();

    public string FormattedTime => Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string FormattedLatency => ElapsedMs > 0 
        ? $"{ElapsedMs / 1000.0:F2}s ({Traces.Count} Turns)" 
        : "Investigating...";

    public string ConfidenceDisplay => $"{ConfidenceScore:P0}";

    public bool HasBlockedIp => !string.IsNullOrWhiteSpace(BlockedIp);

    public bool IsCritical => StatusSeverity == "CRITICAL";
    public bool IsBenign => StatusSeverity == "BENIGN";
    public bool IsSuspended => StatusSeverity == "SUSPENDED";
    public bool IsReflex => StatusSeverity == "REFLEX";
}
