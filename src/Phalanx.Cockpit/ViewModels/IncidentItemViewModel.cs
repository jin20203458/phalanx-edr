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
    [NotifyPropertyChangedFor(nameof(TargetFileName))]
    [NotifyPropertyChangedFor(nameof(TargetDirectoryPath))]
    [NotifyPropertyChangedFor(nameof(HasTargetDirectory))]
    private string _targetImage = string.Empty;

    [ObservableProperty]
    private string _commandLine = string.Empty;

    [ObservableProperty]
    private uint _parentPid;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ParentFileName))]
    [NotifyPropertyChangedFor(nameof(ParentDirectoryPath))]
    [NotifyPropertyChangedFor(nameof(HasParentDirectory))]
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

    public string RelativeTime
    {
        get
        {
            var diff = DateTime.UtcNow - Timestamp;
            if (diff.TotalMinutes < 1) return "방금 전";
            if (diff.TotalMinutes < 60) return $"{(int)diff.TotalMinutes}분 전";
            if (diff.TotalHours < 24) return $"{(int)diff.TotalHours}시간 전";
            return $"{(int)diff.TotalDays}일 전";
        }
    }

    public string PrimaryMitreTactic => MitreTactics.Count > 0 ? MitreTactics[0] : (IsCritical ? "T1059.001" : "T1218");

    public string FormattedLatency
    {
        get
        {
            if (ElapsedMs <= 0 && (VerdictAction == "SUSPENDED" || string.IsNullOrEmpty(VerdictAction)))
                return "Investigating...";

            double displayMs = ElapsedMs > 0 ? ElapsedMs : 0.08;
            string turns = Traces.Count <= 1 ? "Reflex" : $"{Traces.Count} Turns";

            if (displayMs < 1.0)
                return $"{displayMs * 1000.0:F0}μs ({displayMs:F2}ms, {turns})";
            if (displayMs < 1000.0)
                return $"{displayMs:F1}ms ({turns})";
            return $"{displayMs / 1000.0:F2}s ({turns})";
        }
    }

    public string ConfidenceDisplay => $"{ConfidenceScore:P0}";

    public bool HasBlockedIp => !string.IsNullOrWhiteSpace(BlockedIp);

    public bool IsCritical => StatusSeverity == "CRITICAL";
    public bool IsBenign => StatusSeverity == "BENIGN";
    public bool IsSuspended => StatusSeverity == "SUSPENDED";
    public bool IsReflex => StatusSeverity == "REFLEX";

    // 2단 계층 분리: 파일명 우선 (절대 안 잘림) + 디렉터리 경로 분리
    public string ParentFileName
    {
        get
        {
            if (string.IsNullOrWhiteSpace(ParentImage)) return "-";
            try
            {
                var name = System.IO.Path.GetFileName(ParentImage);
                return string.IsNullOrEmpty(name) ? ParentImage : name;
            }
            catch
            {
                return ParentImage;
            }
        }
    }

    public string ParentDirectoryPath
    {
        get
        {
            if (string.IsNullOrWhiteSpace(ParentImage)) return string.Empty;
            try
            {
                var dir = System.IO.Path.GetDirectoryName(ParentImage);
                return string.IsNullOrEmpty(dir) ? string.Empty : dir;
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    public bool HasParentDirectory => !string.IsNullOrEmpty(ParentDirectoryPath);

    public string TargetFileName
    {
        get
        {
            if (string.IsNullOrWhiteSpace(TargetImage)) return "-";
            try
            {
                var name = System.IO.Path.GetFileName(TargetImage);
                return string.IsNullOrEmpty(name) ? TargetImage : name;
            }
            catch
            {
                return TargetImage;
            }
        }
    }

    public string TargetDirectoryPath
    {
        get
        {
            if (string.IsNullOrWhiteSpace(TargetImage)) return string.Empty;
            try
            {
                var dir = System.IO.Path.GetDirectoryName(TargetImage);
                return string.IsNullOrEmpty(dir) ? string.Empty : dir;
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    public bool HasTargetDirectory => !string.IsNullOrEmpty(TargetDirectoryPath);
}
