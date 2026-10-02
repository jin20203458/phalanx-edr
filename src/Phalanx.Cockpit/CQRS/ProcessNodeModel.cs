using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.CQRS;

/// <summary>
/// C# 로컬 메모리에 투영되는 프로세스 트리 노드 모델 (MVVM ObservableObject)
/// </summary>
public partial class ProcessNodeModel : ObservableObject
{
    [ObservableProperty]
    private int _depth;

    partial void OnDepthChanged(int value)
    {
        OnPropertyChanged(nameof(IndentMargin));
    }

    public Thickness IndentMargin => new Thickness(Depth * 18, 0, 0, 0);

    [ObservableProperty]
    private bool _isExpanded = true;

    public bool HasChildren => Children.Count > 0;

    public ProcessNodeModel()
    {
        Children.CollectionChanged += (s, e) =>
        {
            OnPropertyChanged(nameof(HasChildren));
        };
    }
    [ObservableProperty]
    private uint _processId;

    [ObservableProperty]
    private uint _parentProcessId;

    [ObservableProperty]
    private ulong _processGuid;

    [ObservableProperty]
    private ulong _parentProcessGuid;

    [ObservableProperty]
    private string _imageName = string.Empty;

    [ObservableProperty]
    private string _fullImagePath = string.Empty;

    [ObservableProperty]
    private string _commandLine = string.Empty;

    [ObservableProperty]
    private ulong _startTimeNs;

    [ObservableProperty]
    private ulong _exitTimeNs;

    [ObservableProperty]
    private ulong _exitCode;

    [ObservableProperty]
    private uint _sessionId;

    [ObservableProperty]
    private uint _tokenElevationType;

    [ObservableProperty]
    private bool _isAlive = true;

    [ObservableProperty]
    private bool _isSuspended;

    [ObservableProperty]
    private bool _isTerminated;

    [ObservableProperty]
    private bool _isRestored;

    [ObservableProperty]
    private bool _isInvestigating;

    [ObservableProperty]
    private ProcessLifecycle _lifecycle = ProcessLifecycle.LifecycleUnknown;

    [ObservableProperty]
    private string _statusBadge = "[정상]";

    public string Status => StatusBadge;

    partial void OnStatusBadgeChanged(string value) => OnPropertyChanged(nameof(Status));

    partial void OnIsAliveChanged(bool value) => RefreshStatusBadge();
    partial void OnIsSuspendedChanged(bool value) => RefreshStatusBadge();
    partial void OnIsTerminatedChanged(bool value) => RefreshStatusBadge();
    partial void OnIsRestoredChanged(bool value) => RefreshStatusBadge();
    partial void OnIsInvestigatingChanged(bool value) => RefreshStatusBadge();
    partial void OnLifecycleChanged(ProcessLifecycle value) => RefreshStatusBadge();

    public ObservableCollection<ProcessNodeModel> Children { get; } = new();

    public ProcessNodeModel? Parent { get; set; }

    public void RefreshStatusBadge()
    {
        if (IsTerminated || Lifecycle == ProcessLifecycle.LifecycleTerminated)
        {
            if (IsAlive) IsAlive = false;
            if (IsSuspended) IsSuspended = false;
            if (IsInvestigating) IsInvestigating = false;
            StatusBadge = "[현장 사살]";
        }
        else if (Lifecycle == ProcessLifecycle.LifecycleStop)
        {
            if (IsAlive) IsAlive = false;
            if (IsSuspended) IsSuspended = false;
            if (IsInvestigating) IsInvestigating = false;
            StatusBadge = "[정상 종료]";
        }
        else if (IsInvestigating)
        {
            if (!IsSuspended) IsSuspended = true;
            StatusBadge = "[원자적 동결 (수사 중)]";
        }
        else if (IsSuspended)
        {
            StatusBadge = "[원자적 동결 (수동 대기)]";
        }
        else if (Lifecycle == ProcessLifecycle.LifecycleSnapshot)
        {
            StatusBadge = "[기저 프로세스]";
        }
        else
        {
            StatusBadge = "[실시간 가동 중]";
        }
    }

    public void UpdateStatus(ProcessLifecycle lifecycle, bool isSuspended = false, bool isTerminated = false)
    {
        Lifecycle = lifecycle;
        IsSuspended = isSuspended;
        IsTerminated = isTerminated;

        if (isTerminated || lifecycle == ProcessLifecycle.LifecycleTerminated)
        {
            IsAlive = false;
            IsRestored = false;
            IsInvestigating = false;
        }

        RefreshStatusBadge();
    }
}
