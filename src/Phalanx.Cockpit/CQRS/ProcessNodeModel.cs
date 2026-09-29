using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.CQRS;

/// <summary>
/// C# 로컬 메모리에 투영되는 프로세스 트리 노드 모델 (MVVM ObservableObject)
/// </summary>
public partial class ProcessNodeModel : ObservableObject
{
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
    private ProcessLifecycle _lifecycle = ProcessLifecycle.LifecycleUnknown;

    [ObservableProperty]
    private string _statusBadge = "[정상]";

    public ObservableCollection<ProcessNodeModel> Children { get; } = new();

    public ProcessNodeModel? Parent { get; set; }

    public void UpdateStatus(ProcessLifecycle lifecycle, bool isSuspended = false, bool isTerminated = false)
    {
        Lifecycle = lifecycle;
        IsSuspended = isSuspended;
        IsTerminated = isTerminated;

        if (isTerminated || lifecycle == ProcessLifecycle.LifecycleTerminated)
        {
            IsAlive = false;
            StatusBadge = "💀 [0.1ms 현장 사살]";
        }
        else if (isSuspended || lifecycle == ProcessLifecycle.LifecycleSuspended)
        {
            StatusBadge = "❄️ [24μs 원자적 동결 (수사 중)]";
        }
        else if (lifecycle == ProcessLifecycle.LifecycleStop)
        {
            IsAlive = false;
            StatusBadge = "⏹️ [정상 종료]";
        }
        else if (lifecycle == ProcessLifecycle.LifecycleSnapshot)
        {
            StatusBadge = "🌳 [기저 프로세스]";
        }
        else
        {
            StatusBadge = "🟢 [실시간 가동 중]";
        }
    }
}
