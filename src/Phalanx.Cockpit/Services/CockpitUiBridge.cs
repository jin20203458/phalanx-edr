using System.Windows;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Services;

/// <summary>
/// Kestrel gRPC 백그라운드 서비스 및 AI 위협 헌터의 실시간 이벤트를
/// WPF UI 스레드로 스레드 안전하게 마샬링하는 싱글톤 이벤트 브리지.
/// </summary>
public class CockpitUiBridge
{
    public static CockpitUiBridge Instance { get; } = new();

    // UI 알림 이벤트
    public event Action<bool>? SensorConnectionChanged;
    public event Action<int>? ProcessCountUpdated;
    public event Action<ProcessNodeModel, string>? InvestigationStarted;
    public event Action<string, ReActTraceRecord>? ReActStepCompleted;
    public event Action<InvestigationResult>? InvestigationCompleted;
    public event Action? IncidentsDatabaseCleared;
    public event Action<string /* statusText */, bool /* isOnline */>? EngineConfigurationChanged;

    // 수동 제어 역방향 명령 대리자 (MainWindow -> gRPC 서비스)
    public Func<MitigationCommand, Task>? ManualCommandSender { get; set; }

    // 심층 조사 취소 역방향 대리자 (MainViewModel -> AutonomousHunterAgent)
    public Func<string, bool>? InvestigationCancelHandler { get; set; }

    public bool CancelInvestigation(string incidentId)
    {
        return InvestigationCancelHandler?.Invoke(incidentId) ?? false;
    }

    public void NotifyIncidentsDatabaseCleared()
    {
        Dispatch(() => IncidentsDatabaseCleared?.Invoke());
    }

    public void NotifySensorConnected(bool isConnected)
    {
        Dispatch(() => SensorConnectionChanged?.Invoke(isConnected));
    }

    public void NotifyProcessCount(int count)
    {
        Dispatch(() => ProcessCountUpdated?.Invoke(count));
    }

    public void NotifyInvestigationStarted(ProcessNodeModel targetNode, string incidentId)
    {
        Dispatch(() => InvestigationStarted?.Invoke(targetNode, incidentId));
    }

    public void NotifyReActStepCompleted(string incidentId, ReActTraceRecord trace)
    {
        Dispatch(() => ReActStepCompleted?.Invoke(incidentId, trace));
    }

    public void NotifyInvestigationCompleted(InvestigationResult result)
    {
        Dispatch(() => InvestigationCompleted?.Invoke(result));
    }

    public void NotifyEngineConfigurationChanged(string statusText, bool isOnline)
    {
        Dispatch(() => EngineConfigurationChanged?.Invoke(statusText, isOnline));
    }

    public async Task SendManualCommandAsync(MitigationCommand command)
    {
        if (ManualCommandSender != null)
        {
            await ManualCommandSender(command);
        }
    }

    private void Dispatch(Action action)
    {
        var app = Application.Current;
        if (ReferenceEquals(this, Instance) && app?.Dispatcher != null && !app.Dispatcher.CheckAccess() && app.Dispatcher.Thread.IsAlive && !app.Dispatcher.HasShutdownStarted)
        {
            _ = app.Dispatcher.InvokeAsync(action);
        }
        else
        {
            action();
        }
    }
}
