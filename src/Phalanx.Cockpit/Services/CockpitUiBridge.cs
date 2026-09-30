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
    private static CockpitUiBridge? _instance;
    public static CockpitUiBridge Instance => _instance ??= new CockpitUiBridge();

    // UI 알림 이벤트
    public event Action<bool>? SensorConnectionChanged;
    public event Action<int>? ProcessCountUpdated;
    public event Action<ProcessNodeModel, string>? InvestigationStarted;
    public event Action<InvestigationResult>? InvestigationCompleted;
    public event Action<MitigationCommand>? CommandDispatched;

    // 수동 제어 역방향 명령 대리자 (MainWindow -> gRPC 서비스)
    public Func<MitigationCommand, Task>? ManualCommandSender { get; set; }

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

    public void NotifyInvestigationCompleted(InvestigationResult result)
    {
        Dispatch(() => InvestigationCompleted?.Invoke(result));
    }

    public void NotifyCommandDispatched(MitigationCommand command)
    {
        Dispatch(() => CommandDispatched?.Invoke(command));
    }

    public async Task SendManualCommandAsync(MitigationCommand command)
    {
        if (ManualCommandSender != null)
        {
            await ManualCommandSender(command);
        }
    }

    private static void Dispatch(Action action)
    {
        var app = Application.Current;
        if (app?.Dispatcher != null && !app.Dispatcher.CheckAccess())
        {
            _ = app.Dispatcher.InvokeAsync(action);
        }
        else
        {
            action();
        }
    }
}
