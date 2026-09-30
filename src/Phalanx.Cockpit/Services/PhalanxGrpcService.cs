using Grpc.Core;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Services;

/// <summary>
/// C++ 네이티브 센서(Phalanx.Sensor)와의 gRPC 양방향 스트리밍 통신 엔드포인트 서비스.
/// 센서로부터 TelemetryBatch를 수신하여 CQRS 프로젝션 트리를 갱신하고,
/// 선제 동결(LIFECYCLE_SUSPENDED) 인입 시 자율 AI 위협 헌터를 가동하여 방어 명령을 역전송합니다.
/// </summary>
public class PhalanxGrpcService : PhalanxService.PhalanxServiceBase
{
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly AutonomousHunterAgent _agent;
    private readonly CockpitUiBridge? _uiBridge;
    private IServerStreamWriter<MitigationCommand>? _responseStream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public event Action<TelemetryBatch>? OnBatchReceived;
    public event Action<MitigationCommand>? OnCommandSent;

    public PhalanxGrpcService(
        ProcessTreeProjectionManager treeManager,
        AutonomousHunterAgent agent,
        CockpitUiBridge? uiBridge = null)
    {
        _treeManager = treeManager;
        _agent = agent;
        _uiBridge = uiBridge;

        if (_uiBridge != null)
        {
            _uiBridge.ManualCommandSender = SendCommandAsync;
        }
    }

    public override async Task StreamTelemetry(
        IAsyncStreamReader<TelemetryBatch> requestStream,
        IServerStreamWriter<MitigationCommand> responseStream,
        ServerCallContext context)
    {
        _responseStream = responseStream;
        Console.WriteLine("⚡ [gRPC Server] C++ 센서 클라이언트 연결됨.");
        _uiBridge?.NotifySensorConnected(true);

        try
        {
            while (await requestStream.MoveNext(context.CancellationToken))
            {
                var batch = requestStream.Current;
                OnBatchReceived?.Invoke(batch);

                // 1. 배치 내부 프로세스 이벤트들을 CQRS 프로젝션 트리에 투영
                foreach (var ev in batch.ProcessEvents)
                {
                    _treeManager.ApplyDeltaEvent(ev);

                    // 2. C++ 엔진에서 24μs 원자적 동결을 완료하고 수사 의뢰한 타깃 감지
                    if (ev.IsSuspended || ev.Lifecycle == ProcessLifecycle.LifecycleSuspended)
                    {
                        var targetNode = _treeManager.FindActiveNodeByPid(ev.ProcessId);
                        if (targetNode != null)
                        {
                            Console.WriteLine($"❄️ [수사 의뢰 인입] PID: {targetNode.ProcessId} ({targetNode.ImageName}) - 자율 AI 헌터 기동!");
                            
                            // 비동기 AI 에이전트 수사 루프 즉각 가동
                            _ = Task.Run(async () =>
                            {
                                try
                                {
                                    await _agent.InvestigateAsync(
                                        targetNode,
                                        async cmd => await SendCommandAsync(cmd),
                                        context.CancellationToken);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"❌ [AI 에이전트 수사 오류] {ex.Message}");
                                }
                            });
                        }
                    }
                }

                _uiBridge?.NotifyProcessCount(_treeManager.ActiveCount);
            }
        }
        catch (OperationCanceledException)
        {
            // 클라이언트 정상 연결 해제
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️ [gRPC 스트림 예외] {ex.Message}");
        }
        finally
        {
            _responseStream = null;
            _uiBridge?.NotifySensorConnected(false);
            Console.WriteLine("🔌 [gRPC Server] C++ 센서 클라이언트 연결 종료.");
        }
    }

    /// <summary>
    /// C++ 센서로 방어 완화 명령(사살/동결해제/연장) 비동기 전송
    /// </summary>
    public async Task SendCommandAsync(MitigationCommand command)
    {
        if (_responseStream == null)
        {
            return;
        }

        await _writeLock.WaitAsync();
        try
        {
            if (_responseStream != null)
            {
                await _responseStream.WriteAsync(command);
                OnCommandSent?.Invoke(command);
                _uiBridge?.NotifyCommandDispatched(command);
                Console.WriteLine($"🛡️ [gRPC 완화 명령 하달] 조치: {command.Action} | 타깃 PID: {command.TargetPid} | 사유: {command.Reason}");
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
