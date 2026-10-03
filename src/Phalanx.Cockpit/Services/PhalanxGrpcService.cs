using System.Collections.Concurrent;
using Grpc.Core;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Services;

/// <summary>
/// C++ 네이티브 센서(Phalanx.Sensor)와의 gRPC 양방향 스트리밍 통신 엔드포인트 서비스.
/// 센서로부터 TelemetryBatch를 수신하여 CQRS 프로젝션 트리를 갱신하고,
/// 선제 동결(LIFECYCLE_SUSPENDED) 인입 시 자율 AI 위협 헌터를 가동하여 방어 명령을 역전송합니다.
/// 다중 클라이언트(센서 및 모의 도구) 동시 연결을 안전하게 지원합니다.
/// </summary>
public class PhalanxGrpcService : PhalanxService.PhalanxServiceBase
{
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly AutonomousHunterAgent _agent;
    private readonly CockpitUiBridge? _uiBridge;
    private readonly ConcurrentDictionary<string, IServerStreamWriter<MitigationCommand>> _activeClients = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public event Action<TelemetryBatch>? OnBatchReceived;
    public event Action<MitigationCommand>? OnCommandSent;
    public int ActiveConnectionCount => _activeClients.Count;

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
        string connectionId = Guid.NewGuid().ToString("N");
        _activeClients[connectionId] = responseStream;
        Console.WriteLine($"[gRPC Server] 클라이언트 연결됨 (ID: {connectionId}, 활성 연결 수: {_activeClients.Count})");
        _uiBridge?.NotifySensorConnected(true);

        try
        {
            while (await requestStream.MoveNext(context.CancellationToken))
            {
                var batch = requestStream.Current;
                OnBatchReceived?.Invoke(batch);

                // 1. 기저 프로세스 스냅샷 배치 일괄 주입 (개별 분할 방지 및 부모-자식 트리 온전 보존)
                var snapshotEvents = batch.ProcessEvents
                    .Where(e => e.Lifecycle == ProcessLifecycle.LifecycleSnapshot)
                    .ToList();

                if (snapshotEvents.Count > 0)
                {
                    _treeManager.ApplySnapshotBatch(snapshotEvents);
                }

                // 2. 실시간 증분 델타 이벤트 처리
                var deltaEvents = batch.ProcessEvents
                    .Where(e => e.Lifecycle != ProcessLifecycle.LifecycleSnapshot)
                    .ToList();

                foreach (var ev in deltaEvents)
                {
                    _treeManager.ApplyDeltaEvent(ev);

                    // 2. C++ 엔진에서 24μs 원자적 동결을 완료하고 수사 의뢰한 타깃 감지
                    if (ev.IsSuspended || ev.Lifecycle == ProcessLifecycle.LifecycleSuspended)
                    {
                        var targetNode = _treeManager.FindActiveNodeByPid(ev.ProcessId);
                        if (targetNode != null)
                        {
                            Console.WriteLine($"[SUSPEND] PID: {targetNode.ProcessId} ({targetNode.ImageName}) - 자율 AI 헌터 기동!");
                            
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
                                    Console.WriteLine($"[ERROR] AI 에이전트 수사 오류: {ex.Message}");
                                }
                            });
                        }
                    }
                    // 3. C++ 커널 룰 엔진에서 0.1ms 이내 즉각 현장 사살(Reflex Kill) 집행된 타깃 감지
                    else if (ev.IsTerminated || ev.Lifecycle == ProcessLifecycle.LifecycleTerminated)
                    {
                        var node = _treeManager.FindNodeByPid(ev.ProcessId) ?? new ProcessNodeModel
                        {
                            ProcessId = ev.ProcessId,
                            ParentProcessId = ev.ParentProcessId,
                            ImageName = ev.ImageName,
                            CommandLine = ev.CommandLine
                        };

                        Console.WriteLine($"[REFLEX KILL] PID: {node.ProcessId} ({node.ImageName}) - 0.1ms Reflex Kill 즉시 관제 보고!");
                        try
                        {
                            _agent.HandleReflexKill(node);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[ERROR] 현장 사살 보고 오류: {ex.Message}");
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
            Console.WriteLine($"[STREAM ERROR] {ex.Message}\n{ex.StackTrace}");
        }
        finally
        {
            _activeClients.TryRemove(connectionId, out _);
            Console.WriteLine($"[gRPC Server] 클라이언트 연결 종료 (ID: {connectionId}, 잔여 연결 수: {_activeClients.Count})");

            // 모든 연결이 종료되었을 때만 UI에 DISCONNECTED 알림
            if (_activeClients.IsEmpty)
            {
                _uiBridge?.NotifySensorConnected(false);
            }
        }
    }

    /// <summary>
    /// 연결된 모든 C++ 센서 및 클라이언트로 방어 완화 명령(사살/동결해제/연장) 비동기 전송
    /// </summary>
    public async Task SendCommandAsync(MitigationCommand command)
    {
        if (_activeClients.IsEmpty)
        {
            return;
        }

        await _writeLock.WaitAsync();
        try
        {
            var deadClients = new List<string>();
            foreach (var kvp in _activeClients)
            {
                try
                {
                    await kvp.Value.WriteAsync(command);
                }
                catch
                {
                    deadClients.Add(kvp.Key);
                }
            }

            foreach (var dead in deadClients)
            {
                _activeClients.TryRemove(dead, out _);
            }

            if (_activeClients.IsEmpty)
            {
                _uiBridge?.NotifySensorConnected(false);
            }

            OnCommandSent?.Invoke(command);
            Console.WriteLine($"[COMMAND] 조치: {command.Action} | 타깃 PID: {command.TargetPid} | 사유: {command.Reason}");
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
