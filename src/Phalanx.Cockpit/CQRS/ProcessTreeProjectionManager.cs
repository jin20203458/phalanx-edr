using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.CQRS;

/// <summary>
/// C++ 네이티브 엔진으로부터 수신한 스냅샷 및 생명주기 델타 이벤트를 바탕으로
/// C# 로컬 메모리에 완전한 프로세스 트리 DAG를 실시간 투영(CQRS Read Model)하는 매니저.
/// C++로의 네트워크 역질의 없이 로컬 RAM에서 0초 만에 족보를 탐색합니다.
/// </summary>
public class ProcessTreeProjectionManager
{
    private readonly ConcurrentDictionary<ulong, ProcessNodeModel> _nodesByGuid = new();
    private readonly ConcurrentDictionary<uint, ulong> _activePidToGuid = new();
    private readonly object _syncLock = new();

    /// <summary>
    /// UI 렌더링용 루트 노드 컬렉션 (부모가 없거나 기저 시스템 프로세스)
    /// </summary>
    public ObservableCollection<ProcessNodeModel> RootNodes { get; } = new();

    /// <summary>
    /// 전체 노드 플랫 컬렉션
    /// </summary>
    public ObservableCollection<ProcessNodeModel> AllNodes { get; } = new();

    public event Action<ProcessNodeModel>? OnProcessSuspended;
    public event Action<ProcessNodeModel>? OnProcessTerminated;
    public event Action<ProcessNodeModel>? OnProcessStarted;
    public event Action<ProcessNodeModel>? OnProcessStopped;

    public int ActiveCount => _activePidToGuid.Count;
    public int TotalCount => _nodesByGuid.Count;

    /// <summary>
    /// 엔진 기동 또는 재연결 시 C++이 1회 일괄 전송한 기저 프로세스 스냅샷 배치 주입
    /// </summary>
    public void ApplySnapshotBatch(IEnumerable<ProcessEvent> events)
    {
        lock (_syncLock)
        {
            var eventList = events.ToList();
            var tempMap = new Dictionary<uint, ProcessNodeModel>();

            foreach (var ev in eventList)
            {
                ulong guid = ev.ProcessGuid != 0 ? ev.ProcessGuid : ((ev.TimestampNs << 32) | ev.ProcessId);
                var node = new ProcessNodeModel
                {
                    ProcessId = ev.ProcessId,
                    ParentProcessId = ev.ParentProcessId,
                    ProcessGuid = guid,
                    ParentProcessGuid = ev.ParentProcessGuid,
                    ImageName = ev.ImageName,
                    CommandLine = ev.CommandLine,
                    StartTimeNs = ev.TimestampNs,
                    SessionId = ev.SessionId,
                    TokenElevationType = ev.TokenElevationType,
                    IsAlive = true,
                };
                node.UpdateStatus(ProcessLifecycle.LifecycleSnapshot);

                _nodesByGuid[guid] = node;
                _activePidToGuid[ev.ProcessId] = guid;
                tempMap[ev.ProcessId] = node;
            }

            // 부모-자식 트리 링크 구성
            foreach (var node in tempMap.Values)
            {
                if (node.ParentProcessId != 0 && tempMap.TryGetValue(node.ParentProcessId, out var parentNode))
                {
                    node.Parent = parentNode;
                    node.ParentProcessGuid = parentNode.ProcessGuid;
                    parentNode.Children.Add(node);
                }
                else
                {
                    RootNodes.Add(node);
                }
                AllNodes.Add(node);
            }
        }
    }

    /// <summary>
    /// 실시간 생명주기 델타(생성/종료/동결/사살) 이벤트 처리
    /// </summary>
    public void ApplyDeltaEvent(ProcessEvent ev)
    {
        lock (_syncLock)
        {
            ulong guid = ev.ProcessGuid != 0 ? ev.ProcessGuid : ((ev.TimestampNs << 32) | ev.ProcessId);

            switch (ev.Lifecycle)
            {
                case ProcessLifecycle.LifecycleSnapshot:
                    ApplySnapshotBatch(new[] { ev });
                    break;

                case ProcessLifecycle.LifecycleStart:
                case ProcessLifecycle.LifecycleSuspended:
                case ProcessLifecycle.LifecycleTerminated:
                    HandleStartOrMitigated(ev, guid);
                    break;

                case ProcessLifecycle.LifecycleStop:
                    HandleStop(ev);
                    break;

                default:
                    // 알 수 없는 경우 Start/Mitigated 공통 처리
                    HandleStartOrMitigated(ev, guid);
                    break;
            }
        }
    }

    private void HandleStartOrMitigated(ProcessEvent ev, ulong guid)
    {
        // 1. 이미 존재하는 활성 노드의 상태 전이(SUSPENDED, TERMINATED)인 경우 기존 노드 업데이트
        if ((ev.Lifecycle == ProcessLifecycle.LifecycleSuspended || ev.Lifecycle == ProcessLifecycle.LifecycleTerminated || ev.IsSuspended || ev.IsTerminated) &&
            _activePidToGuid.TryGetValue(ev.ProcessId, out ulong existingGuid) &&
            (ev.ProcessGuid == 0 || ev.ProcessGuid == existingGuid) &&
            _nodesByGuid.TryGetValue(existingGuid, out var existingNode))
        {
            existingNode.UpdateStatus(ev.Lifecycle, ev.IsSuspended, ev.IsTerminated);
            if (ev.IsTerminated || ev.Lifecycle == ProcessLifecycle.LifecycleTerminated)
            {
                OnProcessTerminated?.Invoke(existingNode);
            }
            else if (ev.IsSuspended || ev.Lifecycle == ProcessLifecycle.LifecycleSuspended)
            {
                OnProcessSuspended?.Invoke(existingNode);
            }
            return;
        }

        // PID 재사용 처리: 동일 PID의 이전 노드가 활성 상태라면 종료 처리
        if (_activePidToGuid.TryGetValue(ev.ProcessId, out ulong oldGuid) && oldGuid != guid)
        {
            if (_nodesByGuid.TryGetValue(oldGuid, out var oldNode))
            {
                oldNode.IsAlive = false;
                oldNode.UpdateStatus(ProcessLifecycle.LifecycleStop);
            }
        }

        var node = new ProcessNodeModel
        {
            ProcessId = ev.ProcessId,
            ParentProcessId = ev.ParentProcessId,
            ProcessGuid = guid,
            ParentProcessGuid = ev.ParentProcessGuid,
            ImageName = ev.ImageName,
            CommandLine = ev.CommandLine,
            StartTimeNs = ev.TimestampNs,
            SessionId = ev.SessionId,
            TokenElevationType = ev.TokenElevationType,
            IsAlive = !ev.IsTerminated && ev.Lifecycle != ProcessLifecycle.LifecycleTerminated,
        };
        node.UpdateStatus(ev.Lifecycle, ev.IsSuspended, ev.IsTerminated);

        _nodesByGuid[guid] = node;
        if (node.IsAlive)
        {
            _activePidToGuid[ev.ProcessId] = guid;
        }

        // 부모 탐색 및 연결
        ProcessNodeModel? parent = null;
        if (ev.ParentProcessGuid != 0 && _nodesByGuid.TryGetValue(ev.ParentProcessGuid, out parent))
        {
            node.Parent = parent;
            parent.Children.Add(node);
        }
        else if (ev.ParentProcessId != 0 && _activePidToGuid.TryGetValue(ev.ParentProcessId, out ulong pGuid) &&
                 _nodesByGuid.TryGetValue(pGuid, out parent))
        {
            node.Parent = parent;
            node.ParentProcessGuid = pGuid;
            parent.Children.Add(node);
        }
        else
        {
            RootNodes.Add(node);
        }
        AllNodes.Add(node);

        if (ev.IsTerminated || ev.Lifecycle == ProcessLifecycle.LifecycleTerminated)
        {
            OnProcessTerminated?.Invoke(node);
        }
        else if (ev.IsSuspended || ev.Lifecycle == ProcessLifecycle.LifecycleSuspended)
        {
            OnProcessSuspended?.Invoke(node);
        }
        else
        {
            OnProcessStarted?.Invoke(node);
        }
    }

    private void HandleStop(ProcessEvent ev)
    {
        ProcessNodeModel? targetNode = null;
        if (ev.ProcessGuid != 0 && _nodesByGuid.TryGetValue(ev.ProcessGuid, out targetNode))
        {
            // GUID로 직접 적중
        }
        else if (_activePidToGuid.TryGetValue(ev.ProcessId, out ulong activeGuid) &&
                 _nodesByGuid.TryGetValue(activeGuid, out targetNode))
        {
            // PID로 활성 노드 적중
        }

        if (targetNode != null)
        {
            targetNode.IsAlive = false;
            targetNode.ExitTimeNs = ev.TimestampNs;
            targetNode.ExitCode = ev.ExitCode;
            targetNode.UpdateStatus(ProcessLifecycle.LifecycleStop);
            _activePidToGuid.TryRemove(ev.ProcessId, out _);
            OnProcessStopped?.Invoke(targetNode);
        }
    }

    /// <summary>
    /// C++로의 추가 RPC 질의 없이 로컬 메모리에서 즉시 0초 만에 족보(부모->조부모->증조부모)를 역추적
    /// </summary>
    public IReadOnlyList<ProcessNodeModel> GetAncestry(uint pid, int maxDepth = 5, bool includeSelf = false)
    {
        if (!_activePidToGuid.TryGetValue(pid, out ulong guid))
        {
            return Array.Empty<ProcessNodeModel>();
        }
        return GetAncestryByGuid(guid, maxDepth, includeSelf);
    }

    /// <summary>
    /// GUID 기반 족보 역추적
    /// </summary>
    public IReadOnlyList<ProcessNodeModel> GetAncestryByGuid(ulong guid, int maxDepth = 5, bool includeSelf = false)
    {
        var list = new List<ProcessNodeModel>();
        if (!_nodesByGuid.TryGetValue(guid, out var current))
        {
            return list;
        }

        if (includeSelf)
        {
            list.Add(current);
        }

        var parent = current.Parent;
        int depth = 0;
        while (parent != null && depth < maxDepth)
        {
            list.Add(parent);
            parent = parent.Parent;
            depth++;
        }

        return list;
    }

    public ProcessNodeModel? FindActiveNodeByPid(uint pid)
    {
        if (_activePidToGuid.TryGetValue(pid, out ulong guid) &&
            _nodesByGuid.TryGetValue(guid, out var node))
        {
            return node;
        }
        return null;
    }

    public ProcessNodeModel? FindNodeByPid(uint pid)
    {
        lock (_syncLock)
        {
            return AllNodes.FirstOrDefault(n => n.ProcessId == pid);
        }
    }

    public ProcessNodeModel? FindNodeByGuid(ulong guid)
    {
        _nodesByGuid.TryGetValue(guid, out var node);
        return node;
    }

    public void Clear()
    {
        lock (_syncLock)
        {
            _nodesByGuid.Clear();
            _activePidToGuid.Clear();
            RootNodes.Clear();
            AllNodes.Clear();
        }
    }
}
