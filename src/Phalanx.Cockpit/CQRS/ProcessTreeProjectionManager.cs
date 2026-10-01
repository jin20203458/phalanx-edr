using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Windows;
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

    /// <summary>
    /// 1차원 플랫 가상화 렌더링용 활성 노드 컬렉션 (ListView VirtualizingStackPanel 최적화)
    /// </summary>
    public ObservableCollection<ProcessNodeModel> VisibleNodes { get; } = new();

    public event Action<ProcessNodeModel>? OnProcessSuspended;
    public event Action<ProcessNodeModel>? OnProcessTerminated;
    public event Action<ProcessNodeModel>? OnProcessStarted;
    public event Action<ProcessNodeModel>? OnProcessStopped;

    public int ActiveCount => _activePidToGuid.Count;
    public int TotalCount => _nodesByGuid.Count;

    public ProcessTreeProjectionManager()
    {
        var app = Application.Current;
        if (app != null)
        {
            System.Windows.Data.BindingOperations.EnableCollectionSynchronization(RootNodes, _syncLock);
            System.Windows.Data.BindingOperations.EnableCollectionSynchronization(AllNodes, _syncLock);
            System.Windows.Data.BindingOperations.EnableCollectionSynchronization(VisibleNodes, _syncLock);
        }
    }

    private static void DispatchUI(Action action)
    {
        var app = Application.Current;
        if (app?.Dispatcher != null && !app.Dispatcher.CheckAccess())
        {
            app.Dispatcher.Invoke(action);
        }
        else
        {
            action();
        }
    }

    /// <summary>
    /// OS 특수 가상 프로세스(PID 0)의 표기를 작업 관리자 표준 명칭으로 정제
    /// </summary>
    public static string NormalizeProcessImageName(uint pid, string? imageName)
    {
        if (pid == 0 || string.Equals(imageName, "[System Process]", StringComparison.OrdinalIgnoreCase))
        {
            return "System Idle Process";
        }
        return imageName ?? string.Empty;
    }

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

                if (_nodesByGuid.TryGetValue(guid, out var existing))
                {
                    existing.UpdateStatus(ProcessLifecycle.LifecycleSnapshot);
                    if (!string.IsNullOrEmpty(ev.CommandLine)) existing.CommandLine = ev.CommandLine;
                    if (ev.TokenElevationType != 0) existing.TokenElevationType = ev.TokenElevationType;
                    tempMap[ev.ProcessId] = existing;
                    continue;
                }

                var node = new ProcessNodeModel
                {
                    ProcessId = ev.ProcessId,
                    ParentProcessId = ev.ParentProcessId,
                    ProcessGuid = guid,
                    ParentProcessGuid = ev.ParentProcessGuid,
                    ImageName = NormalizeProcessImageName(ev.ProcessId, ev.ImageName),
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
            var rootNodesToAdd = new List<ProcessNodeModel>();
            var allNodesToAdd = new List<ProcessNodeModel>();

            foreach (var node in tempMap.Values)
            {
                if (node.ParentProcessId != 0 && tempMap.TryGetValue(node.ParentProcessId, out var parentNode))
                {
                    if (node.Parent != parentNode)
                    {
                        node.Parent = parentNode;
                        node.ParentProcessGuid = parentNode.ProcessGuid;
                    }
                    if (!parentNode.Children.Contains(node))
                    {
                        parentNode.Children.Add(node);
                    }
                }
                else
                {
                    if (!RootNodes.Contains(node) && !rootNodesToAdd.Contains(node))
                    {
                        rootNodesToAdd.Add(node);
                    }
                }

                if (!AllNodes.Contains(node) && !allNodesToAdd.Contains(node))
                {
                    allNodesToAdd.Add(node);
                }
            }

            // 계층 깊이(Depth) 일괄 재계산
            void UpdateDepths(ProcessNodeModel cur, int d)
            {
                cur.Depth = d;
                foreach (var c in cur.Children)
                {
                    UpdateDepths(c, d + 1);
                }
            }

            var allRoots = RootNodes.Concat(rootNodesToAdd).Distinct().ToList();
            foreach (var r in allRoots)
            {
                UpdateDepths(r, 0);
            }

            // 가시화 플랫 리스트 생성
            var flatList = new List<ProcessNodeModel>();
            foreach (var r in allRoots)
            {
                CollectVisibleSubtree(r, flatList);
            }

            DispatchUI(() =>
            {
                foreach (var node in rootNodesToAdd)
                {
                    RootNodes.Add(node);
                }
                foreach (var node in allNodesToAdd)
                {
                    AllNodes.Add(node);
                }

                VisibleNodes.Clear();
                foreach (var node in flatList)
                {
                    VisibleNodes.Add(node);
                }
            });
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
            ImageName = NormalizeProcessImageName(ev.ProcessId, ev.ImageName),
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
        }
        else if (ev.ParentProcessId != 0 && _activePidToGuid.TryGetValue(ev.ParentProcessId, out ulong pGuid) &&
                 _nodesByGuid.TryGetValue(pGuid, out parent))
        {
            node.Parent = parent;
            node.ParentProcessGuid = pGuid;
        }

        node.Depth = parent != null ? parent.Depth + 1 : 0;

        DispatchUI(() =>
        {
            if (parent != null)
            {
                if (!parent.Children.Contains(node))
                {
                    parent.Children.Add(node);
                }

                if (parent.IsExpanded)
                {
                    int insertIdx = FindLastVisibleDescendantIndex(parent);
                    if (insertIdx >= 0 && !VisibleNodes.Contains(node))
                    {
                        VisibleNodes.Insert(insertIdx + 1, node);
                    }
                    else if (!VisibleNodes.Contains(node))
                    {
                        VisibleNodes.Add(node);
                    }
                }
            }
            else
            {
                if (!RootNodes.Contains(node))
                {
                    RootNodes.Add(node);
                }
                if (!VisibleNodes.Contains(node))
                {
                    VisibleNodes.Add(node);
                }
            }

            if (!AllNodes.Contains(node))
            {
                AllNodes.Add(node);
            }
        });

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
            DispatchUI(() =>
            {
                targetNode.IsAlive = false;
                targetNode.ExitTimeNs = ev.TimestampNs;
                targetNode.ExitCode = ev.ExitCode;
                targetNode.UpdateStatus(ProcessLifecycle.LifecycleStop);
            });
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
            DispatchUI(() =>
            {
                RootNodes.Clear();
                AllNodes.Clear();
                VisibleNodes.Clear();
            });
        }
    }

    /// <summary>
    /// 단일 서브트리를 DFS 전위 순회(Pre-Order)하며 가시화 노드를 평탄화 수집
    /// </summary>
    private void CollectVisibleSubtree(ProcessNodeModel node, List<ProcessNodeModel> output)
    {
        output.Add(node);
        if (node.IsExpanded && node.Children.Count > 0)
        {
            foreach (var child in node.Children)
            {
                CollectVisibleSubtree(child, output);
            }
        }
    }

    /// <summary>
    /// 노드의 펼침/접힘 상태를 토글하고 가시화 플랫 컬렉션(VisibleNodes)을 부분 갱신 (VS Code splice 스타일)
    /// </summary>
    public void ToggleNodeExpanded(ProcessNodeModel node)
    {
        lock (_syncLock)
        {
            node.IsExpanded = !node.IsExpanded;

            if (!node.IsExpanded)
            {
                // 접힘(Collapse): VisibleNodes에서 해당 노드의 모든 하위 자손을 제거
                int nodeIdx = VisibleNodes.IndexOf(node);
                if (nodeIdx < 0) return;

                var descendantsToRemove = new List<ProcessNodeModel>();
                for (int i = nodeIdx + 1; i < VisibleNodes.Count; i++)
                {
                    var candidate = VisibleNodes[i];
                    if (IsDescendantOf(candidate, node))
                    {
                        descendantsToRemove.Add(candidate);
                    }
                    else
                    {
                        break;
                    }
                }

                DispatchUI(() =>
                {
                    foreach (var d in descendantsToRemove)
                    {
                        VisibleNodes.Remove(d);
                    }
                });
            }
            else
            {
                // 펼침(Expand): 자식 중 가시 상태인 노드들을 해당 노드 바로 뒤에 순차 삽입
                int nodeIdx = VisibleNodes.IndexOf(node);
                if (nodeIdx < 0) return;

                var toInsert = new List<ProcessNodeModel>();
                foreach (var child in node.Children)
                {
                    CollectVisibleSubtree(child, toInsert);
                }

                DispatchUI(() =>
                {
                    int currentIdx = VisibleNodes.IndexOf(node);
                    if (currentIdx >= 0)
                    {
                        for (int i = 0; i < toInsert.Count; i++)
                        {
                            VisibleNodes.Insert(currentIdx + 1 + i, toInsert[i]);
                        }
                    }
                });
            }
        }
    }

    /// <summary>
    /// 특정 노드가 화면(VisibleNodes)에 확실히 나타나도록 모든 상위 조상 노드를 펼치고 동기화
    /// </summary>
    public void EnsureNodeVisible(ProcessNodeModel node)
    {
        lock (_syncLock)
        {
            bool anyChange = false;
            var cur = node.Parent;
            while (cur != null)
            {
                if (!cur.IsExpanded)
                {
                    cur.IsExpanded = true;
                    anyChange = true;
                }
                cur = cur.Parent;
            }

            if (anyChange || !VisibleNodes.Contains(node))
            {
                RebuildVisibleNodes();
            }
        }
    }

    /// <summary>
    /// 가시화 플랫 컬렉션(VisibleNodes) 전체 재구축
    /// </summary>
    public void RebuildVisibleNodes()
    {
        lock (_syncLock)
        {
            var list = new List<ProcessNodeModel>();
            foreach (var root in RootNodes)
            {
                CollectVisibleSubtree(root, list);
            }

            DispatchUI(() =>
            {
                VisibleNodes.Clear();
                foreach (var item in list)
                {
                    VisibleNodes.Add(item);
                }
            });
        }
    }

    private int FindLastVisibleDescendantIndex(ProcessNodeModel parent)
    {
        int parentIdx = VisibleNodes.IndexOf(parent);
        if (parentIdx < 0) return -1;
        int idx = parentIdx;
        for (int i = parentIdx + 1; i < VisibleNodes.Count; i++)
        {
            var current = VisibleNodes[i];
            if (IsDescendantOf(current, parent))
            {
                idx = i;
            }
            else
            {
                break;
            }
        }
        return idx;
    }

    private static bool IsDescendantOf(ProcessNodeModel candidate, ProcessNodeModel ancestor)
    {
        var cur = candidate.Parent;
        while (cur != null)
        {
            if (cur == ancestor) return true;
            cur = cur.Parent;
        }
        return false;
    }

    /// <summary>
    /// Windows Win32 Toolhelp32 API를 활용하여 로컬 OS의 모든 프로세스를 0초 즉시 스냅샷 수집
    /// (C++ 센서 연결 전 또는 오프라인 상태에서도 관제 콕핏에 전체 프로세스 트리를 즉각 렌더링)
    /// </summary>
    public void InitializeFromLocalOsSnapshot()
    {
        if (!OperatingSystem.IsWindows()) return;

        var events = new List<ProcessEvent>();
        IntPtr hSnap = CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
        if (hSnap == IntPtr.Zero || hSnap == new IntPtr(-1)) return;

        try
        {
            var pe = new PROCESSENTRY32();
            pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

            if (Process32First(hSnap, ref pe))
            {
                ulong nowNs = (ulong)DateTime.UtcNow.Ticks * 100;
                do
                {
                    uint pid = pe.th32ProcessID;
                    uint ppid = pe.th32ParentProcessID;
                    string img = pe.szExeFile;

                    var ev = new ProcessEvent
                    {
                        ProcessId = pid,
                        ParentProcessId = ppid,
                        ImageName = NormalizeProcessImageName(pid, img),
                        TimestampNs = nowNs,
                        Lifecycle = ProcessLifecycle.LifecycleSnapshot,
                        ProcessGuid = ((nowNs << 32) | pid),
                        IsSuspended = false,
                        IsTerminated = false
                    };
                    events.Add(ev);
                } while (Process32Next(hSnap, ref pe));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Local Snapshot Warning] {ex.Message}");
        }
        finally
        {
            CloseHandle(hSnap);
        }

        if (events.Count > 0)
        {
            ApplySnapshotBatch(events);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
