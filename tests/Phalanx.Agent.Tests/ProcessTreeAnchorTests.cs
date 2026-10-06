using System.Collections.Specialized;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.ViewModels;
using Phalanx.Shared.Protos;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class ProcessTreeAnchorTests
{
    [Fact]
    public void IsSelectionPinned_DefaultIsTrue_AndCanBeToggled()
    {
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        // 기본값은 true (선택 항목 화면 고정 활성화)
        Assert.True(vm.IsSelectionPinned);

        // 토글 검증
        bool propertyChangedRaised = false;
        vm.PropertyChanged += (sender, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.IsSelectionPinned))
            {
                propertyChangedRaised = true;
            }
        };

        vm.IsSelectionPinned = false;
        Assert.False(vm.IsSelectionPinned);
        Assert.True(propertyChangedRaised);

        vm.IsSelectionPinned = true;
        Assert.True(vm.IsSelectionPinned);
    }

    [Fact]
    public void RebuildVisibleNodes_InPlaceReconciliation_PreservesNodeInstances_WithoutResetAction()
    {
        var manager = new ProcessTreeProjectionManager();
        var snapshotEvents = new List<ProcessEvent>
        {
            new ProcessEvent
            {
                ProcessId = 4,
                ParentProcessId = 0,
                ImageName = "System",
                TimestampNs = 1000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 1000,
                ParentProcessId = 4,
                ImageName = "explorer.exe",
                CommandLine = "explorer.exe",
                TimestampNs = 2000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 2000,
                ParentProcessId = 1000,
                ImageName = "cmd.exe",
                CommandLine = "cmd.exe /c whoami",
                TimestampNs = 3000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        };

        manager.ApplySnapshotBatch(snapshotEvents);
        Assert.Equal(3, manager.VisibleNodes.Count);

        var explorerNodeBefore = manager.FindNodeByPid(1000);
        Assert.NotNull(explorerNodeBefore);

        // CollectionChanged 이벤트 감시 (Reset 발생 여부 추적)
        bool resetOccurred = false;
        NotifyCollectionChangedAction? lastAction = null;
        manager.VisibleNodes.CollectionChanged += (sender, args) =>
        {
            lastAction = args.Action;
            if (args.Action == NotifyCollectionChangedAction.Reset)
            {
                resetOccurred = true;
            }
        };

        // 신규 자식 프로세스 추가 (PID 2500)
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 2500,
            ParentProcessId = 1000,
            ImageName = "powershell.exe",
            CommandLine = "powershell.exe -enc ...",
            TimestampNs = 4000,
            Lifecycle = ProcessLifecycle.LifecycleStart
        });

        // RebuildVisibleNodes 실행 (차분 동기화)
        manager.RebuildVisibleNodes();

        // 1. Reset 액션이 발생하지 않았음을 확인 (WPF 가상화 컨테이너 파괴 및 스크롤 0 리셋 방지)
        Assert.False(resetOccurred, "RebuildVisibleNodes must not trigger NotifyCollectionChangedAction.Reset during in-place reconciliation.");

        // 2. 기존 노드 인스턴스(explorerNodeBefore)가 객체 동일성(ReferenceEquals)을 유지한 채 컬렉션 내에 존재하는지 검증
        var explorerNodeAfter = manager.FindNodeByPid(1000);
        Assert.Same(explorerNodeBefore, explorerNodeAfter);
        Assert.Contains(explorerNodeBefore, manager.VisibleNodes);

        // 3. 신규 노드가 올바르게 컬렉션에 추가되었는지 검증
        var psNode = manager.FindNodeByPid(2500);
        Assert.NotNull(psNode);
        Assert.Contains(psNode, manager.VisibleNodes);
        Assert.Equal(4, manager.VisibleNodes.Count);
    }

    [Fact]
    public void RebuildVisibleNodes_WhenNodesAddedOrRemoved_PreservesSelectionInMainViewModel()
    {
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        var initialEvents = new List<ProcessEvent>
        {
            new ProcessEvent
            {
                ProcessId = 4,
                ParentProcessId = 0,
                ImageName = "System",
                TimestampNs = 1000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 1000,
                ParentProcessId = 4,
                ImageName = "explorer.exe",
                CommandLine = "explorer.exe",
                TimestampNs = 2000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 2000,
                ParentProcessId = 1000,
                ImageName = "notepad.exe",
                CommandLine = "notepad.exe",
                TimestampNs = 3000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        };

        treeManager.ApplySnapshotBatch(initialEvents);

        // 사용자가 explorer.exe (PID 1000)를 선택했다고 가정
        var targetNode = treeManager.FindNodeByPid(1000);
        Assert.NotNull(targetNode);
        vm.SelectedProcessNode = targetNode;
        Assert.Same(targetNode, vm.SelectedProcessNode);
        Assert.True(vm.IsSelectionPinned);

        // 백그라운드 텔레메트리로 새 프로세스 다수 유입
        for (uint i = 3001; i <= 3005; i++)
        {
            treeManager.ApplyDeltaEvent(new ProcessEvent
            {
                ProcessId = i,
                ParentProcessId = 1000,
                ImageName = $"worker_{i}.exe",
                TimestampNs = 4000 + i,
                Lifecycle = ProcessLifecycle.LifecycleStart
            });
        }

        treeManager.RebuildVisibleNodes();

        // 선택된 노드가 null이 되지 않고 참조가 온전히 유지되는지 검증
        Assert.NotNull(vm.SelectedProcessNode);
        Assert.Same(targetNode, vm.SelectedProcessNode);

        // VisibleProcesses에도 여전히 포함되어 있어 UI에서 스크롤 앵커링이 가능한 상태인지 검증
        Assert.Contains(vm.SelectedProcessNode, vm.VisibleProcesses);
    }

    [Fact]
    public void RebuildVisibleNodes_RemovesTerminatedNodes_WhenHideTerminatedIsTrue_PreservesRemainingInstances()
    {
        var manager = new ProcessTreeProjectionManager();
        var snapshotEvents = new List<ProcessEvent>
        {
            new ProcessEvent
            {
                ProcessId = 4,
                ParentProcessId = 0,
                ImageName = "System",
                TimestampNs = 1000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 1000,
                ParentProcessId = 4,
                ImageName = "explorer.exe",
                TimestampNs = 2000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 2000,
                ParentProcessId = 1000,
                ImageName = "temp_task.exe",
                TimestampNs = 3000,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        };

        manager.ApplySnapshotBatch(snapshotEvents);
        Assert.Equal(3, manager.VisibleNodes.Count);

        var systemNode = manager.FindNodeByPid(4);
        var explorerNode = manager.FindNodeByPid(1000);
        var tempNode = manager.FindNodeByPid(2000);

        Assert.NotNull(systemNode);
        Assert.NotNull(explorerNode);
        Assert.NotNull(tempNode);

        // PID 2000 종료 이벤트 수신
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 2000,
            ParentProcessId = 1000,
            ImageName = "temp_task.exe",
            TimestampNs = 4000,
            Lifecycle = ProcessLifecycle.LifecycleStop
        });

        // HideTerminated = true 활성화
        manager.HideTerminated = true;
        manager.RebuildVisibleNodes();

        // PID 2000만 가시 목록에서 제거되고, System과 Explorer는 인스턴스 그대로 유지
        Assert.Equal(2, manager.VisibleNodes.Count);
        Assert.Contains(systemNode, manager.VisibleNodes);
        Assert.Contains(explorerNode, manager.VisibleNodes);
        Assert.DoesNotContain(tempNode, manager.VisibleNodes);

        // 다시 HideTerminated = false 복원 시
        manager.HideTerminated = false;
        manager.RebuildVisibleNodes();

        Assert.Equal(3, manager.VisibleNodes.Count);
        Assert.Contains(tempNode, manager.VisibleNodes);
    }
}
