using Phalanx.Cockpit.CQRS;
using Phalanx.Shared.Protos;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class ProcessTreeProjectionTests
{
    [Fact]
    public void TestSnapshotBatchIngestionAndTreeBuilding()
    {
        var manager = new ProcessTreeProjectionManager();
        var snapshotEvents = new List<ProcessEvent>();

        // 1. 350개 모의 활성 프로세스 스냅샷 생성 (C++ InitializeFromSnapshot 모사)
        // PID 4: System (Root)
        snapshotEvents.Add(new ProcessEvent
        {
            ProcessId = 4,
            ParentProcessId = 0,
            ImageName = "System",
            TimestampNs = 1000,
            Lifecycle = ProcessLifecycle.LifecycleSnapshot
        });

        // PID 1000: winword.exe (Parent)
        snapshotEvents.Add(new ProcessEvent
        {
            ProcessId = 1000,
            ParentProcessId = 4,
            ImageName = "winword.exe",
            CommandLine = "winword.exe invoice.docx",
            TimestampNs = 2000,
            Lifecycle = ProcessLifecycle.LifecycleSnapshot
        });

        // 나머지 348개 일반 프로세스
        for (uint i = 2000; i < 2348; i++)
        {
            snapshotEvents.Add(new ProcessEvent
            {
                ProcessId = i,
                ParentProcessId = 4,
                ImageName = $"service_{i}.exe",
                TimestampNs = 10000 + i,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            });
        }

        // 스냅샷 일괄 주입
        manager.ApplySnapshotBatch(snapshotEvents);

        // 검증: 총 노드 350개 적재 확인
        Assert.Equal(350, manager.TotalCount);
        Assert.Equal(350, manager.ActiveCount);

        // 부모-자식 트리 링크 검증
        var winword = manager.FindActiveNodeByPid(1000);
        Assert.NotNull(winword);
        Assert.NotNull(winword.Parent);
        Assert.Equal((uint)4, winword.Parent.ProcessId);

        // 족보 횡단(Ancestry Traversal) 검증 (< 1ms, 0초 탐색)
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ancestry = manager.GetAncestry(1000, maxDepth: 5, includeSelf: true);
        sw.Stop();

        Assert.Equal(2, ancestry.Count);
        Assert.Equal("winword.exe", ancestry[0].ImageName);
        Assert.Equal("System", ancestry[1].ImageName);
        Assert.True(sw.ElapsedMilliseconds < 5, $"족보 조회가 너무 느림: {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void TestDeltaLifecycleEvents()
    {
        var manager = new ProcessTreeProjectionManager();

        // 1. 기저 프로세스 (PID 1000)
        manager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 1000,
                ParentProcessId = 0,
                ImageName = "explorer.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        // 2. 신규 자식 프로세스 기동 (LIFECYCLE_START)
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 5000,
            ParentProcessId = 1000,
            ImageName = "cmd.exe",
            CommandLine = "cmd.exe /c dir",
            TimestampNs = 50000,
            Lifecycle = ProcessLifecycle.LifecycleStart
        });

        var cmdNode = manager.FindActiveNodeByPid(5000);
        Assert.NotNull(cmdNode);
        Assert.True(cmdNode.IsAlive);
        Assert.Equal((uint)1000, cmdNode.ParentProcessId);

        // 3. 동결 상태 전이 (LIFECYCLE_SUSPENDED)
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 5000,
            ParentProcessId = 1000,
            ImageName = "cmd.exe",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        Assert.True(cmdNode.IsSuspended);
        Assert.Contains("동결", cmdNode.StatusBadge);

        // 4. 프로세스 정상 종료 (LIFECYCLE_STOP)
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 5000,
            ExitCode = 0,
            Lifecycle = ProcessLifecycle.LifecycleStop
        });

        Assert.False(cmdNode.IsAlive);
        Assert.Contains("종료", cmdNode.StatusBadge);
        Assert.Null(manager.FindActiveNodeByPid(5000));
    }

    [Fact]
    public void TestPidReuseHandling()
    {
        var manager = new ProcessTreeProjectionManager();

        // 프로세스 1: PID 7000 (이전 세대)
        ulong guid1 = ((ulong)100000 << 32) | 7000;
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 7000,
            ParentProcessId = 1000,
            ProcessGuid = guid1,
            ImageName = "old_proc.exe",
            Lifecycle = ProcessLifecycle.LifecycleStart
        });

        // 프로세스 1 종료
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 7000,
            ProcessGuid = guid1,
            Lifecycle = ProcessLifecycle.LifecycleStop
        });

        // 동일 PID 7000 재할당 (신규 세대)
        ulong guid2 = ((ulong)200000 << 32) | 7000;
        manager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 7000,
            ParentProcessId = 2000,
            ProcessGuid = guid2,
            ImageName = "new_service.exe",
            Lifecycle = ProcessLifecycle.LifecycleStart
        });

        var activeNode = manager.FindActiveNodeByPid(7000);
        Assert.NotNull(activeNode);
        Assert.Equal("new_service.exe", activeNode.ImageName);
        Assert.Equal(guid2, activeNode.ProcessGuid);

        // 이전 노드는 여전히 GUID로 조회 가능하며 IsAlive=false 상태 유지
        var oldNode = manager.FindNodeByGuid(guid1);
        Assert.NotNull(oldNode);
        Assert.False(oldNode.IsAlive);
        Assert.Equal("old_proc.exe", oldNode.ImageName);
    }
}
