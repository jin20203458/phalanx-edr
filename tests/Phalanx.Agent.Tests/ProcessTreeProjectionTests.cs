using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.ViewModels;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.Tools;
using Phalanx.Cockpit.Scenarios;
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

    [Fact]
    public void TestFlatTreeProjectionAndCollapseExpand()
    {
        var manager = new ProcessTreeProjectionManager();

        // 1. Root: PID 4 (System)
        // 2. Child: PID 100 (winword.exe)
        // 3. Grandchild: PID 200 (powershell.exe)
        // 4. Root 2: PID 500 (explorer.exe)
        var snapshot = new List<ProcessEvent>
        {
            new ProcessEvent { ProcessId = 4, ParentProcessId = 0, ImageName = "System", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 100, ParentProcessId = 4, ImageName = "winword.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 200, ParentProcessId = 100, ImageName = "powershell.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 500, ParentProcessId = 0, ImageName = "explorer.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot }
        };

        manager.ApplySnapshotBatch(snapshot);

        // 검증: VisibleNodes가 DFS 전위 순서(Pre-order)로 평탄화되었는지 확인
        Assert.Equal(4, manager.VisibleNodes.Count);
        Assert.Equal((uint)4, manager.VisibleNodes[0].ProcessId);
        Assert.Equal(0, manager.VisibleNodes[0].Depth);

        Assert.Equal((uint)100, manager.VisibleNodes[1].ProcessId);
        Assert.Equal(1, manager.VisibleNodes[1].Depth);
        Assert.True(manager.VisibleNodes[1].HasChildren);

        Assert.Equal((uint)200, manager.VisibleNodes[2].ProcessId);
        Assert.Equal(2, manager.VisibleNodes[2].Depth);
        Assert.False(manager.VisibleNodes[2].HasChildren);

        Assert.Equal((uint)500, manager.VisibleNodes[3].ProcessId);
        Assert.Equal(0, manager.VisibleNodes[3].Depth);

        // winword.exe(PID 100) 접기 (Collapse) 테스트
        var winword = manager.FindActiveNodeByPid(100)!;
        manager.ToggleNodeExpanded(winword);

        Assert.False(winword.IsExpanded);
        Assert.Equal(3, manager.VisibleNodes.Count);
        // powershell.exe(PID 200)가 VisibleNodes에서 제거되었는지 확인
        Assert.DoesNotContain(manager.VisibleNodes, n => n.ProcessId == 200);

        // winword.exe(PID 100) 다시 펼치기 (Expand) 테스트
        manager.ToggleNodeExpanded(winword);

        Assert.True(winword.IsExpanded);
        Assert.Equal(4, manager.VisibleNodes.Count);
        Assert.Equal((uint)200, manager.VisibleNodes[2].ProcessId);

        // EnsureNodeVisible 테스트: winword 접힌 상태에서 powershell 가시화 요청 시 자동 언랩 검증
        manager.ToggleNodeExpanded(winword);
        Assert.False(winword.IsExpanded);
        Assert.Equal(3, manager.VisibleNodes.Count);

        var powershell = manager.FindActiveNodeByPid(200)!;
        manager.EnsureNodeVisible(powershell);

        Assert.True(winword.IsExpanded);
        Assert.Contains(manager.VisibleNodes, n => n.ProcessId == 200);
    }

    [Fact]
    public void TestSystemIdleProcessNormalization()
    {
        var manager = new ProcessTreeProjectionManager();

        manager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 0,
                ParentProcessId = 0,
                ImageName = "[System Process]",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        var idleNode = manager.FindActiveNodeByPid(0);
        Assert.NotNull(idleNode);
        Assert.Equal("System Idle Process", idleNode.ImageName);
    }

    [Fact]
    public void TestMainViewModel_FocusProcessInGraphCommand()
    {
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = CockpitUiBridge.Instance;
        var sensorController = SensorProcessController.Instance;
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, [], geminiApiKey: string.Empty);
        var labRunner = new AttackLabScenarioRunner(treeManager, agent);

        treeManager.ApplySnapshotBatch(
        [
            new ProcessEvent
            {
                ProcessId = 4,
                ParentProcessId = 0,
                ImageName = "System",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 1234,
                ParentProcessId = 4,
                ImageName = "malware.exe",
                TokenElevationType = 2,
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        ]);

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge, sensorController, labRunner);

        Assert.Equal(CockpitViewType.Incidents, vm.CurrentView);
        Assert.Null(vm.SelectedProcessNode);

        // 심층 포렌식 분석의 '전역 프로세스 트리에서 위치 확인 ➔' 명령 실행
        vm.FocusProcessInGraphCommand.Execute((uint)1234);

        // 뷰 전환 및 노드 선택 정합성 검증
        Assert.Equal(CockpitViewType.ProcessGraph, vm.CurrentView);
        Assert.NotNull(vm.SelectedProcessNode);
        Assert.Equal((uint)1234, vm.SelectedProcessNode.ProcessId);
        Assert.Equal((uint)2, vm.SelectedProcessNode.TokenElevationType);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestMainViewModel_ManualActuation_SuspendResumeTerminateCommands()
    {
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();
        var sensorController = SensorProcessController.Instance;
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, [], geminiApiKey: string.Empty);
        var labRunner = new AttackLabScenarioRunner(treeManager, agent);

        MitigationCommand? lastSentCommand = null;
        uiBridge.ManualCommandSender = cmd =>
        {
            lastSentCommand = cmd;
            return Task.CompletedTask;
        };

        treeManager.ApplySnapshotBatch(
        [
            new ProcessEvent
            {
                ProcessId = 5678,
                ParentProcessId = 4,
                ImageName = "target1.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            },
            new ProcessEvent
            {
                ProcessId = 5679,
                ParentProcessId = 4,
                ImageName = "target2.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        ]);

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge, sensorController, labRunner);
        var node1 = treeManager.FindNodeByPid(5678);
        var node2 = treeManager.FindNodeByPid(5679);
        Assert.NotNull(node1);
        Assert.NotNull(node2);

        // 초기 상태 검증 (로컬 OS 스냅샷 반영)
        int initialMonitoredCount = vm.MonitoredProcessCount;
        Assert.True(initialMonitoredCount > 0);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);
        Assert.Equal(0, vm.TotalRestoredCount);
        Assert.Equal(0, vm.TotalTerminatedCount);

        // ==========================================
        // [시나리오 1: 노드 1 - Gauge 반복 동결/해제 및 자연 종료 검증]
        // ==========================================
        vm.SelectedProcessNode = node1;

        // 1-1. 최초 동결 ➔ FROZEN: 1, RESTORED: 0
        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.NotNull(lastSentCommand);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionSuspend, lastSentCommand.Action);
        Assert.Equal((uint)5678, lastSentCommand.TargetPid);
        Assert.True(node1.IsSuspended);
        Assert.Contains("동결", node1.StatusBadge);
        Assert.Equal(1, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);
        Assert.Equal(0, vm.TotalTerminatedCount);
        Assert.Equal(initialMonitoredCount, vm.MonitoredProcessCount);

        // 1-2. 최초 해제 ➔ FROZEN: 0, RESTORED: 1
        lastSentCommand = null;
        await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
        Assert.NotNull(lastSentCommand);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionResume, lastSentCommand.Action);
        Assert.Equal((uint)5678, lastSentCommand.TargetPid);
        Assert.False(node1.IsSuspended);
        Assert.True(node1.IsRestored);
        Assert.Equal("[실시간 가동 중]", node1.StatusBadge);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(1, vm.ActiveRestoredCount);
        Assert.Equal(0, vm.TotalTerminatedCount);
        Assert.Equal(initialMonitoredCount, vm.MonitoredProcessCount);

        // 1-3. 재동결 (복원 상태 ➔ 동결 전이) ➔ FROZEN: 1, RESTORED: 0 (Gauge 회수 검증)
        lastSentCommand = null;
        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.Equal(1, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount); // 복원 유지 수가 다시 0으로 회수됨!

        // 1-4. 재해제 ➔ FROZEN: 0, RESTORED: 1 (무한 증가하지 않고 상한 1 유지 검증)
        lastSentCommand = null;
        await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(1, vm.ActiveRestoredCount); // 2가 아닌 1 유지!

        // 1-5. 3회 추가 반복 동결/해제 루프 ➔ RESTORED가 절대 2 이상 증가하지 않음을 증명
        for (int i = 0; i < 3; i++)
        {
            await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
            Assert.Equal(1, vm.ActiveSuspendedCount);
            Assert.Equal(0, vm.ActiveRestoredCount);

            await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
            Assert.Equal(0, vm.ActiveSuspendedCount);
            Assert.Equal(1, vm.ActiveRestoredCount);
        }

        // 1-6. 복원 상태 프로세스의 자연 종료(LifecycleStop) ➔ RESTORED: 0 회수 및 MONITORED 차감
        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 5678,
            Lifecycle = ProcessLifecycle.LifecycleStop,
            TimestampNs = 8888
        });
        Assert.False(node1.IsAlive);
        Assert.False(node1.IsRestored);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount); // 자연 종료 시 실시간 Gauge 0으로 회수!
        Assert.Equal(initialMonitoredCount - 1, vm.MonitoredProcessCount);

        // ==========================================
        // [시나리오 2: 노드 2 - 동결 중 직접 사살 및 사망 가드/배지 보존 검증]
        // ==========================================
        vm.SelectedProcessNode = node2;

        // 2-1. 노드 2 동결 ➔ FROZEN: 1, RESTORED: 0
        lastSentCommand = null;
        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.Equal(1, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);

        // 2-2. 동결 중 직접 사살 ➔ FROZEN: 0 (즉시 반환), TERMINATED: 1, MONITORED 차감
        lastSentCommand = null;
        await vm.TerminateSelectedProcessCommand.ExecuteAsync(null);
        Assert.NotNull(lastSentCommand);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, lastSentCommand.Action);
        Assert.Equal((uint)5679, lastSentCommand.TargetPid);
        Assert.True(node2.IsTerminated);
        Assert.False(node2.IsAlive);
        Assert.False(node2.IsRestored);
        Assert.Contains("사살", node2.StatusBadge);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);
        Assert.Equal(1, vm.TotalTerminatedCount);
        Assert.Equal(initialMonitoredCount - 2, vm.MonitoredProcessCount);

        // 2-3. 사망 노드에 대한 추가 동결/해제/사살 실행 가드 차단 검증
        lastSentCommand = null;
        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(lastSentCommand);
        await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(lastSentCommand);
        await vm.TerminateSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(lastSentCommand);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);
        Assert.Equal(1, vm.TotalTerminatedCount);
        Assert.Equal(initialMonitoredCount - 2, vm.MonitoredProcessCount);

        // 2-4. 사살 노드에 ETW LifecycleStop 이벤트 수신 시 [현장 사살] 배지 보존 검증
        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 5679,
            Lifecycle = ProcessLifecycle.LifecycleStop,
            TimestampNs = 9999
        });
        Assert.True(node2.IsTerminated);
        Assert.False(node2.IsAlive);
        Assert.Contains("사살", node2.StatusBadge);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TestProcessTree_NormalizeProcessImageName_StripsNtAndDosPaths()
    {
        // 1. NT 디바이스 경로 정제
        string ntPath = @"\Device\HarddiskVolume3\Program Files\Git\cmd\git.exe";
        Assert.Equal("git.exe", ProcessTreeProjectionManager.NormalizeProcessImageName(100, ntPath));

        // 2. Win32 DOS 경로 정제
        string dosPath = @"C:\Windows\System32\conhost.exe";
        Assert.Equal("conhost.exe", ProcessTreeProjectionManager.NormalizeProcessImageName(200, dosPath));

        // 3. 슬래시 혼용 경로 정제
        string slashPath = "C:/Program Files/App/app.exe";
        Assert.Equal("app.exe", ProcessTreeProjectionManager.NormalizeProcessImageName(300, slashPath));

        // 4. 순수 파일명 유지
        Assert.Equal("powershell.exe", ProcessTreeProjectionManager.NormalizeProcessImageName(400, "powershell.exe"));

        // 5. PID 0 System Idle Process
        Assert.Equal("System Idle Process", ProcessTreeProjectionManager.NormalizeProcessImageName(0, ""));
        Assert.Equal("System Idle Process", ProcessTreeProjectionManager.NormalizeProcessImageName(10, "[System Process]"));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TestProcessTree_HideTerminatedProcesses_FilterAndPreserveAncestry()
    {
        var treeManager = new ProcessTreeProjectionManager();

        treeManager.ApplySnapshotBatch(
        [
            new ProcessEvent { ProcessId = 100, ParentProcessId = 0, ImageName = "root1.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 101, ParentProcessId = 100, ImageName = "child1.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 200, ParentProcessId = 0, ImageName = "root2.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 201, ParentProcessId = 200, ImageName = "child2.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 202, ParentProcessId = 201, ImageName = "grandchild.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
            new ProcessEvent { ProcessId = 300, ParentProcessId = 0, ImageName = "root3.exe", Lifecycle = ProcessLifecycle.LifecycleSnapshot },
        ]);

        foreach (var node in treeManager.AllNodes)
        {
            node.IsExpanded = true;
        }

        var child1 = treeManager.FindNodeByPid(101)!;
        child1.IsAlive = false;
        var root2 = treeManager.FindNodeByPid(200)!;
        root2.IsAlive = false;
        var grandChild = treeManager.FindNodeByPid(202)!;
        grandChild.IsAlive = false;
        var root3 = treeManager.FindNodeByPid(300)!;
        root3.IsAlive = false;

        // A) 필터링 OFF 상태 (기본): 모든 노드가 가시화 목록에 포함
        treeManager.HideTerminated = false;
        treeManager.RebuildVisibleNodes();
        Assert.Equal(6, treeManager.VisibleNodes.Count);

        // B) 필터링 ON 상태:
        // - Root1 (Alive): 포함
        // - Child1 (Stopped, 자식 없음): 제외
        // - Root2 (Stopped, 하위에 살아있는 Child2 존재): 족보 유지를 위해 포함
        // - Child2 (Alive): 포함
        // - GrandChild (Stopped, 자식 없음): 제외
        // - Root3 (Stopped, 자식 없음): 제외
        treeManager.HideTerminated = true;
        treeManager.RebuildVisibleNodes();

        var visiblePids = treeManager.VisibleNodes.Select(n => n.ProcessId).ToHashSet();
        Assert.Contains((uint)100, visiblePids);
        Assert.DoesNotContain((uint)101, visiblePids);
        Assert.Contains((uint)200, visiblePids); // 고아 방지 보존 확인!
        Assert.Contains((uint)201, visiblePids);
        Assert.DoesNotContain((uint)202, visiblePids);
        Assert.DoesNotContain((uint)300, visiblePids);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TestInvestigation_RealtimeProgressAndTraceStreaming_Lifecycle()
    {
        // 1. Arrange: 테스트용 뷰모델 및 인프라 구성
        var archiveManager = new ForensicArchiveManager();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();
        var sensorController = new SensorProcessController();
        var labRunner = new AttackLabScenarioRunner(treeManager);
        var vm = new MainViewModel(archiveManager, treeManager, uiBridge, sensorController, labRunner);

        var testNode = new ProcessNodeModel
        {
            ProcessId = 9999,
            ImageName = "powershell.exe",
            CommandLine = "powershell.exe -enc test"
        };
        string incidentId = "INC-TEST-STREAM-001";

        // 2. Act: 수사 개시 (InvestigationStarted)
        uiBridge.NotifyInvestigationStarted(testNode, incidentId);

        var incident = Assert.Single(vm.Incidents, x => x.IncidentId == incidentId);
        Assert.True(incident.IsInvestigating);
        Assert.Equal("SUSPENDED", incident.StatusSeverity);
        Assert.Contains("수사 착수", incident.FormattedLatency);

        // 3. 실시간 경과 시간 통지 검증 ([NotifyPropertyChangedFor] 동작 확인)
        bool latencyChanged = false;
        incident.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(IncidentItemViewModel.FormattedLatency))
            {
                latencyChanged = true;
            }
        };
        incident.ActiveElapsedSeconds = 1.5;
        Assert.True(latencyChanged);
        Assert.Contains("1.5s", incident.FormattedLatency);

        // 4. 실시간 ReAct 턴 스트리밍 1: DecodePayloadTool 완료
        var trace1 = new ReActTraceRecord
        {
            IncidentId = incidentId,
            StepNumber = 1,
            ActionTool = "DecodePayloadTool",
            Thought = "난독화 명령줄 해독",
            ActionArgsJson = "{}",
            Observation = "해독 결과: http://185.220.101.5",
            ElapsedMs = 2.5
        };
        uiBridge.NotifyReActStepCompleted(incidentId, trace1);

        Assert.Single(incident.Traces);
        Assert.True(incident.Traces[0].IsExpanded);
        Assert.Equal(1, incident.Traces[0].StepNumber);
        Assert.Contains("DecodePayloadTool 완료", incident.InvestigationProgressText);
        Assert.Contains("Turn 1", incident.FormattedLatency);

        // 5. 실시간 ReAct 턴 스트리밍 2: ThreatReputationTool 완료 (이전 턴 자동 접힘, 신규 턴 자동 펼침 확인)
        var trace2 = new ReActTraceRecord
        {
            IncidentId = incidentId,
            StepNumber = 2,
            ActionTool = "ThreatReputationTool",
            Thought = "위협 평판 조회",
            ActionArgsJson = "{}",
            Observation = "위협 점수 98점 (악성 확정)",
            ElapsedMs = 5.0
        };
        uiBridge.NotifyReActStepCompleted(incidentId, trace2);

        Assert.Equal(2, incident.Traces.Count);
        Assert.False(incident.Traces[0].IsExpanded); // 이전 턴 접힘
        Assert.True(incident.Traces[1].IsExpanded);  // 최신 턴 펼침
        Assert.Contains("ThreatReputationTool 완료", incident.InvestigationProgressText);
        Assert.Contains("Turn 2", incident.FormattedLatency);

        // 5-1. 실시간 ReAct 턴 스트리밍 3: 최종 판결 (ActionTool='None' -> FINAL VERDICT 표기 검증)
        var trace3 = new ReActTraceRecord
        {
            IncidentId = incidentId,
            StepNumber = 3,
            ActionTool = "None",
            Thought = "최종 사살 판결 도출",
            ActionArgsJson = "{}",
            Observation = "최종 판결 도출: ACTION_KILL (확신도 99%)",
            ElapsedMs = 1.0
        };
        uiBridge.NotifyReActStepCompleted(incidentId, trace3);

        Assert.Equal(3, incident.Traces.Count);
        Assert.False(incident.Traces[1].IsExpanded);
        Assert.True(incident.Traces[2].IsExpanded);
        Assert.Equal("PHASE 03 : FINAL VERDICT", incident.Traces[2].FormattedStep);
        Assert.Contains("최종 판결", incident.InvestigationProgressText);

        // 6. Act: 수사 완료 (InvestigationCompleted)
        var record = new IncidentRecord
        {
            IncidentId = incidentId,
            Timestamp = DateTime.UtcNow,
            TargetPid = testNode.ProcessId,
            TargetImage = testNode.ImageName,
            CommandLine = testNode.CommandLine,
            VerdictAction = "ACTION_KILL",
            ConfidenceScore = 0.99,
            SummaryTitle = "악성 C2 파워셸 침투 탐지 및 격리 사살",
            Narrative = "AI 수사관이 난독화 해독 및 위협 조회를 거쳐 사살 판결을 내렸습니다.",
            MitreTactics = new() { "T1059.001" },
            ElapsedMs = 15.0
        };

        var invResult = new InvestigationResult(
            incidentId,
            MitigationCommand.Types.ActionType.ActionKill,
            0.99,
            record.SummaryTitle,
            record.Narrative,
            record.MitreTactics,
            "185.220.101.5",
            new List<ReActTraceRecord> { trace1, trace2, trace3 },
            TimeSpan.FromMilliseconds(15.0),
            record,
            new()
        );
        uiBridge.NotifyInvestigationCompleted(invResult);

        // 7. Assert: 수사 완료 후 상태 보존 및 심층수사실(SelectedIncident) 유지 검증
        Assert.False(incident.IsInvestigating);
        Assert.Empty(incident.InvestigationProgressText);
        Assert.Equal("CRITICAL", incident.StatusSeverity);
        Assert.Equal(3, incident.Traces.Count);
        Assert.True(incident.Traces[2].IsExpanded); // 아코디언 상태 보존 (Traces.Clear()로 인한 강제 초기화 방지)
        Assert.Contains("15.0ms", incident.FormattedLatency);

        // 핵심 검증: 수사 종료 후 SelectedIncident가 null로 유실되지 않고 유지되는지 확인 (심층수사실 빈 화면 버그 방어)
        Assert.NotNull(vm.SelectedIncident);
        Assert.Same(incident, vm.SelectedIncident);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestAttackLab_NewScenarios_EvasionAndDetection_Verdicts()
    {
        // 1. Arrange: 5대 포렌식 도구를 장착한 오프라인 자율 위협 헌터 에이전트 구성
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool()
        };
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
        var labRunner = new AttackLabScenarioRunner(treeManager, agent);

        // 2. [시나리오 #7] SCCM 유지보수 스크립트 ➔ ACTION_RESUME (오탐 방지)
        var sc7 = AttackScenarioRegistry.FindById(7);
        Assert.NotNull(sc7);
        var res7 = await labRunner.ExecuteScenarioAsync(sc7, AttackLabMode.CleanRoom);
        Assert.True(res7.IsPass);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionResume, res7.ActualAction);
        Assert.Equal("ACTION_RESUME", res7.ExpectedAction);

        // 3. [시나리오 #8] 개발 도구 루프백 IPC ➔ ACTION_RESUME (개발자 워크플로우 보존)
        var sc8 = AttackScenarioRegistry.FindById(8);
        Assert.NotNull(sc8);
        var res8 = await labRunner.ExecuteScenarioAsync(sc8, AttackLabMode.CleanRoom);
        Assert.True(res8.IsPass);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionResume, res8.ActualAction);
        Assert.Equal("ACTION_RESUME", res8.ExpectedAction);

        // 4. [시나리오 #9] LOLBAS Rundll32 프록시 공격 ➔ ACTION_KILL (은폐 회피 차단)
        var sc9 = AttackScenarioRegistry.FindById(9);
        Assert.NotNull(sc9);
        var res9 = await labRunner.ExecuteScenarioAsync(sc9, AttackLabMode.CleanRoom);
        Assert.True(res9.IsPass);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res9.ActualAction);
        Assert.Equal("ACTION_KILL", res9.ExpectedAction);

        // 5. [시나리오 #10] Process Injection VAD 인메모리 위협 ➔ ACTION_KILL (메모리 주입 적발)
        var sc10 = AttackScenarioRegistry.FindById(10);
        Assert.NotNull(sc10);
        var res10 = await labRunner.ExecuteScenarioAsync(sc10, AttackLabMode.CleanRoom);
        Assert.True(res10.IsPass);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, res10.ActualAction);
        Assert.Equal("ACTION_KILL", res10.ExpectedAction);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestAttackLab_AllTenScenarios_FullChainBatch_Passes100Percent()
    {
        // 1. Arrange: 10개 전 시나리오 일괄 회귀 테스트 인프라 구성
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var uiBridge = new CockpitUiBridge();
        var sensorController = new SensorProcessController();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool()
        };
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
        var labRunner = new AttackLabScenarioRunner(treeManager, agent);
        var vm = new MainViewModel(archiveManager, treeManager, uiBridge, sensorController, labRunner);

        // 2. Act: 1~10번 전 시나리오 일괄 회귀 테스트 실행
        await vm.RunAllScenariosBatchCommand.ExecuteAsync(null);

        // 3. Assert: 10개 시나리오 100% 전원 PASS 검증
        Assert.Equal("PASS", vm.LatestVerdictStatus);
        Assert.Contains("10개 중 10개 통과", vm.SimulatorLog);
        Assert.Contains("100.0%", vm.LatestAssertionText);
        Assert.Equal(10, vm.Scenarios.Count(s => s.Id != MainViewModel.CustomScenarioId));
    }
}


