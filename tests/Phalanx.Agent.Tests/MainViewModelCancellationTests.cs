using System.Diagnostics;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.ViewModels;
using Phalanx.Shared.Protos;
using ActionType = Phalanx.Shared.Protos.MitigationCommand.Types.ActionType;
using Xunit;

namespace Phalanx.Agent.Tests;

public class MainViewModelCancellationTests
{
    [Fact]
    [Trait("Category", "Unit")]
    public void TestInvestigationCompleted_WhenActionSuspend_PreservesSuspendedCountersAndStatusSeverity()
    {
        // 1. 컴포넌트 셋업
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        uint targetPid = 7788;
        string incidentId = "INC-TEST-CANCEL-001";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "suspect.exe",
                CommandLine = "suspect.exe --malicious-flag",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            }
        });

        var targetNode = treeManager.FindNodeByPid(targetPid);
        Assert.NotNull(targetNode);

        // 2. 수사 시작 알림 주입
        uiBridge.NotifyInvestigationStarted(targetNode, incidentId);

        Assert.Equal(1, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);
        Assert.Equal(0, vm.TotalTerminatedCount);

        var incidentItem = vm.SelectedIncident;
        Assert.NotNull(incidentItem);
        Assert.True(incidentItem.IsInvestigating);
        Assert.False(incidentItem.CanManualActuate);

        // 3. 수사 취소(ActionSuspend) 완료 알림 주입
        var cancelledRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            TargetPid = targetPid,
            TargetImage = "suspect.exe",
            CommandLine = "suspect.exe --malicious-flag",
            VerdictAction = "SUSPENDED",
            SummaryTitle = "사용자 수동 개입에 의한 AI 심층 수사 취소 (동결 유지)",
            RemediationStatus = "SUSPENDED_MANUAL_HOLD",
            RemediationSteps = new() { "AI 자율 수사 취소 완료", "관리자 수동 처분 대기" }
        };

        var cancelledResult = new InvestigationResult(
            incidentId,
            ActionType.ActionSuspend,
            0.0,
            cancelledRecord.SummaryTitle,
            "수사 취소 서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(150),
            cancelledRecord,
            cancelledRecord.RemediationSteps
        );

        uiBridge.NotifyInvestigationCompleted(cancelledResult);

        // 4. 불변식 검증: ActiveSuspendedCount 감산 방어 및 복구 카운트 불변
        Assert.Equal(1, vm.ActiveSuspendedCount);
        Assert.Equal(0, vm.ActiveRestoredCount);
        Assert.Equal(0, vm.TotalTerminatedCount);

        // 5. 타깃 노드 동결 유지 검증
        Assert.True(targetNode.IsSuspended);
        Assert.False(targetNode.IsRestored);
        Assert.False(targetNode.IsTerminated);

        // 6. UI 아이템 상태 검증
        Assert.False(incidentItem.IsInvestigating);
        Assert.Equal("SUSPENDED", incidentItem.StatusSeverity);
        Assert.Equal("SUSPENDED", incidentItem.VerdictAction);
        Assert.True(incidentItem.CanManualActuate); // 동결 상태이고 수사 중이 아니므로 수동 처분 활성화
        Assert.Contains("취소됨 (동결 상태 유지)", incidentItem.InvestigationProgressText);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestManualActuation_KillAndResumeCommands()
    {
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();

        MitigationCommand? dispatchedCommand = null;
        uiBridge.ManualCommandSender = cmd =>
        {
            dispatchedCommand = cmd;
            return Task.CompletedTask;
        };

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        uint targetPid = 8899;
        string incidentId = "INC-TEST-MANUAL-001";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "target.exe",
                CommandLine = "target.exe",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            }
        });

        var targetNode = treeManager.FindNodeByPid(targetPid);
        Assert.NotNull(targetNode);

        // 1. 수사 시작 및 취소로 동결 대기 상태 진입
        uiBridge.NotifyInvestigationStarted(targetNode, incidentId);

        var cancelledRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            TargetPid = targetPid,
            TargetImage = "target.exe",
            CommandLine = "target.exe",
            VerdictAction = "SUSPENDED",
            SummaryTitle = "사용자 수동 개입에 의한 AI 심층 수사 취소",
            RemediationStatus = "SUSPENDED_MANUAL_HOLD"
        };
        archiveManager.SaveIncident(cancelledRecord, new List<ReActTraceRecord>());

        var cancelledResult = new InvestigationResult(
            incidentId,
            ActionType.ActionSuspend,
            0.0,
            cancelledRecord.SummaryTitle,
            "서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(50),
            cancelledRecord,
            cancelledRecord.RemediationSteps
        );
        uiBridge.NotifyInvestigationCompleted(cancelledResult);

        Assert.True(vm.SelectedIncident?.CanManualActuate);

        // 2. 관리자 수동 사살(Kill) 커맨드 실행
        await vm.KillSelectedIncidentCommand.ExecuteAsync(null);

        // gRPC 커맨드 전송 및 프로세스 상태 검증
        Assert.NotNull(dispatchedCommand);
        Assert.Equal(ActionType.ActionKill, dispatchedCommand.Action);
        Assert.Equal(targetPid, dispatchedCommand.TargetPid);

        Assert.True(targetNode.IsTerminated);
        Assert.False(targetNode.IsSuspended);
        Assert.Equal(0, vm.ActiveSuspendedCount);
        Assert.Equal(1, vm.TotalTerminatedCount);
        Assert.NotNull(vm.SelectedIncident);
        Assert.Equal("CRITICAL", vm.SelectedIncident.StatusSeverity);

        // 3. 다른 노드로 동결 해제(Resume) 검증
        uint resumePid = 9911;
        string resumeIncidentId = "INC-TEST-MANUAL-002";
        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = resumePid,
                ParentProcessId = 1000,
                ImageName = "benign.exe",
                CommandLine = "benign.exe",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            }
        });

        var resumeNode = treeManager.FindNodeByPid(resumePid);
        Assert.NotNull(resumeNode);

        uiBridge.NotifyInvestigationStarted(resumeNode, resumeIncidentId);

        var resumeCancelledRecord = new IncidentRecord
        {
            IncidentId = resumeIncidentId,
            TargetPid = resumePid,
            TargetImage = "benign.exe",
            CommandLine = "benign.exe",
            VerdictAction = "SUSPENDED",
            SummaryTitle = "사용자 취소",
            RemediationStatus = "SUSPENDED_MANUAL_HOLD"
        };
        archiveManager.SaveIncident(resumeCancelledRecord, new List<ReActTraceRecord>());

        uiBridge.NotifyInvestigationCompleted(new InvestigationResult(
            resumeIncidentId,
            ActionType.ActionSuspend,
            0.0,
            "취소",
            "서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(50),
            resumeCancelledRecord,
            resumeCancelledRecord.RemediationSteps
        ));

        Assert.True(vm.SelectedIncident?.CanManualActuate);

        // 동결 해제 실행
        await vm.ResumeSelectedIncidentCommand.ExecuteAsync(null);

        Assert.NotNull(dispatchedCommand);
        Assert.Equal(ActionType.ActionResume, dispatchedCommand.Action);
        Assert.Equal(resumePid, dispatchedCommand.TargetPid);

        Assert.True(resumeNode.IsRestored);
        Assert.False(resumeNode.IsSuspended);
        Assert.Equal(1, vm.ActiveRestoredCount);
        Assert.NotNull(vm.SelectedIncident);
        Assert.Equal("BENIGN", vm.SelectedIncident.StatusSeverity);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestCancellation_FollowedByFocusProcessInGraph_AllowsActuationViaProcessTreeCommands()
    {
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();

        MitigationCommand? dispatchedCommand = null;
        uiBridge.ManualCommandSender = cmd =>
        {
            dispatchedCommand = cmd;
            return Task.CompletedTask;
        };

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        uint targetPid = 5566;
        string incidentId = "INC-NAV-TREE-001";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "frozen_cmd.exe",
                CommandLine = "frozen_cmd.exe",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            }
        });

        var targetNode = treeManager.FindNodeByPid(targetPid);
        Assert.NotNull(targetNode);

        // 1. 수사 시작 후 사용자 취소
        uiBridge.NotifyInvestigationStarted(targetNode, incidentId);

        var cancelledRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            TargetPid = targetPid,
            TargetImage = "frozen_cmd.exe",
            CommandLine = "frozen_cmd.exe",
            VerdictAction = "SUSPENDED",
            SummaryTitle = "사용자 취소",
            RemediationStatus = "SUSPENDED_MANUAL_HOLD"
        };
        archiveManager.SaveIncident(cancelledRecord, new List<ReActTraceRecord>());

        uiBridge.NotifyInvestigationCompleted(new InvestigationResult(
            incidentId,
            ActionType.ActionSuspend,
            0.0,
            "취소",
            "서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(50),
            cancelledRecord,
            cancelledRecord.RemediationSteps
        ));

        // 2. 유저가 '프로세스 트리로 이동' 버튼 클릭 (FocusProcessInGraphCommand 실행)
        vm.FocusProcessInGraphCommand.Execute(targetPid);

        // 3. 프로세스 트리 뷰로 전환 및 해당 노드 자동 선택 검증
        Assert.Equal(CockpitViewType.ProcessGraph, vm.CurrentView);
        Assert.NotNull(vm.SelectedProcessNode);
        Assert.Equal(targetPid, vm.SelectedProcessNode.ProcessId);
        Assert.True(vm.SelectedProcessNode.IsSuspended);

        // 4. 프로세스 트리 인스펙터의 사살 커맨드(TerminateSelectedProcessCommand)를 통해 사살 집행
        await vm.TerminateSelectedProcessCommand.ExecuteAsync(null);

        Assert.NotNull(dispatchedCommand);
        Assert.Equal(ActionType.ActionKill, dispatchedCommand.Action);
        Assert.Equal(targetPid, dispatchedCommand.TargetPid);
        Assert.True(targetNode.IsTerminated);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestInvestigationCompleted_WhenTerminated_UpdatesProcessNodeToTerminatedAndDisablesButtons()
    {
        // Arrange
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();
        MitigationCommand? dispatchedCommand = null;
        uiBridge.ManualCommandSender = cmd =>
        {
            dispatchedCommand = cmd;
            return Task.CompletedTask;
        };

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);
        uint targetPid = 9999;
        string incidentId = "INC-TEST-KILL-STATE-001";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "powershell.exe",
                CommandLine = "powershell.exe -enc malicious",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            }
        });

        var targetNode = treeManager.FindNodeByPid(targetPid);
        Assert.NotNull(targetNode);

        // 1. 수사 시작: targetNode 상태 검증
        uiBridge.NotifyInvestigationStarted(targetNode, incidentId);
        vm.SelectedProcessNode = targetNode;

        Assert.True(targetNode.IsInvestigating);
        Assert.True(targetNode.IsSuspended);
        Assert.True(targetNode.IsAlive);
        Assert.False(targetNode.IsTerminated);
        Assert.Equal("[원자적 동결 (수사 중)]", targetNode.Status);

        // 2. 수사 중 상태에서 수동 제어 시도 -> 가드에 의해 전송 차단 검증
        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand);
        await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand);
        await vm.TerminateSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand);

        // 3. AI 수사 완료 및 사살(ActionKill) 인입
        var killRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            TargetPid = targetPid,
            TargetImage = "powershell.exe",
            CommandLine = "powershell.exe -enc malicious",
            VerdictAction = "ACTION_KILL",
            RemediationStatus = "SECURED"
        };
        var killResult = new InvestigationResult(
            incidentId,
            ActionType.ActionKill,
            0.99,
            "악성 파워셸 사살",
            "사살 서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(200),
            killRecord,
            killRecord.RemediationSteps
        );

        uiBridge.NotifyInvestigationCompleted(killResult);

        // 4. 불변식 검증: targetNode가 현장 사살 상태로 전이되어야 함
        Assert.False(targetNode.IsInvestigating);
        Assert.False(targetNode.IsAlive);
        Assert.False(targetNode.IsSuspended);
        Assert.True(targetNode.IsTerminated);
        Assert.Equal("[현장 사살]", targetNode.Status);

        // 5. 사살 완료 후 수동 동결/해제/사살 명령 재시도 -> 전부 차단 검증
        dispatchedCommand = null;
        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand);
        await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand);
        await vm.TerminateSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestInvestigationCompleted_WhenResumed_UpdatesProcessNodeToRestoredAndEnablesSuspend()
    {
        // Arrange
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();
        MitigationCommand? dispatchedCommand = null;
        uiBridge.ManualCommandSender = cmd =>
        {
            dispatchedCommand = cmd;
            return Task.CompletedTask;
        };

        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);
        uint targetPid = 8888;
        string incidentId = "INC-TEST-RESUME-STATE-001";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "benign_task.exe",
                CommandLine = "benign_task.exe --check",
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            }
        });

        var targetNode = treeManager.FindNodeByPid(targetPid);
        Assert.NotNull(targetNode);

        // 1. 수사 시작
        uiBridge.NotifyInvestigationStarted(targetNode, incidentId);
        vm.SelectedProcessNode = targetNode;
        Assert.True(targetNode.IsInvestigating);
        Assert.Equal("[원자적 동결 (수사 중)]", targetNode.Status);

        // 2. AI 수사 완료 (정상 판정 복구 ActionResume)
        var resumeRecord = new IncidentRecord
        {
            IncidentId = incidentId,
            TargetPid = targetPid,
            TargetImage = "benign_task.exe",
            CommandLine = "benign_task.exe --check",
            VerdictAction = "ACTION_RESUME",
            RemediationStatus = "RESTORED"
        };
        var resumeResult = new InvestigationResult(
            incidentId,
            ActionType.ActionResume,
            0.98,
            "정상 작업 복구",
            "복구 서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(120),
            resumeRecord,
            resumeRecord.RemediationSteps
        );

        uiBridge.NotifyInvestigationCompleted(resumeResult);

        // 3. 상태 전이 검증: 실시간 가동 중으로 복원
        Assert.False(targetNode.IsInvestigating);
        Assert.True(targetNode.IsAlive);
        Assert.False(targetNode.IsSuspended);
        Assert.True(targetNode.IsRestored);
        Assert.False(targetNode.IsTerminated);
        Assert.Equal("[실시간 가동 중]", targetNode.Status);

        // 4. 가동 중이므로 동결(Suspend) 가능, 동결 해제(Resume)는 이미 해제되었으므로 차단
        dispatchedCommand = null;
        await vm.ResumeSelectedProcessCommand.ExecuteAsync(null);
        Assert.Null(dispatchedCommand); // 이미 가동 중이므로 무시

        await vm.SuspendSelectedProcessCommand.ExecuteAsync(null);
        Assert.NotNull(dispatchedCommand);
        Assert.Equal(ActionType.ActionSuspend, dispatchedCommand.Action);
        Assert.Equal(targetPid, dispatchedCommand.TargetPid);
        Assert.True(targetNode.IsSuspended);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TestInvestigationStarted_WhenBrowsingInvestigationView_PreservesCurrentSelectedIncident()
    {
        // Arrange
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();
        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        var nodeA = new ProcessNodeModel { ProcessId = 1111, ImageName = "incident_a.exe", CommandLine = "incident_a.exe" };
        var nodeB = new ProcessNodeModel { ProcessId = 2222, ImageName = "incident_b.exe", CommandLine = "incident_b.exe" };

        // 1. 사건 A 수사 시작 및 관제사가 심층 수사실(InvestigationView)에서 사건 A를 열람 중
        uiBridge.NotifyInvestigationStarted(nodeA, "INC-AAA-001");
        vm.CurrentView = CockpitViewType.Investigation;
        var selectedBefore = vm.SelectedIncident;
        Assert.NotNull(selectedBefore);
        Assert.Equal("INC-AAA-001", selectedBefore.IncidentId);

        // 2. 다른 새로운 위협 사건 B의 수사가 백그라운드에서 인입
        uiBridge.NotifyInvestigationStarted(nodeB, "INC-BBB-002");

        // 3. 불변식 검증: 관제사의 포렌식 화면이 전환되지 않고 기존 사건 A가 그대로 유지되어야 함
        Assert.NotNull(vm.SelectedIncident);
        Assert.Equal("INC-AAA-001", vm.SelectedIncident.IncidentId);
        Assert.Equal(selectedBefore, vm.SelectedIncident);

        // 사건 목록에는 2개 모두 정상 적재되어 있어야 함
        Assert.Equal(2, vm.Incidents.Count);
        Assert.Equal("INC-BBB-002", vm.Incidents[0].IncidentId);
        Assert.Equal("INC-AAA-001", vm.Incidents[1].IncidentId);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void TestInvestigationCompleted_WhenBrowsingDifferentIncident_PreservesCurrentSelectedIncident()
    {
        // Arrange
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var treeManager = new ProcessTreeProjectionManager();
        var uiBridge = new CockpitUiBridge();
        var vm = new MainViewModel(archiveManager, treeManager, uiBridge);

        var nodeA = new ProcessNodeModel { ProcessId = 3333, ImageName = "viewing_a.exe", CommandLine = "viewing_a.exe" };
        var nodeB = new ProcessNodeModel { ProcessId = 4444, ImageName = "background_b.exe", CommandLine = "background_b.exe" };

        uiBridge.NotifyInvestigationStarted(nodeA, "INC-VIEWING-A");
        uiBridge.NotifyInvestigationStarted(nodeB, "INC-BACKGROUND-B");

        // 관제사가 사건 A를 열람 중
        var itemA = vm.Incidents.First(x => x.IncidentId == "INC-VIEWING-A");
        vm.SelectedIncident = itemA;
        vm.CurrentView = CockpitViewType.Investigation;

        // 사건 B의 AI 수사가 완료되어 알림 인입
        var recordB = new IncidentRecord
        {
            IncidentId = "INC-BACKGROUND-B",
            TargetPid = 4444,
            TargetImage = "background_b.exe",
            VerdictAction = "ACTION_KILL",
            RemediationStatus = "SECURED"
        };
        var resultB = new InvestigationResult(
            "INC-BACKGROUND-B",
            ActionType.ActionKill,
            0.99,
            "B 사살",
            "서사",
            new List<string>(),
            string.Empty,
            new List<ReActTraceRecord>(),
            TimeSpan.FromMilliseconds(50),
            recordB,
            recordB.RemediationSteps
        );
        uiBridge.NotifyInvestigationCompleted(resultB);

        // 불변식 검증: 관제사의 포렌식 화면(사건 A)이 사건 B로 바뀌지 않고 그대로 보존되어야 함
        Assert.NotNull(vm.SelectedIncident);
        Assert.Equal("INC-VIEWING-A", vm.SelectedIncident.IncidentId);

        // 사건 B의 상태는 목록에서 정상적으로 사살 상태로 갱신되어 있어야 함
        var itemB = vm.Incidents.First(x => x.IncidentId == "INC-BACKGROUND-B");
        Assert.Equal("ACTION_KILL", itemB.VerdictAction);
        Assert.Equal("CRITICAL", itemB.StatusSeverity);
    }
}
