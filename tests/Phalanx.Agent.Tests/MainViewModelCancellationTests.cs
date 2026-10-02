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
}
