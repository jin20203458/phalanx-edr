using System.Diagnostics;
using System.Text;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;
using ActionType = Phalanx.Shared.Protos.MitigationCommand.Types.ActionType;
using Xunit;

namespace Phalanx.Agent.Tests;

public class AutonomousHunterAgentCancellationTests
{
    [Fact]
    [Trait("Category", "Unit")]
    public async Task InvestigateAsync_WhenCancelledEarly_PreservesSuspendedStateAndDoesNotSendKillOrResume()
    {
        // 1. 컴포넌트 셋업 (인메모리 격리)
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();

        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool(),
            new RegistryInspectionTool()
        };

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);

        // 2. 동결 타깃 프로세스 설정
        var targetNode = new ProcessNodeModel
        {
            ProcessId = 8492,
            ParentProcessId = 3104,
            ImageName = "powershell.exe",
            CommandLine = "powershell.exe -enc mockpayload",
            IsSuspended = true
        };

        // 3. 커맨드 전송 추적
        var dispatchedCommands = new List<MitigationCommand>();

        // 4. 사전 취소된 CTS 생성
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // 5. 수사 호출
        var result = await agent.InvestigateAsync(
            targetNode,
            cmd => { dispatchedCommands.Add(cmd); return Task.CompletedTask; },
            cts.Token);

        // 6. 불변식 검증: C++ 센서로 어떠한 사살/해제 명령도 전송되지 않음
        Assert.Empty(dispatchedCommands);

        // 7. 결과 및 아카이브 상태 검증: SUSPENDED 동결 유지 및 안전 보존
        Assert.NotNull(result);
        Assert.Equal(ActionType.ActionSuspend, result.VerdictAction);
        Assert.Equal("사용자 수동 개입에 의한 AI 심층 수사 취소 (동결 유지)", result.SummaryTitle);

        var record = archiveManager.GetIncident(result.IncidentId);
        Assert.NotNull(record);
        Assert.Equal("SUSPENDED", record.VerdictAction);
        Assert.Equal("SUSPENDED_MANUAL_HOLD", record.RemediationStatus);
        Assert.Equal(8492u, record.TargetPid);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task CancelInvestigation_WhenInvokedDuringActiveInvestigation_CancelsAndPreservesSuspendedState()
    {
        // 1. 컴포넌트 셋업
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();

        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool(),
            new FileInspectionTool(),
            new RegistryInspectionTool()
        };

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);

        var targetNode = new ProcessNodeModel
        {
            ProcessId = 9999,
            ParentProcessId = 1000,
            ImageName = "cmd.exe",
            CommandLine = "cmd.exe /c calc.exe",
            IsSuspended = true
        };

        var dispatchedCommands = new List<MitigationCommand>();

        // 2. 수사 시작 시 즉시 CancelInvestigation 트리거
        agent.OnInvestigationStarted += (node, incId) =>
        {
            bool cancelSuccess = agent.CancelInvestigation(incId);
            Assert.True(cancelSuccess);
        };

        // 3. 수사 호출
        var result = await agent.InvestigateAsync(
            targetNode,
            cmd => { dispatchedCommands.Add(cmd); return Task.CompletedTask; });

        // 4. 불변식 검증: 사살/해제 명령 전송 0건 확인
        Assert.Empty(dispatchedCommands);
        Assert.Equal(ActionType.ActionSuspend, result.VerdictAction);

        var record = archiveManager.GetIncident(result.IncidentId);
        Assert.NotNull(record);
        Assert.Equal("SUSPENDED_MANUAL_HOLD", record.RemediationStatus);
    }
}
