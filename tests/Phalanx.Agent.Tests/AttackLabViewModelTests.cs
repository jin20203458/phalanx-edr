using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.ViewModels;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class AttackLabViewModelTests
{
    private AttackLabViewModel CreateViewModel()
    {
        var treeManager = new ProcessTreeProjectionManager();
        var runner = new AttackLabScenarioRunner(treeManager, null);
        var uiBridge = new CockpitUiBridge();
        return new AttackLabViewModel(runner, uiBridge);
    }

    [Fact]
    public void Constructor_InitializesDefaultStateCorrectly()
    {
        var vm = CreateViewModel();

        Assert.Equal(11, vm.Scenarios.Count); // 10 golden + 1 custom studio
        Assert.Equal(AttackLabViewModel.CustomScenarioId, 99);
        Assert.Equal("grpc", vm.SelectedLabMode);
        Assert.True(vm.IsModeGrpc);
        Assert.False(vm.IsModeOs);
        Assert.False(vm.IsModeLive);
        Assert.Equal(0, vm.SelectedLabTab);
        Assert.True(vm.IsGoldenScenariosTab);
        Assert.False(vm.IsCustomStudioTab);
        Assert.False(vm.IsArchitectureGuideVisible);
        Assert.Equal("READY", vm.LatestVerdictStatus);
    }

    [Fact]
    public void SetLabModeCommand_UpdatesModeAndFlags()
    {
        var vm = CreateViewModel();

        vm.SetLabModeCommand.Execute("os");
        Assert.Equal("os", vm.SelectedLabMode);
        Assert.False(vm.IsModeGrpc);
        Assert.True(vm.IsModeOs);
        Assert.False(vm.IsModeLive);

        vm.SetLabModeCommand.Execute("live");
        Assert.Equal("live", vm.SelectedLabMode);
        Assert.False(vm.IsModeGrpc);
        Assert.False(vm.IsModeOs);
        Assert.True(vm.IsModeLive);
    }

    [Fact]
    public void SelectLabTabCommand_SwitchesTabsCorrectly()
    {
        var vm = CreateViewModel();

        vm.SelectLabTabCommand.Execute("1");
        Assert.Equal(1, vm.SelectedLabTab);
        Assert.False(vm.IsGoldenScenariosTab);
        Assert.True(vm.IsCustomStudioTab);

        vm.SelectLabTabCommand.Execute("0");
        Assert.Equal(0, vm.SelectedLabTab);
        Assert.True(vm.IsGoldenScenariosTab);
        Assert.False(vm.IsCustomStudioTab);
    }

    [Theory]
    [InlineData("powershell", "powershell.exe", "winword.exe", "ACTION_KILL")]
    [InlineData("certutil", "certutil.exe", "excel.exe", "ACTION_KILL")]
    [InlineData("rundll32", "rundll32.exe", "cmd.exe", "ACTION_KILL")]
    [InlineData("benign", "powershell.exe", "explorer.exe", "ACTION_RESUME")]
    public void ApplyCustomTemplateCommand_LoadsPresetParameters(string template, string expectedTarget, string expectedParent, string expectedAction)
    {
        var vm = CreateViewModel();

        vm.ApplyCustomTemplateCommand.Execute(template);

        Assert.Equal(expectedTarget, vm.CustomTargetImage);
        Assert.Equal(expectedParent, vm.CustomParentImage);
        Assert.Equal(expectedAction, vm.CustomExpectedAction);
    }

    [Fact]
    public void ClearSimulatorLogCommand_ResetsLogMessage()
    {
        var vm = CreateViewModel();
        vm.SimulatorLog = "Dirty log content";

        vm.ClearSimulatorLogCommand.Execute(null);

        Assert.Contains("방어 검증 로그가 초기화되었습니다", vm.SimulatorLog);
    }
}
