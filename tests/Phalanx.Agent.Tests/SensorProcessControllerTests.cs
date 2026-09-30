using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.ViewModels;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.CQRS;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class SensorProcessControllerTests
{
    [Fact]
    public void TestSensorProcessController_ResolvesBinaryPathSuccessfully()
    {
        var controller = new SensorProcessController();
        string? binaryPath = controller.ResolveSensorBinaryPath();

        Assert.NotNull(binaryPath);
        Assert.True(File.Exists(binaryPath), $"Resolved sensor path does not exist: {binaryPath}");
        Assert.EndsWith("Phalanx.Sensor.exe", binaryPath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TestSensorProcessController_StopWhenNotRunning_DoesNotThrow()
    {
        var controller = new SensorProcessController();
        var exception = await Record.ExceptionAsync(() => controller.StopSensorAsync());
        Assert.Null(exception);
    }

    [Fact]
    public void TestMainViewModel_SensorToggleText_ReactsToConnectionAndRunningState()
    {
        var uiBridge = new CockpitUiBridge();
        var controller = new SensorProcessController(uiBridge);
        var archive = new ForensicArchiveManager("test_sensor_vm.db");
        var tree = new ProcessTreeProjectionManager();

        var vm = new MainViewModel(archive, tree, uiBridge, controller);

        // 기본 상태: 미연결/미가동
        Assert.False(vm.SensorConnected);
        Assert.Equal("START SENSOR", vm.SensorToggleText);

        // 센서 연결됨
        uiBridge.NotifySensorConnected(true);
        Assert.True(vm.SensorConnected);
        Assert.Equal("STOP SENSOR", vm.SensorToggleText);

        // 센서 연결 끊어짐
        uiBridge.NotifySensorConnected(false);
        Assert.False(vm.SensorConnected);
        Assert.Equal("START SENSOR", vm.SensorToggleText);
    }
}
