using System.IO;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Cockpit.ViewModels;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class SettingsViewModelTests
{
    [Fact]
    public void TestSettingsViewModel_TwoWayBinding_TogglesAuthModesCorrectly()
    {
        var vm = new SettingsViewModel();

        // 1. 기본 상태: UseVertexAi = true, IsApiKeyMode = false
        vm.UseVertexAi = true;
        Assert.True(vm.UseVertexAi);
        Assert.False(vm.IsApiKeyMode);

        // 2. IsApiKeyMode를 true로 설정 시 (TwoWay 바인딩에 의한 세터 호출)
        vm.IsApiKeyMode = true;
        Assert.False(vm.UseVertexAi);
        Assert.True(vm.IsApiKeyMode);

        // 3. 다시 UseVertexAi를 true로 변경 시
        vm.UseVertexAi = true;
        Assert.True(vm.UseVertexAi);
        Assert.False(vm.IsApiKeyMode);

        // 4. WPF RadioButton 비활성화 시그널(false) 주입 시 무한 루프나 상태 오염이 발생하지 않는지 방어 검증
        vm.IsApiKeyMode = false;
        Assert.True(vm.UseVertexAi);
        Assert.False(vm.IsApiKeyMode);

        vm.UseVertexAi = false;
        Assert.False(vm.UseVertexAi);
        Assert.True(vm.IsApiKeyMode);

        vm.IsApiKeyMode = false;
        Assert.True(vm.UseVertexAi);
        Assert.False(vm.IsApiKeyMode);
    }

    [Fact]
    public void TestSettingsViewModel_CategorySelection_SwitchesProperly()
    {
        var vm = new SettingsViewModel();

        vm.SelectedCategory = "SENSOR";
        Assert.True(vm.IsCategorySensor);
        Assert.False(vm.IsCategoryAi);

        vm.SelectedCategory = "STORAGE";
        Assert.True(vm.IsCategoryStorage);

        vm.SelectedCategory = "INFO";
        Assert.True(vm.IsCategoryInfo);

        vm.SelectedCategory = "AI";
        Assert.True(vm.IsCategoryAi);
    }

    [Fact]
    public void TestSettingsViewModel_DefaultsAndReset()
    {
        var vm = new SettingsViewModel();

        vm.MaxSteps = 9;
        vm.SensorPort = 59999;
        vm.SensorHost = "10.0.0.1";

        vm.ResetDefaultsCommand.Execute(null);

        Assert.Equal(5, vm.MaxSteps);
        Assert.Equal(50051, vm.SensorPort);
        Assert.Equal("127.0.0.1", vm.SensorHost);
    }

    [Fact]
    public void TestSettingsViewModel_SaveSettings_SynchronizesAllComponents()
    {
        string appSettingsFile = Path.Combine(AppContext.BaseDirectory, "AppSettings.json");
        string? originalContent = File.Exists(appSettingsFile) ? File.ReadAllText(appSettingsFile) : null;

        try
        {
            var treeManager = new Phalanx.Cockpit.CQRS.ProcessTreeProjectionManager();
            var archiveManager = Phalanx.Cockpit.Storage.ForensicArchiveManager.CreateInMemory();
            var tools = System.Array.Empty<Phalanx.Cockpit.Tools.IInvestigationTool>();
            var agent = new Phalanx.Cockpit.Agent.AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
            var labRunner = new Phalanx.Cockpit.Services.AttackLabScenarioRunner(treeManager, agent);
            var sensorController = new Phalanx.Cockpit.Services.SensorProcessController();

            var vm = new SettingsViewModel(
                agent: agent,
                archiveManager: null,
                uiBridge: null,
                sensorController: sensorController,
                labRunner: labRunner
            );

            // 변경할 파라미터 지정
            vm.MaxSteps = 8;
            vm.CtsTimeoutSec = 35;
            vm.OfflineFallbackEnabled = false;
            vm.FailSecureEnabled = false;

            vm.SensorHost = "10.0.0.99";
            vm.SensorPort = 52000;
            vm.ReportExportPath = "CustomAuditDir";

            // 저장 커맨드 실행
            vm.SaveSettingsCommand.Execute(null);

            // 검증: AutonomousHunterAgent 반영 확인
            Assert.Equal(8, agent.MaxSteps);
            Assert.Equal(35, agent.CtsTimeoutSec);
            Assert.False(agent.OfflineFallbackEnabled);
            Assert.False(agent.FailSecureEnabled);

            // 검증: SensorProcessController 반영 확인
            Assert.Equal("10.0.0.99:52000", sensorController.Endpoint);
            Assert.Equal(10, sensorController.WatchdogTimeoutSec);
            Assert.Equal(35, sensorController.ExtendTimeoutSec);

            // 검증: AttackLabScenarioRunner 반영 확인
            Assert.Equal("CustomAuditDir", labRunner.ReportExportDirectory);
        }
        finally
        {
            if (originalContent != null)
            {
                File.WriteAllText(appSettingsFile, originalContent);
            }
            else if (File.Exists(appSettingsFile))
            {
                File.Delete(appSettingsFile);
            }
        }
    }

    [Fact]
    public void TestSettingsViewModel_StorageDiagnosticsAndClearIncidents()
    {
        var archiveManager = Phalanx.Cockpit.Storage.ForensicArchiveManager.CreateInMemory();
        var record = new Phalanx.Cockpit.Storage.IncidentRecord
        {
            IncidentId = "INC-STORAGE-TEST-001",
            Timestamp = DateTime.UtcNow,
            TargetPid = 9999,
            TargetImage = "evil.exe",
            CommandLine = "evil.exe --attack",
            VerdictAction = "ACTION_KILL",
            ConfidenceScore = 0.99
        };
        archiveManager.SaveIncident(record);
        Assert.Single(archiveManager.GetAllIncidents());

        var vm = new SettingsViewModel(archiveManager: archiveManager);
        Assert.Equal(1, vm.IncidentCount);
        Assert.False(string.IsNullOrWhiteSpace(vm.DatabaseResolvedPath));
        Assert.False(string.IsNullOrWhiteSpace(vm.DatabaseFileSizeText));

        // 데이터베이스 초기화(ClearAllIncidents) 검증
        int cleared = archiveManager.ClearAllIncidents();
        Assert.Equal(1, cleared);
        Assert.Empty(archiveManager.GetAllIncidents());

        vm.UpdateStorageDiagnostics();
        Assert.Equal(0, vm.IncidentCount);
    }

    [Fact]
    public void TestSettingsViewModel_SystemInformationObservables()
    {
        var vm = new SettingsViewModel();

        // 1. 고정 제품 사양
        Assert.Equal("Phalanx EDR v1.0.0", vm.ProductVersionText);
        Assert.False(string.IsNullOrWhiteSpace(vm.HostPlatformText));
        Assert.StartsWith(".NET ", vm.DotNetRuntimeText);

        // 2. AI 엔진 표시: 입력 폼 값이 아닌 실제 적용 상태 (에이전트 미연결 시 LOCAL OFFLINE, 공급사 명칭 미노출)
        vm.UseVertexAi = true;
        vm.SelectedModel = "gemini-3.7-flash";
        Assert.Equal("LOCAL OFFLINE", vm.ActiveAiModelText);
        Assert.DoesNotContain("Gemini", vm.ActiveAiModelText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Google", vm.ActiveAiModelText, StringComparison.OrdinalIgnoreCase);

        // 3. 센서 IPC 엔드포인트 동적 반영
        vm.SensorHost = "192.168.1.100";
        vm.SensorPort = 50055;
        Assert.Equal("192.168.1.100:50055", vm.ActiveSensorEndpointText);

        // 4. 포렌식 데이터베이스 경로 반영
        vm.DatabasePath = "custom_test.db";
        Assert.Contains("custom_test.db", vm.ActiveDatabaseText);
    }

    [Fact]
    public void TestSettingsViewModel_AppliedEngineState_RefreshesImmediatelyOnReconfiguration()
    {
        var agent = new AutonomousHunterAgent(
            new ProcessTreeProjectionManager(),
            ForensicArchiveManager.CreateInMemory(),
            Array.Empty<IInvestigationTool>(),
            geminiApiKey: string.Empty);
        var vm = new SettingsViewModel(agent);

        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        Assert.False(vm.IsAgentOnline);
        Assert.Equal("LOCAL OFFLINE", vm.AppliedEngineStatusText);

        // 런타임 재구성(설정 저장과 동일 경로) 직후 UI 바인딩 속성이 즉시 갱신되어야 함
        agent.ReloadConfiguration(geminiApiKey: "unit-test-key", modelName: "unit-test-model", useVertexAi: false);

        Assert.True(vm.IsAgentOnline);
        Assert.Equal("CLOUD LLM (unit-test-model)", vm.AppliedEngineStatusText);
        Assert.Contains(nameof(SettingsViewModel.AppliedEngineStatusText), changed);
        Assert.Contains(nameof(SettingsViewModel.IsAgentOnline), changed);

        // 잘못된 인증 파일로 재구성 시 즉시 오프라인 표시 + 사유 노출
        changed.Clear();
        agent.ReloadConfiguration(useVertexAi: true, credentialsPath: "Config/does-not-exist.json");

        Assert.False(vm.IsAgentOnline);
        Assert.Equal("LOCAL OFFLINE", vm.AppliedEngineStatusText);
        Assert.Contains("인증 파일 없음", vm.AppliedEngineDetailText);
        Assert.Contains(nameof(SettingsViewModel.AppliedEngineDetailText), changed);
        Assert.DoesNotContain("Gemini", vm.AppliedEngineDetailText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TestSettingsViewModel_CredentialsFound_RefreshesWhenPathEdited()
    {
        var vm = new SettingsViewModel();
        string tempFile = Path.Combine(Path.GetTempPath(), $"phalanx-cred-{Guid.NewGuid():N}.json");
        File.WriteAllText(tempFile, "{}");
        try
        {
            vm.CredentialsPath = tempFile;
            Assert.True(vm.CredentialsFound);

            vm.CredentialsPath = tempFile + ".missing";
            Assert.False(vm.CredentialsFound);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void TestSettingsViewModel_ThemeCategoryAndModeSelection()
    {
        var vm = new SettingsViewModel();

        vm.SelectedCategory = "THEME";
        Assert.True(vm.IsCategoryTheme);

        vm.SetThemeModeCommand.Execute("Dark");
        Assert.Equal("Dark", vm.SelectedThemeMode);
        Assert.True(vm.IsThemeDark);
        Assert.False(vm.IsThemeLight);

        vm.SetThemeModeCommand.Execute("Light");
        Assert.Equal("Light", vm.SelectedThemeMode);
        Assert.True(vm.IsThemeLight);
        Assert.False(vm.IsThemeDark);

        vm.SetThemeModeCommand.Execute("System");
        Assert.Equal("System", vm.SelectedThemeMode);
        Assert.True(vm.IsThemeSystem);
    }

    [Fact]
    public void TestSettingsWindow_InstantiationAndThemeToggle()
    {
        Exception? error = null;
        var thread = new System.Threading.Thread(() =>
        {
            try
            {
                if (System.Windows.Application.Current == null)
                {
                    _ = new Phalanx.Cockpit.App();
                }
                var vm = new SettingsViewModel();
                var win = new Phalanx.Cockpit.Views.SettingsWindow
                {
                    DataContext = vm
                };
                Assert.NotNull(win);
                Assert.Equal(vm, win.DataContext);

                // 1. 테마 카테고리 전환
                vm.SelectCategoryCommand.Execute("THEME");
                Assert.True(vm.IsCategoryTheme);

                // 2. 윈도우 로드 상태에서 테마 양방향 프로퍼티 토글 검증
                vm.IsThemeDark = true;
                Assert.Equal("Dark", vm.SelectedThemeMode);
                Assert.True(vm.IsThemeDark);

                vm.IsThemeLight = true;
                Assert.Equal("Light", vm.SelectedThemeMode);
                Assert.True(vm.IsThemeLight);

                vm.IsThemeSystem = true;
                Assert.Equal("System", vm.SelectedThemeMode);
                Assert.True(vm.IsThemeSystem);
            }
            catch (Exception ex)
            {
                error = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        thread.SetApartmentState(System.Threading.ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (error != null)
        {
            throw new Exception($"SettingsWindow failed with: {error}");
        }
    }

    [Fact]
    public void TestSettingsViewModel_ApiKeyInput_AutoSwitchesToApiKeyMode()
    {
        var vm = new SettingsViewModel();
        vm.UseVertexAi = true;
        Assert.True(vm.UseVertexAi);
        Assert.False(vm.IsApiKeyMode);

        // API 키 입력 시 자동으로 API Key 모드로 전환 검증
        vm.GeminiApiKey = "AIzaSyTestApiKey12345";
        Assert.False(vm.UseVertexAi);
        Assert.True(vm.IsApiKeyMode);
    }

    [Fact]
    public void TestSettingsViewModel_SaveSettings_DirectApiKey_NotifiesUiBridgeAndTransitionsToOnline()
    {
        string appSettingsFile = Path.Combine(AppContext.BaseDirectory, "AppSettings.json");
        string? originalContent = File.Exists(appSettingsFile) ? File.ReadAllText(appSettingsFile) : null;

        try
        {
            var treeManager = new Phalanx.Cockpit.CQRS.ProcessTreeProjectionManager();
            var archiveManager = Phalanx.Cockpit.Storage.ForensicArchiveManager.CreateInMemory();
            var tools = System.Array.Empty<Phalanx.Cockpit.Tools.IInvestigationTool>();
            var agent = new Phalanx.Cockpit.Agent.AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
            var uiBridge = new Phalanx.Cockpit.Services.CockpitUiBridge();

            string? notifiedStatus = null;
            bool? notifiedOnline = null;
            uiBridge.EngineConfigurationChanged += (status, online) =>
            {
                notifiedStatus = status;
                notifiedOnline = online;
            };

            var vm = new SettingsViewModel(
                agent: agent,
                archiveManager: archiveManager,
                uiBridge: uiBridge,
                sensorController: null,
                labRunner: null
            );

            // 초기 오프라인 확인
            Assert.False(agent.IsOnlineGemini);
            Assert.Equal("LOCAL OFFLINE", vm.AppliedEngineStatusText);

            // 유효 API 키 입력 및 저장
            vm.GeminiApiKey = "AIzaSyValidDummyApiKey";
            vm.SelectedModel = "gemini-3.7-flash";
            vm.SaveSettingsCommand.Execute(null);

            // 검증: 에이전트가 온라인으로 즉시 전환
            Assert.True(agent.IsOnlineGemini);
            Assert.Contains("CLOUD LLM", vm.AppliedEngineStatusText);
            Assert.Contains("gemini-3.7-flash", vm.AppliedEngineStatusText);

            // 검증: UiBridge를 통해 전체 UI로 즉시 브로드캐스트됨
            Assert.NotNull(notifiedStatus);
            Assert.Contains("CLOUD LLM", notifiedStatus);
            Assert.True(notifiedOnline);
        }
        finally
        {
            if (originalContent != null) File.WriteAllText(appSettingsFile, originalContent);
            else if (File.Exists(appSettingsFile)) File.Delete(appSettingsFile);
        }
    }

    [Fact]
    public void TestMainViewModel_LiveEngineProperties_SynchronizeWithSettings()
    {
        var archiveManager = Phalanx.Cockpit.Storage.ForensicArchiveManager.CreateInMemory();
        var treeManager = new Phalanx.Cockpit.CQRS.ProcessTreeProjectionManager();
        var uiBridge = new Phalanx.Cockpit.Services.CockpitUiBridge();
        var tools = System.Array.Empty<Phalanx.Cockpit.Tools.IInvestigationTool>();
        var agent = new Phalanx.Cockpit.Agent.AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);

        var sensorController = new Phalanx.Cockpit.Services.SensorProcessController();
        var labRunner = new Phalanx.Cockpit.Services.AttackLabScenarioRunner(treeManager, agent);
        var settingsVm = new SettingsViewModel(agent, archiveManager, uiBridge);
        var mainVm = new MainViewModel(archiveManager, treeManager, uiBridge, sensorController, labRunner, settingsVm);

        // 초기 상태: 로컬 오프라인
        Assert.Equal("LOCAL OFFLINE", mainVm.CurrentLiveEngineText);
        Assert.False(mainVm.IsCurrentLiveEngineOnline);

        // 설정창에서 API 키 적용
        settingsVm.GeminiApiKey = "AIzaSyTestLiveKey";
        settingsVm.SaveSettingsCommand.Execute(null);

        // 검증: MainViewModel의 LiveEngineText와 IsCurrentLiveEngineOnline이 즉시 CLOUD LLM으로 반영됨
        Assert.Contains("CLOUD LLM", mainVm.CurrentLiveEngineText);
        Assert.True(mainVm.IsCurrentLiveEngineOnline);
    }
}

