using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.Config;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;

namespace Phalanx.Cockpit.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly AutonomousHunterAgent? _agent;
    private readonly ForensicArchiveManager? _archiveManager;
    private readonly CockpitUiBridge _uiBridge;
    private readonly SensorProcessController _sensorController;
    private readonly AttackLabScenarioRunner? _labRunner;

    public event Action? RequestClose;

    // =========================================================================
    // Category Navigation State
    // =========================================================================
    [ObservableProperty]
    private string _selectedCategory = "AI"; // "AI", "SENSOR", "STORAGE", "THEME", "INFO"

    public bool IsCategoryAi => SelectedCategory == "AI";
    public bool IsCategorySensor => SelectedCategory == "SENSOR";
    public bool IsCategoryStorage => SelectedCategory == "STORAGE";
    public bool IsCategoryTheme => SelectedCategory == "THEME";
    public bool IsCategoryInfo => SelectedCategory == "INFO";

    partial void OnSelectedCategoryChanged(string value)
    {
        OnPropertyChanged(nameof(IsCategoryAi));
        OnPropertyChanged(nameof(IsCategorySensor));
        OnPropertyChanged(nameof(IsCategoryStorage));
        OnPropertyChanged(nameof(IsCategoryTheme));
        OnPropertyChanged(nameof(IsCategoryInfo));
    }

    // =========================================================================
    // Theme & UI Appearance Observables
    // =========================================================================
    [ObservableProperty]
    private string _selectedThemeMode = "System"; // "System", "Dark", "Light"

    public bool IsThemeSystem
    {
        get => SelectedThemeMode == "System";
        set
        {
            if (value && SelectedThemeMode != "System")
            {
                SelectedThemeMode = "System";
            }
        }
    }

    public bool IsThemeDark
    {
        get => SelectedThemeMode == "Dark";
        set
        {
            if (value && SelectedThemeMode != "Dark")
            {
                SelectedThemeMode = "Dark";
            }
        }
    }

    public bool IsThemeLight
    {
        get => SelectedThemeMode == "Light";
        set
        {
            if (value && SelectedThemeMode != "Light")
            {
                SelectedThemeMode = "Light";
            }
        }
    }

    public bool IsCurrentThemeActuallyDark => ThemeManager.Instance.IsDark;

    partial void OnSelectedThemeModeChanged(string value)
    {
        OnPropertyChanged(nameof(IsThemeSystem));
        OnPropertyChanged(nameof(IsThemeDark));
        OnPropertyChanged(nameof(IsThemeLight));

        if (Enum.TryParse<AppThemeMode>(value, true, out var mode))
        {
            ThemeManager.Instance.ApplyTheme(mode);
        }
        OnPropertyChanged(nameof(IsCurrentThemeActuallyDark));
    }

    [RelayCommand]
    private void SetThemeMode(string mode)
    {
        SelectedThemeMode = mode;
    }

    // =========================================================================
    // 1. AI Hunter & LLM Configuration Observables
    // =========================================================================
    [ObservableProperty]
    private bool _useVertexAi = true;

    public bool IsApiKeyMode
    {
        get => !UseVertexAi;
        set
        {
            if (value && UseVertexAi)
            {
                UseVertexAi = false;
            }
            else if (!value && !UseVertexAi)
            {
                UseVertexAi = true;
            }
        }
    }

    partial void OnUseVertexAiChanged(bool value)
    {
        OnPropertyChanged(nameof(IsApiKeyMode));
        OnPropertyChanged(nameof(ActiveAiModelText));
    }

    partial void OnSelectedModelChanged(string value) => OnPropertyChanged(nameof(ActiveAiModelText));
    partial void OnSensorHostChanged(string value) => OnPropertyChanged(nameof(ActiveSensorEndpointText));
    partial void OnSensorPortChanged(int value) => OnPropertyChanged(nameof(ActiveSensorEndpointText));
    partial void OnDatabasePathChanged(string value)
    {
        UpdateStorageDiagnostics();
        OnPropertyChanged(nameof(ActiveDatabaseText));
    }

    [ObservableProperty]
    private string _vertexProjectId = "grc0-494913";

    [ObservableProperty]
    private string _vertexLocation = "global";

    [ObservableProperty]
    private string _selectedModel = "gemini-3.7-flash";

    public IReadOnlyList<string> AvailableModels { get; } = new List<string>
    {
        "gemini-3.7-flash",
        "gemini-3.5-flash",
        "gemini-2.5-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro"
    };

    [ObservableProperty]
    private string _credentialsPath = "Config/google-credentials.json";

    partial void OnCredentialsPathChanged(string value)
    {
        try
        {
            string resolved = string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : (Path.IsPathRooted(value) ? value : Path.Combine(AppContext.BaseDirectory, value));
            CredentialsFound = !string.IsNullOrEmpty(resolved) && File.Exists(resolved);
        }
        catch
        {
            CredentialsFound = false;
        }
    }

    [ObservableProperty]
    private bool _credentialsFound;

    [ObservableProperty]
    private string _geminiApiKey = string.Empty;

    partial void OnGeminiApiKeyChanged(string value)
    {
        if (!string.IsNullOrWhiteSpace(value) && UseVertexAi)
        {
            UseVertexAi = false;
        }
        OnPropertyChanged(nameof(ActiveAiModelText));
    }

    [ObservableProperty]
    private int _maxSteps = 5;

    [ObservableProperty]
    private int _watchdogTimeoutSec = 10;

    [ObservableProperty]
    private int _ctsTimeoutSec = 50;

    [ObservableProperty]
    private bool _offlineFallbackEnabled = true;

    [ObservableProperty]
    private bool _failSecureEnabled = true;

    [ObservableProperty]
    private bool _isAgentOnline;

    [ObservableProperty]
    private string _testStatusMessage = string.Empty;

    [ObservableProperty]
    private bool _isTestingConnection;

    // =========================================================================
    // 2. Sensor & Kernel Actuator Observables
    // =========================================================================
    [ObservableProperty]
    private string _sensorHost = "127.0.0.1";

    [ObservableProperty]
    private int _sensorPort = 50051;

    [ObservableProperty]
    private string _sensorBinaryPath = string.Empty;

    [ObservableProperty]
    private bool _sensorBinaryFound;

    [ObservableProperty]
    private bool _isSensorConnected;

    // =========================================================================
    // 3. Storage & Forensic Archive Observables
    // =========================================================================
    [ObservableProperty]
    private string _databasePath = "phalanx_forensics.db";

    [ObservableProperty]
    private string _databaseResolvedPath = string.Empty;

    [ObservableProperty]
    private string _databaseFileSizeText = "0 Bytes";

    [ObservableProperty]
    private bool _databaseFileExists;

    [ObservableProperty]
    private string _reportExportPath = "IncidentReports";

    [ObservableProperty]
    private int _incidentCount;

    // =========================================================================
    // 4. System Information Observables (User-Facing Architecture Specs)
    // =========================================================================
    public string ProductVersionText => "Phalanx EDR v1.0.0";
    public string HostPlatformText => $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription} ({System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture})";
    public string DotNetRuntimeText => $".NET {Environment.Version}";
    /// <summary>
    /// 시스템 정보 탭의 활성 AI 엔진 표시: 입력 폼 값이 아닌 에이전트에 실제 적용된 상태를 표시합니다.
    /// </summary>
    public string ActiveAiModelText => AppliedEngineStatusText;
    public string ActiveSensorEndpointText => $"{SensorHost}:{SensorPort}";
    public string ActiveDatabaseText => !string.IsNullOrWhiteSpace(DatabaseResolvedPath) ? DatabaseResolvedPath : DatabasePath;

    // =========================================================================
    // Applied Runtime Engine State (공급사 중립 표기, 에이전트 실제 상태 기준)
    // =========================================================================
    public string AppliedEngineStatusText
    {
        get
        {
            if (_agent == null) return "LOCAL OFFLINE";
            return _agent.IsOnlineGemini
                ? (string.IsNullOrWhiteSpace(_agent.CurrentModelName) ? "CLOUD LLM" : $"CLOUD LLM ({_agent.CurrentModelName})")
                : "LOCAL OFFLINE";
        }
    }

    public string AppliedEngineDetailText
    {
        get
        {
            if (_agent == null) return "수사 에이전트가 연결되지 않아 로컬 결정론적 엔진 상태로 표시됩니다.";
            if (_agent.IsOnlineGemini)
            {
                return _agent.OfflineFallbackEnabled
                    ? "클라우드 LLM 자율 수사 활성. 호출 실패/지연 시 23ms 로컬 결정론적 엔진으로 자동 폴백합니다."
                    : "클라우드 LLM 자율 수사 활성. 오프라인 폴백 비활성 (장애 시 Fail-Secure 정책 적용).";
            }
            string reason = string.IsNullOrWhiteSpace(_agent.LastClientError) ? "클라우드 LLM 설정 없음" : _agent.LastClientError!;
            return $"클라우드 LLM 비활성 ({reason}). 23ms 로컬 결정론적 엔진으로 수사합니다.";
        }
    }

    [ObservableProperty]
    private string _lastAppliedAtText = string.Empty;

    private void RefreshAppliedEngineState()
    {
        IsAgentOnline = _agent?.IsOnlineGemini ?? false;
        LastAppliedAtText = DateTime.Now.ToString("HH:mm:ss");
        OnPropertyChanged(nameof(IsAgentOnline));
        OnPropertyChanged(nameof(AppliedEngineStatusText));
        OnPropertyChanged(nameof(AppliedEngineDetailText));
        OnPropertyChanged(nameof(ActiveAiModelText));
        _uiBridge?.NotifyEngineConfigurationChanged(AppliedEngineStatusText, IsAgentOnline);
    }

    private void OnAgentConfigurationApplied() => RunOnUi(RefreshAppliedEngineState);

    private static void RunOnUi(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            dispatcher.BeginInvoke(action);
        }
    }

    // =========================================================================
    // AppSettings.json Hot Reload (외부 편집 즉시 반영)
    // =========================================================================
    private FileSystemWatcher? _settingsWatcher;
    private System.Threading.Timer? _settingsReloadDebounce;
    private string? _lastAppliedSettingsHash;

    private static string? ComputeSettingsHash(string path)
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                if (!File.Exists(path)) return null;
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
            }
            catch (IOException)
            {
                Thread.Sleep(50);
            }
            catch
            {
                return null;
            }
        }
        return null;
    }

    private void StartSettingsWatcher()
    {
        try
        {
            string path = GeminiRestClient.SettingsFilePath;
            string? dir = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

            _lastAppliedSettingsHash = ComputeSettingsHash(path);
            _settingsReloadDebounce = new System.Threading.Timer(_ => OnSettingsFileChangedDebounced(), null, Timeout.Infinite, Timeout.Infinite);
            _settingsWatcher = new FileSystemWatcher(dir, Path.GetFileName(path))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName | NotifyFilters.CreationTime
            };
            FileSystemEventHandler onChange = (_, _) => _settingsReloadDebounce?.Change(400, Timeout.Infinite);
            _settingsWatcher.Changed += onChange;
            _settingsWatcher.Created += onChange;
            _settingsWatcher.Renamed += (_, _) => _settingsReloadDebounce?.Change(400, Timeout.Infinite);
            _settingsWatcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine($"[SettingsViewModel] 설정 파일 감시 시작 실패: {ex.Message}");
        }
    }

    private void OnSettingsFileChangedDebounced()
    {
        string? hash = ComputeSettingsHash(GeminiRestClient.SettingsFilePath);
        // 자체 저장(SaveSettings)으로 이미 적용된 내용이거나 실제 내용 변화가 없으면 무시
        if (hash == null || hash == _lastAppliedSettingsHash) return;
        _lastAppliedSettingsHash = hash;
        RunOnUi(ApplyExternalSettingsChange);
    }

    /// <summary>
    /// 설정 파일이 외부에서 변경되었을 때 폼 값, 에이전트, 센서/랩 런타임 파라미터를 즉시 재적용합니다.
    /// </summary>
    public void ApplyExternalSettingsChange()
    {
        LoadCurrentSettings();
        _agent?.ReloadFromSettingsFile();
        ApplySensorAndLabRuntime();
        RefreshAppliedEngineState();
        StatusMessage = $"[{DateTime.Now:HH:mm:ss}] 설정 파일 변경 감지: 즉시 재적용 완료 (수사 엔진: {AppliedEngineStatusText})";
    }

    private void ApplySensorAndLabRuntime()
    {
        _sensorController.Endpoint = $"{SensorHost}:{SensorPort}";
        _sensorController.WatchdogTimeoutSec = WatchdogTimeoutSec;
        _sensorController.ExtendTimeoutSec = CtsTimeoutSec;
        if (_labRunner != null)
        {
            _labRunner.ReportExportDirectory = ReportExportPath;
        }
    }

    // =========================================================================
    // Common Action & Feedback Observables
    // =========================================================================
    [ObservableProperty]
    private string _statusMessage = string.Empty;

    public bool HasStatusMessage => !string.IsNullOrWhiteSpace(StatusMessage);

    partial void OnStatusMessageChanged(string value)
    {
        OnPropertyChanged(nameof(HasStatusMessage));
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    public SettingsViewModel(
        AutonomousHunterAgent? agent = null,
        ForensicArchiveManager? archiveManager = null,
        CockpitUiBridge? uiBridge = null,
        SensorProcessController? sensorController = null,
        AttackLabScenarioRunner? labRunner = null)
    {
        _agent = agent;
        _archiveManager = archiveManager;
        _uiBridge = uiBridge ?? CockpitUiBridge.Instance;
        _sensorController = sensorController ?? SensorProcessController.Instance;
        _labRunner = labRunner;

        if (_agent != null)
        {
            _agent.ConfigurationApplied += OnAgentConfigurationApplied;
        }

        LoadCurrentSettings();
        RefreshAppliedEngineState();

        // 실제 WPF 런타임에서만 설정 파일 감시 (단위 테스트 환경의 공유 파일 간섭 방지)
        if (System.Windows.Application.Current != null && _agent != null)
        {
            StartSettingsWatcher();
        }
    }

    // =========================================================================
    // Methods & Commands
    // =========================================================================
    [RelayCommand]
    private void SelectCategory(string category)
    {
        SelectedCategory = category;
    }

    public void LoadCurrentSettings()
    {
        // 1. Credentials 파일 존재 확인 (실행 폴더 기준 단일 해석)
        string targetCredPath = Path.IsPathRooted(CredentialsPath)
            ? CredentialsPath
            : Path.Combine(AppContext.BaseDirectory, CredentialsPath);
        CredentialsFound = File.Exists(targetCredPath);

        // 2. AppSettings.json 로드 (PhalanxConfigurationManager 단일 공급자)
        try
        {
            var cfg = PhalanxConfigurationManager.Load();

            if (!string.IsNullOrWhiteSpace(cfg.Gemini.ProjectId))
                VertexProjectId = cfg.Gemini.ProjectId;
            if (!string.IsNullOrWhiteSpace(cfg.Gemini.Location))
                VertexLocation = cfg.Gemini.Location;
            if (!string.IsNullOrWhiteSpace(cfg.Gemini.ModelName))
                SelectedModel = cfg.Gemini.ModelName;
            if (!string.IsNullOrWhiteSpace(cfg.Gemini.ApiKey))
                GeminiApiKey = cfg.Gemini.ApiKey;

            UseVertexAi = cfg.Gemini.UseVertexAI;

            if (!string.IsNullOrWhiteSpace(cfg.Gemini.CredentialsPath))
                CredentialsPath = cfg.Gemini.CredentialsPath;

            MaxSteps = Math.Clamp(cfg.Gemini.MaxSteps, 1, 10);
            WatchdogTimeoutSec = Math.Clamp(cfg.Gemini.WatchdogTimeoutSec, 1, 60);
            CtsTimeoutSec = Math.Clamp(cfg.Gemini.CtsTimeoutSec, 5, 120);
            OfflineFallbackEnabled = cfg.Gemini.OfflineFallback;
            FailSecureEnabled = cfg.Gemini.FailSecure;

            if (!string.IsNullOrWhiteSpace(cfg.Sensor.Host))
                SensorHost = cfg.Sensor.Host;
            SensorPort = Math.Clamp(cfg.Sensor.Port, 1024, 65535);

            if (!string.IsNullOrWhiteSpace(cfg.Storage.DatabasePath))
                DatabasePath = cfg.Storage.DatabasePath;
            if (!string.IsNullOrWhiteSpace(cfg.Storage.ReportExportPath))
                ReportExportPath = cfg.Storage.ReportExportPath;

            SelectedThemeMode = string.IsNullOrWhiteSpace(cfg.Theme) ? "System" : cfg.Theme;
        }
        catch { }

        string resolvedCred = Path.IsPathRooted(CredentialsPath)
            ? CredentialsPath
            : Path.Combine(AppContext.BaseDirectory, CredentialsPath);
        CredentialsFound = File.Exists(resolvedCred);


        // 3. 런타임 상태 동기화
        IsAgentOnline = _agent?.IsOnlineGemini ?? false;
        IsSensorConnected = _sensorController.IsSensorRunning;
        string? binPath = _sensorController.ResolveSensorBinaryPath();
        SensorBinaryFound = !string.IsNullOrEmpty(binPath) && File.Exists(binPath);
        SensorBinaryPath = binPath ?? "바이너리 미검출 (out/build/windows-default/...)";
        UpdateStorageDiagnostics();
        OnPropertyChanged(nameof(ActiveAiModelText));
        OnPropertyChanged(nameof(ActiveSensorEndpointText));
        OnPropertyChanged(nameof(ActiveDatabaseText));
    }

    public void UpdateStorageDiagnostics()
    {
        string candidate = DatabasePath;
        string resolved;

        if (Path.IsPathRooted(candidate))
        {
            resolved = candidate;
        }
        else
        {
            string p1 = Path.Combine(Directory.GetCurrentDirectory(), candidate);
            string p2 = Path.Combine(AppContext.BaseDirectory, candidate);

            if (File.Exists(p1))
            {
                resolved = p1;
            }
            else if (File.Exists(p2))
            {
                resolved = p2;
            }
            else
            {
                resolved = p2;
            }
        }

        DatabaseResolvedPath = resolved;
        DatabaseFileExists = File.Exists(resolved);
        OnPropertyChanged(nameof(ActiveDatabaseText));

        if (DatabaseFileExists)
        {
            try
            {
                long bytes = new FileInfo(resolved).Length;
                if (bytes < 1024)
                    DatabaseFileSizeText = $"{bytes} Bytes";
                else if (bytes < 1024 * 1024)
                    DatabaseFileSizeText = $"{bytes / 1024.0:F1} KB";
                else
                    DatabaseFileSizeText = $"{bytes / (1024.0 * 1024.0):F2} MB";
            }
            catch
            {
                DatabaseFileSizeText = "조회 불가";
            }
        }
        else
        {
            DatabaseFileSizeText = "미생성 (0 Bytes)";
        }

        if (_archiveManager != null)
        {
            try
            {
                IncidentCount = _archiveManager.GetAllIncidents().Count;
            }
            catch
            {
                IncidentCount = 0;
            }
        }
    }

    [RelayCommand]
    private void BrowseDatabase()
    {
        var dlg = new OpenFileDialog
        {
            Filter = "LiteDB 포렌식 데이터베이스 (*.db)|*.db|모든 파일 (*.*)|*.*",
            Title = "LiteDB 포렌식 데이터베이스 파일 선택"
        };

        if (dlg.ShowDialog() == true)
        {
            DatabasePath = dlg.FileName;
            UpdateStorageDiagnostics();
            StatusMessage = $"선택된 DB 파일: {Path.GetFileName(DatabasePath)} (재시작 시 적용됩니다)";
        }
    }

    [RelayCommand]
    private void BrowseReportExport()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "침해 보고서 내보내기 디렉터리 선택",
            Multiselect = false
        };

        if (dlg.ShowDialog() == true)
        {
            ReportExportPath = dlg.FolderName;
            StatusMessage = $"선택된 보고서 경로: {ReportExportPath}";
        }
    }

    [RelayCommand]
    private void OpenDatabaseFolder()
    {
        try
        {
            string targetPath = DatabaseResolvedPath;
            if (File.Exists(targetPath))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{targetPath}\"",
                    UseShellExecute = true
                });
            }
            else
            {
                string dir = Path.GetDirectoryName(targetPath) ?? AppContext.BaseDirectory;
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"\"{dir}\"",
                    UseShellExecute = true
                });
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"[탐색기 열기 실패] {ex.Message}";
        }
    }

    [RelayCommand]
    private void OpenReportFolder()
    {
        try
        {
            string dir = Path.IsPathRooted(ReportExportPath)
                ? ReportExportPath
                : Path.Combine(AppContext.BaseDirectory, ReportExportPath);

            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{dir}\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            StatusMessage = $"[폴더 열기 실패] {ex.Message}";
        }
    }

    [RelayCommand]
    private void ClearIncidents()
    {
        if (_archiveManager == null)
        {
            StatusMessage = "포렌식 아카이브 관리자가 초기화되지 않았습니다.";
            return;
        }

        if (System.Windows.Application.Current != null)
        {
            var result = System.Windows.MessageBox.Show(
                "보관된 모든 침해사고 레코드 및 AI ReAct 추론 흔적을 영구 삭제하시겠습니까?\n이 작업은 실행 취소할 수 없습니다.",
                "Phalanx 포렌식 스토리지 초기화",
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Warning);

            if (result != System.Windows.MessageBoxResult.Yes) return;
        }

        try
        {
            int deleted = _archiveManager.ClearAllIncidents();
            IncidentCount = 0;
            UpdateStorageDiagnostics();
            _uiBridge.NotifyIncidentsDatabaseCleared();
            StatusMessage = $"포렌식 데이터베이스 초기화 완료: {deleted}건의 인시던트가 안전하게 삭제되었습니다.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"[초기화 실패] {ex.Message}";
        }
    }

    [RelayCommand]
    private void BrowseCredentials()
    {
        var dlg = new OpenFileDialog
        {
            Filter = "JSON 서비스 계정 키 (*.json)|*.json|모든 파일 (*.*)|*.*",
            Title = "Google Cloud Service Account 키 파일 선택"
        };

        if (dlg.ShowDialog() == true)
        {
            CredentialsPath = dlg.FileName;
            CredentialsFound = File.Exists(CredentialsPath);
            StatusMessage = $"선택된 키 파일: {Path.GetFileName(CredentialsPath)}";
        }
    }

    [RelayCommand]
    private async Task TestConnectionAsync()
    {
        IsTestingConnection = true;
        TestStatusMessage = "연결 시험 중... (Google Cloud 통신 확인)";

        try
        {
            var sw = Stopwatch.StartNew();
            using var http = new HttpClient();

            GeminiRestClient? testClient;
            string? clientError = null;
            if (!UseVertexAi)
            {
                testClient = string.IsNullOrWhiteSpace(GeminiApiKey)
                    ? null
                    : new GeminiRestClient(http, GeminiApiKey, SelectedModel);
                if (testClient == null) clientError = "API Key 모드이지만 API Key가 입력되지 않았습니다.";
            }
            else
            {
                // UI에 입력된 인증 파일 하나만 사용 (다른 위치로 자동 대체하지 않음)
                testClient = GeminiRestClient.TryCreateVertexClient(
                    http, CredentialsPath, VertexProjectId, VertexLocation, SelectedModel, out clientError);
            }

            if (testClient == null)
            {
                TestStatusMessage = $"FAIL: {clientError}";
                return;
            }

            // 단순 핑 호출
            var testHistory = new List<Content>
            {
                new("user", new List<Part> { new Part("Respond with single word: OK") })
            };

            using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(15));
            string resp = await testClient.GenerateContentAsync(testHistory, "You are an automated ping responder.", cts.Token, timeoutMs: 15000);
            sw.Stop();

            TestStatusMessage = $"PASS: LLM 연결 성공! 모델: {testClient.ModelName} (지연시간: {sw.Elapsed.TotalMilliseconds:F0} ms) ➔ 하단의 [저장 및 적용]을 누르면 즉시 수사관에 활성화됩니다.";
            // 연결 테스트는 설정을 적용하지 않으므로 온라인 표시는 실제 에이전트 상태를 그대로 반영
            IsAgentOnline = _agent?.IsOnlineGemini ?? false;
        }
        catch (Exception ex)
        {
            TestStatusMessage = $"FAIL: 연결 오류 - {ex.Message}";
        }
        finally
        {
            IsTestingConnection = false;
        }
    }

    [RelayCommand]
    private void SaveSettings()
    {
        try
        {
            // API Key 직접 인증 모드 판정: 라디오 버튼 선택 또는 유효 API 키 입력 + 인증키 미존재 시 자동 전환
            bool isDirectKeyMode = IsApiKeyMode || (!string.IsNullOrWhiteSpace(GeminiApiKey) && !CredentialsFound);
            if (isDirectKeyMode && UseVertexAi)
            {
                UseVertexAi = false;
            }

            SensorPort = Math.Clamp(SensorPort, 1024, 65535);

            var config = new PhalanxConfiguration
            {
                Gemini = new GeminiSettings
                {
                    ProjectId = VertexProjectId,
                    Location = VertexLocation,
                    ModelName = SelectedModel,
                    CredentialsPath = CredentialsPath,
                    ApiKey = GeminiApiKey,
                    UseVertexAI = UseVertexAi,
                    MaxSteps = MaxSteps,
                    WatchdogTimeoutSec = WatchdogTimeoutSec,
                    CtsTimeoutSec = CtsTimeoutSec,
                    OfflineFallback = OfflineFallbackEnabled,
                    FailSecure = FailSecureEnabled
                },
                Sensor = new SensorSettings
                {
                    Host = SensorHost,
                    Port = SensorPort
                },
                Storage = new StorageSettings
                {
                    DatabasePath = DatabasePath,
                    ReportExportPath = ReportExportPath
                },
                Theme = SelectedThemeMode
            };

            PhalanxConfigurationManager.Save(config);
            string appSettingsFile = PhalanxConfigurationManager.DefaultConfigPath;
            _lastAppliedSettingsHash = ComputeSettingsHash(appSettingsFile);

            // 런타임 컴포넌트 실시간 동기화
            if (_agent != null)
            {
                _agent.ReloadConfiguration(
                    geminiApiKey: isDirectKeyMode ? GeminiApiKey : null,
                    modelName: SelectedModel,
                    useVertexAi: !isDirectKeyMode,
                    maxSteps: MaxSteps,
                    ctsTimeoutSec: CtsTimeoutSec,
                    offlineFallback: OfflineFallbackEnabled,
                    failSecure: FailSecureEnabled,
                    credentialsPath: CredentialsPath,
                    projectId: VertexProjectId,
                    location: VertexLocation
                );
            }

            ApplySensorAndLabRuntime();
            RefreshAppliedEngineState();

            StatusMessage = $"[{DateTime.Now:HH:mm:ss}] 설정 저장 및 즉시 적용 완료 (수사 엔진: {AppliedEngineStatusText})";
        }
        catch (Exception ex)
        {
            StatusMessage = $"[저장 실패] {ex.Message}";
        }
    }

    [RelayCommand]
    private void ResetDefaults()
    {
        UseVertexAi = true;
        VertexProjectId = "grc0-494913";
        VertexLocation = "global";
        SelectedModel = "gemini-3.7-flash";
        CredentialsPath = "Config/google-credentials.json";
        GeminiApiKey = string.Empty;
        MaxSteps = 5;
        WatchdogTimeoutSec = 10;
        CtsTimeoutSec = 50;
        OfflineFallbackEnabled = true;
        FailSecureEnabled = true;

        SensorHost = "127.0.0.1";
        SensorPort = 50051;

        DatabasePath = "phalanx_forensics.db";
        ReportExportPath = "IncidentReports";

        SelectedThemeMode = "System";
        Services.ThemeManager.Instance.ApplyTheme(Services.AppThemeMode.System);

        UpdateStorageDiagnostics();
        OnPropertyChanged(nameof(ActiveAiModelText));
        OnPropertyChanged(nameof(ActiveSensorEndpointText));
        OnPropertyChanged(nameof(ActiveDatabaseText));

        StatusMessage = "설정 파라미터가 엔터프라이즈 기본값으로 초기화되었습니다.";
    }

    [RelayCommand]
    private void Close()
    {
        RequestClose?.Invoke();
    }
}
