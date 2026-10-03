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
    private string _vertexLocation = "us-central1";

    [ObservableProperty]
    private string _selectedModel = "gemini-2.5-flash";

    public IReadOnlyList<string> AvailableModels { get; } = new List<string>
    {
        "gemini-2.5-flash",
        "gemini-2.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-pro"
    };

    [ObservableProperty]
    private string _credentialsPath = "Config/google-credentials.json";

    [ObservableProperty]
    private bool _credentialsFound;

    [ObservableProperty]
    private string _geminiApiKey = string.Empty;

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
    public string ActiveAiModelText => UseVertexAi
        ? $"Google Cloud Vertex AI ({SelectedModel})"
        : $"Google AI Studio ({SelectedModel})";
    public string ActiveSensorEndpointText => $"{SensorHost}:{SensorPort}";
    public string ActiveDatabaseText => !string.IsNullOrWhiteSpace(DatabaseResolvedPath) ? DatabaseResolvedPath : DatabasePath;

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

        LoadCurrentSettings();
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
        // 1. Credentials 파일 존재 확인
        string targetCredPath = Path.Combine(AppContext.BaseDirectory, CredentialsPath);
        if (!File.Exists(targetCredPath))
        {
            targetCredPath = Path.Combine(Directory.GetCurrentDirectory(), CredentialsPath);
        }
        CredentialsFound = File.Exists(targetCredPath) || File.Exists(CredentialsPath);

        // 2. AppSettings.json 로드
        string appSettingsFile = Path.Combine(AppContext.BaseDirectory, "AppSettings.json");
        if (!File.Exists(appSettingsFile))
        {
            appSettingsFile = Path.Combine(Directory.GetCurrentDirectory(), "AppSettings.json");
        }

        if (File.Exists(appSettingsFile))
        {
            try
            {
                var json = File.ReadAllText(appSettingsFile);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                // Vertex / Gemini 섹션 우선 파싱
                JsonElement geminiSec = root;
                if (root.TryGetProperty("Gemini", out var g))
                {
                    geminiSec = g;
                }

                if (geminiSec.TryGetProperty("ProjectId", out var pid) && !string.IsNullOrWhiteSpace(pid.GetString()))
                    VertexProjectId = pid.GetString()!;
                else if (root.TryGetProperty("ProjectId", out var rpid) && !string.IsNullOrWhiteSpace(rpid.GetString()))
                    VertexProjectId = rpid.GetString()!;

                if (geminiSec.TryGetProperty("Location", out var loc) && !string.IsNullOrWhiteSpace(loc.GetString()))
                    VertexLocation = loc.GetString()!;
                else if (root.TryGetProperty("Location", out var rloc) && !string.IsNullOrWhiteSpace(rloc.GetString()))
                    VertexLocation = rloc.GetString()!;

                if (geminiSec.TryGetProperty("ModelName", out var m) && !string.IsNullOrWhiteSpace(m.GetString()))
                    SelectedModel = m.GetString()!;

                if (geminiSec.TryGetProperty("ApiKey", out var k) && !string.IsNullOrWhiteSpace(k.GetString()))
                    GeminiApiKey = k.GetString()!;
                else if (root.TryGetProperty("ApiKey", out var rk) && !string.IsNullOrWhiteSpace(rk.GetString()))
                    GeminiApiKey = rk.GetString()!;

                if (root.TryGetProperty("UseVertexAI", out var uv))
                    UseVertexAi = uv.GetBoolean();
                else if (geminiSec.TryGetProperty("UseVertexAI", out var guv))
                    UseVertexAi = guv.GetBoolean();

                if (geminiSec.TryGetProperty("CredentialsPath", out var cp) && !string.IsNullOrWhiteSpace(cp.GetString()))
                    CredentialsPath = cp.GetString()!;
                if (geminiSec.TryGetProperty("MaxSteps", out var ms) && ms.TryGetInt32(out var msVal))
                    MaxSteps = Math.Clamp(msVal, 1, 10);
                if (geminiSec.TryGetProperty("WatchdogTimeoutSec", out var wt) && wt.TryGetInt32(out var wtVal))
                    WatchdogTimeoutSec = Math.Clamp(wtVal, 1, 60);
                if (geminiSec.TryGetProperty("CtsTimeoutSec", out var ct) && ct.TryGetInt32(out var ctVal))
                    CtsTimeoutSec = Math.Clamp(ctVal, 5, 120);
                if (geminiSec.TryGetProperty("OfflineFallback", out var of))
                    OfflineFallbackEnabled = of.GetBoolean();
                if (geminiSec.TryGetProperty("FailSecure", out var fs))
                    FailSecureEnabled = fs.GetBoolean();

                // Sensor 섹션 파싱
                if (root.TryGetProperty("Sensor", out var sensorSec))
                {
                    if (sensorSec.TryGetProperty("Host", out var sh) && !string.IsNullOrWhiteSpace(sh.GetString()))
                        SensorHost = sh.GetString()!;
                    if (sensorSec.TryGetProperty("Port", out var sp) && sp.TryGetInt32(out var spVal))
                        SensorPort = Math.Clamp(spVal, 1024, 65535);
                }

                // Storage 섹션 파싱
                if (root.TryGetProperty("Storage", out var storageSec))
                {
                    if (storageSec.TryGetProperty("DatabasePath", out var dbp) && !string.IsNullOrWhiteSpace(dbp.GetString()))
                        DatabasePath = dbp.GetString()!;
                    if (storageSec.TryGetProperty("ReportExportPath", out var rep) && !string.IsNullOrWhiteSpace(rep.GetString()))
                        ReportExportPath = rep.GetString()!;
                }

                // Theme 섹션 파싱
                if (root.TryGetProperty("Theme", out var tProp) && !string.IsNullOrWhiteSpace(tProp.GetString()))
                    SelectedThemeMode = tProp.GetString()!;
                else if (root.TryGetProperty("UI", out var uiSec) && uiSec.TryGetProperty("Theme", out var utProp) && !string.IsNullOrWhiteSpace(utProp.GetString()))
                    SelectedThemeMode = utProp.GetString()!;
                else
                    SelectedThemeMode = "System";
            }
            catch { }

            string resolvedCred = Path.IsPathRooted(CredentialsPath)
                ? CredentialsPath
                : Path.Combine(AppContext.BaseDirectory, CredentialsPath);
            CredentialsFound = File.Exists(resolvedCred) || File.Exists(CredentialsPath);
        }

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

            GeminiRestClient? testClient = null;
            if (!UseVertexAi && !string.IsNullOrWhiteSpace(GeminiApiKey))
            {
                testClient = new GeminiRestClient(http, GeminiApiKey, SelectedModel);
            }
            else
            {
                testClient = GeminiRestClient.TryCreateFromLocalConfig(
                    http,
                    SelectedModel,
                    explicitCredentialsPath: CredentialsPath,
                    explicitProjectId: VertexProjectId,
                    explicitLocation: VertexLocation);
            }

            if (testClient == null)
            {
                TestStatusMessage = "FAIL: 인증 설정 생성 실패. google-credentials.json 경로 또는 ProjectId를 확인하십시오.";
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

            TestStatusMessage = $"PASS: Gemini 연결 성공! 모델: {testClient.ModelName} (지연시간: {sw.Elapsed.TotalMilliseconds:F0} ms)";
            IsAgentOnline = true;
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
            string appSettingsFile = Path.Combine(AppContext.BaseDirectory, "AppSettings.json");
            JsonObject rootObj;

            if (File.Exists(appSettingsFile))
            {
                var existingJson = File.ReadAllText(appSettingsFile);
                rootObj = JsonNode.Parse(existingJson)?.AsObject() ?? new JsonObject();
            }
            else
            {
                rootObj = new JsonObject();
            }

            // Gemini 섹션 갱신
            var geminiSec = rootObj["Gemini"] as JsonObject ?? new JsonObject();
            geminiSec["ProjectId"] = VertexProjectId;
            geminiSec["Location"] = VertexLocation;
            geminiSec["ModelName"] = SelectedModel;
            geminiSec["CredentialsPath"] = CredentialsPath;
            geminiSec["ApiKey"] = GeminiApiKey;
            geminiSec["UseVertexAI"] = UseVertexAi;
            geminiSec["MaxSteps"] = MaxSteps;
            geminiSec["WatchdogTimeoutSec"] = WatchdogTimeoutSec;
            geminiSec["CtsTimeoutSec"] = CtsTimeoutSec;
            geminiSec["OfflineFallback"] = OfflineFallbackEnabled;
            geminiSec["FailSecure"] = FailSecureEnabled;

            rootObj["Gemini"] = geminiSec;

            // 하위 호환 필드
            rootObj["ProjectId"] = VertexProjectId;
            rootObj["Location"] = VertexLocation;
            rootObj["ApiKey"] = GeminiApiKey;
            rootObj["UseVertexAI"] = UseVertexAi;

            // 센서 및 스토리지 섹션
            SensorPort = Math.Clamp(SensorPort, 1024, 65535);
            var sensorSec = rootObj["Sensor"] as JsonObject ?? new JsonObject();
            sensorSec["Host"] = SensorHost;
            sensorSec["Port"] = SensorPort;
            rootObj["Sensor"] = sensorSec;

            var storageSec = rootObj["Storage"] as JsonObject ?? new JsonObject();
            storageSec["DatabasePath"] = DatabasePath;
            storageSec["ReportExportPath"] = ReportExportPath;
            rootObj["Storage"] = storageSec;

            rootObj["Theme"] = SelectedThemeMode;

            var opt = new JsonSerializerOptions { WriteIndented = true };
            string output = rootObj.ToJsonString(opt);

            File.WriteAllText(appSettingsFile, output);

            // 소스 디렉터리 AppSettings.json도 존재 시 동시 반영
            string devAppSettings = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\..\src\Phalanx.Cockpit\AppSettings.json"));
            if (File.Exists(devAppSettings))
            {
                try { File.WriteAllText(devAppSettings, output); } catch { }
            }

            // 런타임 컴포넌트 실시간 동기화
            if (_agent != null)
            {
                _agent.ReloadConfiguration(
                    geminiApiKey: UseVertexAi ? null : GeminiApiKey,
                    modelName: SelectedModel,
                    useVertexAi: UseVertexAi,
                    maxSteps: MaxSteps,
                    ctsTimeoutSec: CtsTimeoutSec,
                    offlineFallback: OfflineFallbackEnabled,
                    failSecure: FailSecureEnabled,
                    credentialsPath: CredentialsPath,
                    projectId: VertexProjectId,
                    location: VertexLocation
                );
                IsAgentOnline = _agent.IsOnlineGemini;
            }

            _sensorController.Endpoint = $"{SensorHost}:{SensorPort}";
            _sensorController.WatchdogTimeoutSec = WatchdogTimeoutSec;
            _sensorController.ExtendTimeoutSec = CtsTimeoutSec;

            if (_labRunner != null)
            {
                _labRunner.ReportExportDirectory = ReportExportPath;
            }

            StatusMessage = $"[{DateTime.Now:HH:mm:ss}] 환경 설정이 성공적으로 저장되었습니다. (일부 항목은 재시작 시 적용됩니다)";
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
        VertexLocation = "us-central1";
        SelectedModel = "gemini-2.5-flash";
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
