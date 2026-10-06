using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Reporting;
using Phalanx.Cockpit.Scenarios;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Shared.Protos;
using ActionType = Phalanx.Shared.Protos.MitigationCommand.Types.ActionType;

namespace Phalanx.Cockpit.ViewModels;

public enum CockpitViewType
{
    Incidents,
    Investigation,
    ProcessGraph
}

/// <summary>
/// Phalanx Enterprise EDR 메인 관제 콕핏 뷰모델
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly ForensicArchiveManager _archiveManager;
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly CockpitUiBridge _uiBridge;
    private readonly SensorProcessController _sensorController;
    private readonly AttackLabScenarioRunner _labRunner;
    private readonly IForensicReportGenerator _reportGenerator;

    [ObservableProperty]
    private CockpitViewType _currentView = CockpitViewType.Incidents;

    [ObservableProperty]
    private ProcessNodeModel? _selectedProcessNode;

    partial void OnSelectedProcessNodeChanged(ProcessNodeModel? value)
    {
        OnPropertyChanged(nameof(HasIncidentForSelectedProcess));
        OnPropertyChanged(nameof(SelectedProcessIncident));
    }

    public bool HasIncidentForSelectedProcess =>
        SelectedProcessNode != null && Incidents.Any(x => x.TargetPid == SelectedProcessNode.ProcessId);

    public IncidentItemViewModel? SelectedProcessIncident =>
        SelectedProcessNode != null ? Incidents.FirstOrDefault(x => x.TargetPid == SelectedProcessNode.ProcessId) : null;

    [ObservableProperty]
    private bool _hideTerminatedProcesses;

    partial void OnHideTerminatedProcessesChanged(bool value)
    {
        _treeManager.HideTerminated = value;
        _treeManager.RebuildVisibleNodes();
        OnPropertyChanged(nameof(VisibleProcesses));
    }

    [ObservableProperty]
    private bool _isSelectionPinned = true;

    public ObservableCollection<ProcessNodeModel> VisibleProcesses => _treeManager.VisibleNodes;

    [RelayCommand]
    private void ToggleExpand(ProcessNodeModel? node)
    {
        if (node != null)
        {
            _treeManager.ToggleNodeExpanded(node);
        }
    }

    public AttackLabViewModel AttackLab { get; }

    public const int CustomScenarioId = AttackLabViewModel.CustomScenarioId;
    public ObservableCollection<AttackScenario> Scenarios => AttackLab.Scenarios;
    public AttackScenario? SelectedScenario
    {
        get => AttackLab.SelectedScenario;
        set => AttackLab.SelectedScenario = value;
    }
    public bool IsCustomScenarioSelected => AttackLab.IsCustomScenarioSelected;
    public bool IsGoldenScenarioSelected => AttackLab.IsGoldenScenarioSelected;

    public string SimulatorLog
    {
        get => AttackLab.SimulatorLog;
        set => AttackLab.SimulatorLog = value;
    }

    public string LatestVerdictStatus => AttackLab.LatestVerdictStatus;
    public string LatestAssertionText => AttackLab.LatestAssertionText;
    public IAsyncRelayCommand RunAllScenariosBatchCommand => AttackLab.RunAllScenariosBatchCommand;

    [ObservableProperty]
    private bool _sensorConnected;

    [ObservableProperty]
    private bool _isSensorRunning;

    public string SensorToggleText => (SensorConnected || IsSensorRunning) ? "STOP SENSOR" : "START SENSOR";

    [ObservableProperty]
    private int _monitoredProcessCount;

    [ObservableProperty]
    private int _activeSuspendedCount;

    [ObservableProperty]
    private int _totalTerminatedCount;

    [ObservableProperty]
    private int _activeRestoredCount;

    public int TotalRestoredCount
    {
        get => ActiveRestoredCount;
        set => ActiveRestoredCount = value;
    }

    partial void OnActiveRestoredCountChanged(int value) => OnPropertyChanged(nameof(TotalRestoredCount));

    [ObservableProperty]
    private string _activeFilter = "ALL"; // ALL, CRITICAL, BENIGN, SUSPENDED

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private IncidentItemViewModel? _selectedIncident;

    partial void OnSelectedIncidentChanged(IncidentItemViewModel? value)
    {
        ExportForensicPdfCommand.NotifyCanExecuteChanged();
    }

    public bool CanExportForensicPdf => SelectedIncident != null && !SelectedIncident.IsInvestigating;

    public ObservableCollection<IncidentItemViewModel> Incidents { get; } = new();
    public ObservableCollection<IncidentItemViewModel> FilteredIncidents { get; } = new();

    public SettingsViewModel Settings { get; }

    public string CurrentLiveEngineText => Settings.AppliedEngineStatusText;
    public bool IsCurrentLiveEngineOnline => Settings.IsAgentOnline;
    public string CurrentLiveEngineTooltip => Settings.AppliedEngineDetailText;

    private System.Windows.Threading.DispatcherTimer? _investigationTimer;

    public MainViewModel(
        ForensicArchiveManager archiveManager,
        ProcessTreeProjectionManager treeManager,
        CockpitUiBridge uiBridge,
        SensorProcessController sensorController,
        AttackLabScenarioRunner labRunner,
        SettingsViewModel? settings = null,
        IForensicReportGenerator? reportGenerator = null)
    {
        _archiveManager = archiveManager;
        _treeManager = treeManager;
        _uiBridge = uiBridge;
        _sensorController = sensorController;
        _labRunner = labRunner;
        _reportGenerator = reportGenerator ?? new ForensicPdfReportGenerator();
        Settings = settings ?? new SettingsViewModel(null, archiveManager, uiBridge, sensorController);
        AttackLab = new AttackLabViewModel(labRunner, uiBridge);

        AttackLab.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(AttackLabViewModel.SimulatorLog))
            {
                OnPropertyChanged(nameof(SimulatorLog));
            }
            else if (e.PropertyName == nameof(AttackLabViewModel.LatestVerdictStatus))
            {
                OnPropertyChanged(nameof(LatestVerdictStatus));
            }
            else if (e.PropertyName == nameof(AttackLabViewModel.LatestAssertionText))
            {
                OnPropertyChanged(nameof(LatestAssertionText));
            }
            else if (e.PropertyName == nameof(AttackLabViewModel.SelectedScenario))
            {
                OnPropertyChanged(nameof(SelectedScenario));
                OnPropertyChanged(nameof(IsCustomScenarioSelected));
                OnPropertyChanged(nameof(IsGoldenScenarioSelected));
            }
        };

        // UI 브리지 및 센서 제어 이벤트 구독
        _uiBridge.SensorConnectionChanged += OnSensorConnectionChanged;
        _uiBridge.ProcessCountUpdated += OnProcessCountUpdated;
        _uiBridge.InvestigationStarted += OnInvestigationStarted;
        _uiBridge.ReActStepCompleted += OnReActStepCompleted;
        _uiBridge.InvestigationCompleted += OnInvestigationCompleted;
        _uiBridge.IncidentsDatabaseCleared += LoadIncidentsFromDatabase;
        _uiBridge.EngineConfigurationChanged += OnEngineConfigurationChanged;
        _treeManager.OnProcessStopped += HandleProcessStopped;

        Settings.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(SettingsViewModel.AppliedEngineStatusText) ||
                e.PropertyName == nameof(SettingsViewModel.IsAgentOnline) ||
                e.PropertyName == nameof(SettingsViewModel.AppliedEngineDetailText))
            {
                OnPropertyChanged(nameof(CurrentLiveEngineText));
                OnPropertyChanged(nameof(IsCurrentLiveEngineOnline));
                OnPropertyChanged(nameof(CurrentLiveEngineTooltip));
            }
        };

        _sensorController.SensorStateChanged += state =>
        {
            IsSensorRunning = state;
            OnPropertyChanged(nameof(SensorToggleText));
        };
        IsSensorRunning = _sensorController.IsSensorRunning;

        // DB로부터 과거 사건 웜업
        LoadIncidentsFromDatabase();

        // C++ 센서 연결 전이라도 로컬 PC 프로세스 트리를 즉시 0초 투영 (오프라인 기본 가시성 확보)
        _treeManager.InitializeFromLocalOsSnapshot();
        MonitoredProcessCount = _treeManager.ActiveCount;

        // 어택랩 기본 시나리오 선택
        SelectedScenario = Scenarios.FirstOrDefault();

        // C++ 커널 센서 기동 시도 (UI 표시 후 UAC 비동기 요청)
        _ = AutoStartSensorAsync();
    }

    public MainViewModel(
        ForensicArchiveManager archiveManager,
        ProcessTreeProjectionManager treeManager,
        CockpitUiBridge uiBridge,
        SensorProcessController? sensorController = null)
        : this(archiveManager, treeManager, uiBridge,
               sensorController ?? SensorProcessController.Instance,
               new AttackLabScenarioRunner(treeManager, null),
               null,
               null)
    {
    }

    private void OnSensorConnectionChanged(bool isConnected)
    {
        SensorConnected = isConnected;
        OnPropertyChanged(nameof(SensorToggleText));
    }

    private void OnProcessCountUpdated(int count)
    {
        MonitoredProcessCount = count;
    }

    private void HandleProcessStopped(ProcessNodeModel node, bool wasSuspended, bool wasRestored)
    {
        void Update()
        {
            if (wasRestored && ActiveRestoredCount > 0)
            {
                ActiveRestoredCount--;
            }
            if (wasSuspended && ActiveSuspendedCount > 0)
            {
                ActiveSuspendedCount--;
            }
            MonitoredProcessCount = _treeManager.ActiveCount;
        }

        var app = Application.Current;
        if (app?.Dispatcher != null && !app.Dispatcher.CheckAccess() && app.Dispatcher.Thread.IsAlive && !app.Dispatcher.HasShutdownStarted)
        {
            _ = app.Dispatcher.InvokeAsync(Update);
        }
        else
        {
            Update();
        }
    }

    private void OnEngineConfigurationChanged(string engineStatus, bool isOnline)
    {
        OnPropertyChanged(nameof(CurrentLiveEngineText));
        OnPropertyChanged(nameof(IsCurrentLiveEngineOnline));
        OnPropertyChanged(nameof(CurrentLiveEngineTooltip));

        // 현재 진행 중인 사건이 있다면 최신 활성 엔진 상태 동기화
        var activeIncident = Incidents.FirstOrDefault(x => x.IsInvestigating);
        if (activeIncident != null)
        {
            activeIncident.InvestigationEngine = isOnline ? "CLOUD_LLM" : "OFFLINE_LOCAL";
        }
    }

    private void OnInvestigationStarted(ProcessNodeModel targetNode, string incidentId)
    {
        if (targetNode.IsRestored && ActiveRestoredCount > 0)
        {
            ActiveRestoredCount--;
        }
        targetNode.IsRestored = false;
        targetNode.IsSuspended = true;
        targetNode.IsInvestigating = true;
        targetNode.RefreshStatusBadge();
        ActiveSuspendedCount++;

        string parentImg = _treeManager.FindActiveNodeByPid(targetNode.ParentProcessId)?.ImageName ?? "System";

        var item = new IncidentItemViewModel
        {
            IncidentId = incidentId,
            Timestamp = DateTime.UtcNow,
            TargetPid = targetNode.ProcessId,
            TargetImage = targetNode.ImageName,
            CommandLine = targetNode.CommandLine,
            ParentPid = targetNode.ParentProcessId,
            ParentImage = parentImg,
            VerdictAction = "SUSPENDED",
            StatusSeverity = "SUSPENDED",
            SummaryTitle = "AI 자율 수사관 심층 조사 진행 중 (Process Frozen)...",
            Narrative = "원자적 프로세스 동결 완료. AI 자율 수사관이 메모리 VAD 및 명령줄 난독화 해독을 조사 중입니다.",
            IsInvestigating = true,
            InvestigationProgressText = "원자적 동결 완료. AI 심층 수사 착수...",
            ActiveElapsedSeconds = 0.0
        };

        Incidents.Insert(0, item);
        ApplyFilter();

        // 관제사가 심층 수사실(InvestigationView)에서 기존 사건을 분석 중일 때는 포렌식 조사 연속성을 위해 화면 유지
        if (CurrentView != CockpitViewType.Investigation || SelectedIncident == null)
        {
            SelectedIncident = item;
        }
        StartInvestigationTimer();
    }

    private void OnReActStepCompleted(string incidentId, ReActTraceRecord trace)
    {
        var existing = Incidents.FirstOrDefault(x => x.IncidentId == incidentId);
        if (existing == null) return;

        // 기존 턴 아코디언은 접고, 신규 생성 턴을 펼침
        foreach (var t in existing.Traces)
        {
            t.IsExpanded = false;
        }

        var stepVm = new ReActStepViewModel
        {
            StepNumber = trace.StepNumber,
            ActionTool = trace.ActionTool,
            Thought = trace.Thought,
            ActionArgsJson = trace.ActionArgsJson,
            Observation = trace.Observation,
            ElapsedMs = trace.ElapsedMs,
            IsExpanded = true
        };
        existing.Traces.Add(stepVm);

        existing.InvestigationProgressText = trace.ActionTool.Equals("None", StringComparison.OrdinalIgnoreCase)
            ? "최종 판결 및 포렌식 서사 종합 중..."
            : $"Turn {trace.StepNumber} • {trace.ActionTool} 완료";
    }

    private void OnInvestigationCompleted(InvestigationResult result)
    {
        if (result.VerdictAction != ActionType.ActionSuspend && ActiveSuspendedCount > 0)
        {
            ActiveSuspendedCount--;
        }

        bool isKill = result.VerdictAction == ActionType.ActionKill;
        bool isSuspend = result.VerdictAction == ActionType.ActionSuspend;
        var targetNode = result.Record?.TargetPid is uint pid ? _treeManager.FindNodeByPid(pid) : null;

        if (isSuspend)
        {
            if (targetNode != null)
            {
                targetNode.IsInvestigating = false;
                targetNode.IsSuspended = true;
                targetNode.IsRestored = false;
                targetNode.IsTerminated = false;
                targetNode.IsAlive = true;
                targetNode.RefreshStatusBadge();
            }
        }
        else if (isKill)
        {
            if (targetNode != null)
            {
                targetNode.IsInvestigating = false;
                targetNode.IsAlive = false;
                targetNode.IsSuspended = false;
                targetNode.IsRestored = false;
                targetNode.IsTerminated = true;
                targetNode.UpdateStatus(ProcessLifecycle.LifecycleTerminated, isSuspended: false, isTerminated: true);
            }
            TotalTerminatedCount++;
        }
        else
        {
            if (targetNode != null)
            {
                targetNode.IsInvestigating = false;
                targetNode.IsAlive = true;
                targetNode.IsSuspended = false;
                targetNode.IsRestored = true;
                targetNode.IsTerminated = false;
                targetNode.UpdateStatus(ProcessLifecycle.LifecycleStart, isSuspended: false, isTerminated: false);
            }
            ActiveRestoredCount++;
        }

        var record = result.Record;
        if (record == null) return;

        // 기존 대기 중 카드 갱신 또는 신규 삽입
        var existing = Incidents.FirstOrDefault(x => x.IncidentId == record.IncidentId || x.TargetPid == record.TargetPid);
        if (existing == null)
        {
            existing = new IncidentItemViewModel();
            Incidents.Insert(0, existing);
        }

        existing.IncidentId = record.IncidentId;
        existing.Timestamp = record.Timestamp;
        existing.TargetPid = record.TargetPid;
        existing.TargetImage = record.TargetImage;
        existing.CommandLine = record.CommandLine;
        existing.ParentImage = record.RootCauseProcess;
        existing.VerdictAction = isKill ? "ACTION_KILL" : isSuspend ? "SUSPENDED" : "ACTION_RESUME";
        existing.StatusSeverity = isKill ? "CRITICAL" : isSuspend ? "SUSPENDED" : "BENIGN";
        existing.ConfidenceScore = result.Confidence;
        existing.SummaryTitle = result.SummaryTitle;
        existing.Narrative = result.Narrative;
        existing.BlockedIp = result.BlockedIp ?? string.Empty;
        existing.InvestigationEngine = !string.IsNullOrEmpty(result.InvestigationEngine)
            ? result.InvestigationEngine
            : (record.InvestigationEngine ?? "CLOUD_LLM");
        existing.FallbackReason = result.FallbackReason ?? record.FallbackReason;
        existing.EngineModel = record.EngineModel;
        existing.ElapsedMs = result.Elapsed.TotalMilliseconds;
        existing.IsInvestigating = false;
        existing.InvestigationProgressText = isSuspend ? "사용자에 의해 AI 조사 취소됨 (동결 상태 유지) ➔ 전역 프로세스 트리에서 사살/해제 가능" : string.Empty;

        // 다중 수사 안전 가드: 타 수사 건이 없으면 틱 타이머 정지
        if (!Incidents.Any(x => x.IsInvestigating && x.IncidentId != record.IncidentId))
        {
            _investigationTimer?.Stop();
        }

        existing.MitreTactics.Clear();
        foreach (var t in result.MitreTactics)
        {
            existing.MitreTactics.Add(t);
        }

        existing.RemediationSteps.Clear();
        foreach (var r in record.RemediationSteps)
        {
            existing.RemediationSteps.Add(r);
        }

        // 아코디언 상태 보존: Traces.Clear() 대신 실시간 미수신 누락분만 보충 추가
        for (int i = existing.Traces.Count; i < result.Traces.Count; i++)
        {
            var tr = result.Traces[i];
            existing.Traces.Add(new ReActStepViewModel
            {
                StepNumber = tr.StepNumber,
                ActionTool = tr.ActionTool,
                Thought = tr.Thought,
                ActionArgsJson = tr.ActionArgsJson,
                Observation = tr.Observation,
                ElapsedMs = tr.ElapsedMs,
                IsExpanded = (i == result.Traces.Count - 1)
            });
        }

        if (existing.Traces.Count > 0 && !existing.Traces.Any(t => t.IsExpanded))
        {
            existing.Traces[^1].IsExpanded = true;
        }

        ApplyFilter();
        // 관제사가 다른 사건을 열람 중인 경우 화면 가로채기 방지 (완료된 사건과 일치하거나 선택이 없을 때만 갱신)
        if (SelectedIncident == null || SelectedIncident.IncidentId == existing.IncidentId)
        {
            SelectedIncident = existing;
            OnPropertyChanged(nameof(SelectedIncident));
        }
        ExportForensicPdfCommand.NotifyCanExecuteChanged();
    }

    private void StartInvestigationTimer()
    {
        if (Application.Current != null)
        {
            if (_investigationTimer == null)
            {
                _investigationTimer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(250)
                };
                _investigationTimer.Tick += OnInvestigationTimerTick;
            }
            if (!_investigationTimer.IsEnabled)
            {
                _investigationTimer.Start();
            }
        }
    }

    private void OnInvestigationTimerTick(object? sender, EventArgs e)
    {
        var now = DateTime.UtcNow;
        bool anyActive = false;
        foreach (var inc in Incidents)
        {
            if (inc.IsInvestigating)
            {
                anyActive = true;
                inc.ActiveElapsedSeconds = (now - inc.Timestamp).TotalSeconds;
            }
        }
        if (!anyActive)
        {
            _investigationTimer?.Stop();
        }
    }

    public void LoadIncidentsFromDatabase()
    {
        try
        {
            var dbIncidents = _archiveManager.GetAllIncidents();
            Incidents.Clear();

            int kills = 0;
            int resumes = 0;

            foreach (var rec in dbIncidents)
            {
                bool isKill = rec.VerdictAction == "ACTION_KILL";
                if (isKill) kills++; else resumes++;

                var item = new IncidentItemViewModel
                {
                    IncidentId = rec.IncidentId ?? string.Empty,
                    Timestamp = rec.Timestamp,
                    TargetPid = rec.TargetPid,
                    TargetImage = rec.TargetImage ?? string.Empty,
                    CommandLine = rec.CommandLine ?? string.Empty,
                    VerdictAction = rec.VerdictAction ?? string.Empty,
                    StatusSeverity = isKill ? "CRITICAL" : "BENIGN",
                    ConfidenceScore = rec.ConfidenceScore,
                    SummaryTitle = rec.SummaryTitle ?? string.Empty,
                    Narrative = rec.Narrative ?? string.Empty,
                    BlockedIp = rec.BlockedIp ?? string.Empty,
                    ParentImage = rec.RootCauseProcess ?? string.Empty,
                    InvestigationEngine = rec.InvestigationEngine ?? "CLOUD_LLM",
                    FallbackReason = rec.FallbackReason,
                    EngineModel = rec.EngineModel
                };

                foreach (var m in rec.MitreTactics)
                {
                    item.MitreTactics.Add(m);
                }

                foreach (var r in rec.RemediationSteps)
                {
                    item.RemediationSteps.Add(r);
                }

                var traces = _archiveManager.GetTracesForIncident(rec.IncidentId ?? string.Empty);
                foreach (var tr in traces)
                {
                    item.Traces.Add(new ReActStepViewModel
                    {
                        StepNumber = tr.StepNumber,
                        ActionTool = tr.ActionTool,
                        Thought = tr.Thought,
                        ActionArgsJson = tr.ActionArgsJson,
                        Observation = tr.Observation,
                        ElapsedMs = tr.ElapsedMs
                    });
                }

                double traceElapsed = traces.Sum(t => t.ElapsedMs);
                item.ElapsedMs = rec.ElapsedMs > 0 ? rec.ElapsedMs : (traceElapsed > 0 ? traceElapsed : 0.08);
                Incidents.Add(item);
            }

            TotalTerminatedCount = kills;
            // Gauge 모델 원칙: ActiveRestoredCount는 현재 살아있는 프로세스의 실시간 복원 상태 수치이므로 과거 DB 사건 수로 덮어쓰지 않고 0으로 시작
            ApplyFilter();

            if (FilteredIncidents.Count > 0 && SelectedIncident == null)
            {
                SelectedIncident = FilteredIncidents[0];
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DB Warmup Error] {ex.Message}");
        }
    }

    [RelayCommand]
    private void SetFilter(string filter)
    {
        ActiveFilter = filter;
        ApplyFilter();
    }

    [RelayCommand]
    private void SelectIncident(IncidentItemViewModel? incident)
    {
        SelectedIncident = incident;
    }

    [RelayCommand]
    private async Task ToggleSensorAsync()
    {
        if (SensorConnected || IsSensorRunning)
        {
            await _sensorController.StopSensorAsync();
        }
        else
        {
            await _sensorController.StartSensorAsync();
        }
    }

    private async Task AutoStartSensorAsync()
    {
        // 단위 테스트 환경 또는 헤드리스 실행 시 UAC 팝업 및 센서 자동 기동 방지
        if (System.Windows.Application.Current == null ||
            AppDomain.CurrentDomain.FriendlyName.Contains("test", StringComparison.OrdinalIgnoreCase) ||
            AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name?.Contains("xunit", StringComparison.OrdinalIgnoreCase) == true))
        {
            return;
        }

        // UI가 완전히 로드된 후 자연스럽게 UAC 승격 팝업을 띄우기 위해 짧은 딜레이 부여
        await Task.Delay(500);
        if (!SensorConnected && !IsSensorRunning)
        {
            await _sensorController.StartSensorAsync();
        }
    }

    [RelayCommand]
    private void RefreshFromDb()
    {
        LoadIncidentsFromDatabase();
    }

    partial void OnSearchQueryChanged(string value)
    {
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var previousSelected = SelectedIncident;
        FilteredIncidents.Clear();
        foreach (var item in Incidents)
        {
            bool matchesCategory = ActiveFilter switch
            {
                "CRITICAL" => item.StatusSeverity == "CRITICAL",
                "BENIGN" => item.StatusSeverity == "BENIGN",
                "SUSPENDED" => item.StatusSeverity == "SUSPENDED",
                _ => true
            };

            if (!matchesCategory) continue;

            if (!string.IsNullOrWhiteSpace(SearchQuery))
            {
                bool matchesSearch = (item.TargetImage?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                     (item.CommandLine?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                     item.TargetPid.ToString().Contains(SearchQuery) ||
                                     (item.SummaryTitle?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                     (item.BlockedIp?.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ?? false);
                if (!matchesSearch) continue;
            }

            FilteredIncidents.Add(item);
        }

        if (previousSelected != null && FilteredIncidents.Contains(previousSelected))
        {
            SelectedIncident = previousSelected;
        }
    }

    [RelayCommand]
    private void SwitchView(string viewName)
    {
        if (Enum.TryParse<CockpitViewType>(viewName, true, out var parsed))
        {
            CurrentView = parsed;
        }
    }

    [RelayCommand]
    private void OpenInvestigation(IncidentItemViewModel? incident)
    {
        if (incident != null)
        {
            SelectedIncident = incident;
        }
        CurrentView = CockpitViewType.Investigation;
    }

    [RelayCommand]
    private void ReturnToIncidents()
    {
        CurrentView = CockpitViewType.Incidents;
    }

    private System.Windows.Window? _attackLabWindow;

    [RelayCommand]
    private void OpenAttackLab()
    {
        if (_attackLabWindow != null && _attackLabWindow.IsLoaded)
        {
            if (_attackLabWindow.WindowState == System.Windows.WindowState.Minimized)
            {
                _attackLabWindow.WindowState = System.Windows.WindowState.Normal;
            }
            _attackLabWindow.Activate();
            return;
        }

        _attackLabWindow = new Views.AttackLabWindow
        {
            DataContext = AttackLab
        };
        _attackLabWindow.Closed += (s, e) => _attackLabWindow = null;
        _attackLabWindow.Show();
    }

    private System.Windows.Window? _settingsWindow;

    [RelayCommand]
    private void OpenSettings()
    {
        if (_settingsWindow != null && _settingsWindow.IsLoaded)
        {
            if (_settingsWindow.WindowState == System.Windows.WindowState.Minimized)
            {
                _settingsWindow.WindowState = System.Windows.WindowState.Normal;
            }
            _settingsWindow.Activate();
            return;
        }

        Settings.LoadCurrentSettings();
        _settingsWindow = new Views.SettingsWindow
        {
            DataContext = Settings,
            Owner = System.Windows.Application.Current?.MainWindow
        };
        _settingsWindow.Closed += (s, e) => _settingsWindow = null;
        _settingsWindow.Show();
    }

    [RelayCommand]
    private void FocusProcessInGraph(uint pid)
    {
        CurrentView = CockpitViewType.ProcessGraph;
        var node = _treeManager.FindNodeByPid(pid);
        if (node != null)
        {
            _treeManager.EnsureNodeVisible(node);
            SelectedProcessNode = node;
        }
    }

    [RelayCommand]
    private void OpenInvestigationForProcess(uint pid)
    {
        var incident = Incidents.FirstOrDefault(x => x.TargetPid == pid);
        if (incident != null)
        {
            SelectedIncident = incident;
            CurrentView = CockpitViewType.Investigation;
        }
    }

    [RelayCommand]
    private async Task SuspendSelectedProcessAsync()
    {
        var node = SelectedProcessNode;
        if (node == null || !node.IsAlive || node.IsSuspended || node.IsInvestigating) return;
        bool wasSuspended = node.IsSuspended;
        bool wasRestored = node.IsRestored;
        var cmd = new MitigationCommand
        {
            Action = ActionType.ActionSuspend,
            TargetPid = node.ProcessId,
            Reason = $"관제사 수동 원자적 동결 (PID: {node.ProcessId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);
        node.UpdateStatus(ProcessLifecycle.LifecycleSuspended, isSuspended: true, isTerminated: false);
        node.IsRestored = false;

        if (wasRestored && ActiveRestoredCount > 0)
        {
            ActiveRestoredCount--;
        }
        if (!wasSuspended)
        {
            ActiveSuspendedCount++;
        }
    }

    [RelayCommand]
    private async Task ResumeSelectedProcessAsync()
    {
        var node = SelectedProcessNode;
        if (node == null || !node.IsAlive || !node.IsSuspended || node.IsInvestigating) return;
        bool wasSuspended = node.IsSuspended;
        var cmd = new MitigationCommand
        {
            Action = ActionType.ActionResume,
            TargetPid = node.ProcessId,
            Reason = $"관제사 수동 동결 해제 (PID: {node.ProcessId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);
        node.UpdateStatus(ProcessLifecycle.LifecycleStart, isSuspended: false, isTerminated: false);
        if (wasSuspended)
        {
            node.IsRestored = true;
            if (ActiveSuspendedCount > 0)
            {
                ActiveSuspendedCount--;
            }
            ActiveRestoredCount++;
        }
    }

    [RelayCommand]
    private async Task TerminateSelectedProcessAsync()
    {
        var node = SelectedProcessNode;
        if (node == null || !node.IsAlive || node.IsTerminated || node.IsInvestigating) return;
        bool wasSuspended = node.IsSuspended;
        bool wasRestored = node.IsRestored;
        var cmd = new MitigationCommand
        {
            Action = ActionType.ActionKill,
            TargetPid = node.ProcessId,
            Reason = $"관제사 수동 긴급 사살 (PID: {node.ProcessId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);
        node.UpdateStatus(ProcessLifecycle.LifecycleTerminated, isSuspended: false, isTerminated: true);
        node.IsRestored = false;

        if (wasSuspended && ActiveSuspendedCount > 0)
        {
            ActiveSuspendedCount--;
        }
        if (wasRestored && ActiveRestoredCount > 0)
        {
            ActiveRestoredCount--;
        }
        TotalTerminatedCount++;
        if (MonitoredProcessCount > 0)
        {
            MonitoredProcessCount--;
        }

        if (HideTerminatedProcesses)
        {
            _treeManager.RebuildVisibleNodes();
        }
    }

    [RelayCommand]
    private void RefreshProcessTree()
    {
        _treeManager.HideTerminated = HideTerminatedProcesses;
        if (!SensorConnected)
        {
            _treeManager.Clear();
            _treeManager.InitializeFromLocalOsSnapshot();
        }
        else
        {
            _treeManager.RebuildVisibleNodes();
        }
        OnPropertyChanged(nameof(VisibleProcesses));
        MonitoredProcessCount = _treeManager.ActiveCount;
    }

    [RelayCommand]
    private void CopyText(string? text)
    {
        if (!string.IsNullOrEmpty(text))
        {
            try
            {
                System.Windows.Clipboard.SetText(text);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Clipboard Error] {ex.Message}");
            }
        }
    }





    [RelayCommand(CanExecute = nameof(CanExportForensicPdf))]
    private async Task ExportForensicPdfAsync()
    {
        var incident = SelectedIncident;
        if (incident == null || incident.IsInvestigating) return;

        try
        {
            string exportDir = string.IsNullOrWhiteSpace(Settings.ReportExportPath)
                ? Path.Combine(AppContext.BaseDirectory, "IncidentReports")
                : (Path.IsPathRooted(Settings.ReportExportPath)
                    ? Settings.ReportExportPath
                    : Path.Combine(AppContext.BaseDirectory, Settings.ReportExportPath));

            string savedPath;
            if (Application.Current != null)
            {
                string safeIncidentId = string.IsNullOrWhiteSpace(incident.IncidentId)
                    ? $"INC-{DateTime.UtcNow:yyyyMMdd-HHmmss}"
                    : string.Join("_", incident.IncidentId.Split(Path.GetInvalidFileNameChars()));
                string defaultFileName = $"Phalanx_Forensic_Report_{safeIncidentId}_{incident.Timestamp:yyyyMMdd_HHmmss}.pdf";

                var saveDialog = new SaveFileDialog
                {
                    Title = "A4 포렌식 리포트 저장 위치 지정",
                    Filter = "PDF Files (*.pdf)|*.pdf|All Files (*.*)|*.*",
                    InitialDirectory = Directory.Exists(exportDir) ? exportDir : AppContext.BaseDirectory,
                    FileName = defaultFileName
                };

                if (saveDialog.ShowDialog() != true)
                {
                    return; // 사용자가 취소함
                }

                string targetFilePath = saveDialog.FileName;
                savedPath = await Task.Run(() => _reportGenerator.ExportReportToFilePath(incident, targetFilePath));
            }
            else
            {
                // Headless/CLI/Unit Test 환경에서는 다이얼로그 없이 기본 디렉터리로 직결 저장
                savedPath = await Task.Run(() => _reportGenerator.ExportReportToFile(incident, exportDir));
            }

            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [포렌식 PDF 리포트 생성 완료] 사건: {incident.IncidentId}\n" +
                            $" ➔ 저장 경로: {savedPath}\n" +
                            $" ➔ 처분: {incident.VerdictAction} (확신도: {incident.ConfidenceDisplay})";

            if (Application.Current != null)
            {
                MessageBox.Show(
                    $"A4 포렌식 보고서가 성공적으로 출력되었습니다.\n\n저장 경로:\n{savedPath}",
                    "Phalanx 포렌식 리포트 출력 완료",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [리포트 출력 오류] {ex.Message}";
            if (Application.Current != null)
            {
                MessageBox.Show(
                    $"보고서 출력 중 오류가 발생하였습니다:\n{ex.Message}",
                    "리포트 출력 실패",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }

    [RelayCommand]
    public void CancelInvestigation(string? incidentId)
    {
        string? targetId = incidentId ?? SelectedIncident?.IncidentId;
        if (string.IsNullOrEmpty(targetId)) return;

        // CockpitUiBridge를 통해 에이전트의 실제 CancellationTokenSource 취소 호출
        bool cancelled = _uiBridge.CancelInvestigation(targetId);

        // 실제 취소 요청이 접수된 경우에만 UI 상태 갱신
        if (cancelled && SelectedIncident != null && SelectedIncident.IncidentId == targetId)
        {
            SelectedIncident.InvestigationProgressText = "사용자에 의해 AI 조사 취소됨 (동결 상태 유지) ➔ 전역 프로세스 트리에서 사살/해제 가능";
            SelectedIncident.IsInvestigating = false;
        }
    }

    [RelayCommand]
    public async Task KillSelectedIncidentAsync()
    {
        if (SelectedIncident == null || !SelectedIncident.CanManualActuate) return;

        uint pid = SelectedIncident.TargetPid;
        string incidentId = SelectedIncident.IncidentId;

        // 1. gRPC 커널 완화 명령 생성 및 전송
        var cmd = new MitigationCommand
        {
            TargetPid = pid,
            Action = MitigationCommand.Types.ActionType.ActionKill,
            Reason = $"관리자 수동 사살 집행 (IncidentId: {incidentId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);

        // 2. 프로세스 트리 노드 상태 갱신
        var node = _treeManager.FindNodeByPid(pid);
        if (node != null)
        {
            node.IsInvestigating = false;
            node.IsAlive = false;
            node.IsSuspended = false;
            node.IsTerminated = true;
            node.UpdateStatus(ProcessLifecycle.LifecycleTerminated, isSuspended: false, isTerminated: true);
        }

        // 3. 뷰모델 상태 갱신
        SelectedIncident.VerdictAction = "ACTION_KILL";
        SelectedIncident.StatusSeverity = "CRITICAL";
        SelectedIncident.InvestigationProgressText = "관리자에 의해 수동 사살 완료";
        SelectedIncident.RemediationSteps.Add($"관리자 수동 사살 완료 (PID: {pid})");

        // 4. 대시보드 통계 카운터 갱신
        if (ActiveSuspendedCount > 0) ActiveSuspendedCount--;
        TotalTerminatedCount++;

        // 5. LiteDB 영속화
        var record = _archiveManager.GetIncident(incidentId);
        if (record != null)
        {
            record.VerdictAction = "ACTION_KILL";
            record.RemediationStatus = "TERMINATED_MANUAL";
            record.RemediationSteps.Add($"관리자 수동 사살 완료 (PID: {pid})");
            _archiveManager.SaveIncident(record, new List<ReActTraceRecord>());
        }

        // 6. 필터 및 뷰 동기화
        ApplyFilter();
    }

    [RelayCommand]
    public async Task ResumeSelectedIncidentAsync()
    {
        if (SelectedIncident == null || !SelectedIncident.CanManualActuate) return;

        uint pid = SelectedIncident.TargetPid;
        string incidentId = SelectedIncident.IncidentId;

        // 1. gRPC 커널 완화 명령 생성 및 전송
        var cmd = new MitigationCommand
        {
            TargetPid = pid,
            Action = MitigationCommand.Types.ActionType.ActionResume,
            Reason = $"관리자 수동 동결 해제 집행 (IncidentId: {incidentId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);

        // 2. 프로세스 트리 노드 상태 갱신
        var node = _treeManager.FindNodeByPid(pid);
        if (node != null)
        {
            node.IsInvestigating = false;
            node.IsAlive = true;
            node.IsSuspended = false;
            node.IsRestored = true;
            node.IsTerminated = false;
            node.UpdateStatus(ProcessLifecycle.LifecycleStart, isSuspended: false, isTerminated: false);
        }

        // 3. 뷰모델 상태 갱신
        SelectedIncident.VerdictAction = "ACTION_RESUME";
        SelectedIncident.StatusSeverity = "BENIGN";
        SelectedIncident.InvestigationProgressText = "관리자에 의해 수동 동결 해제 완료";
        SelectedIncident.RemediationSteps.Add($"관리자 수동 동결 해제 완료 (PID: {pid})");

        // 4. 대시보드 통계 카운터 갱신
        if (ActiveSuspendedCount > 0) ActiveSuspendedCount--;
        ActiveRestoredCount++;

        // 5. LiteDB 영속화
        var record = _archiveManager.GetIncident(incidentId);
        if (record != null)
        {
            record.VerdictAction = "ACTION_RESUME";
            record.RemediationStatus = "RESTORED_MANUAL";
            record.RemediationSteps.Add($"관리자 수동 동결 해제 완료 (PID: {pid})");
            _archiveManager.SaveIncident(record, new List<ReActTraceRecord>());
        }

        // 6. 필터 및 뷰 동기화
        ApplyFilter();
    }
}
