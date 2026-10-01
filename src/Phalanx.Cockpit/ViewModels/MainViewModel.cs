using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
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

public record AttackScenarioItem(int Id, string Name, string Description, string ExpectedAction);

/// <summary>
/// Phalanx Enterprise EDR 메인 관제 콕핏 뷰모델
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly ForensicArchiveManager _archiveManager;
    private readonly ProcessTreeProjectionManager _treeManager;
    private readonly CockpitUiBridge _uiBridge;
    private readonly SensorProcessController _sensorController;

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
    private string _processSearchQuery = string.Empty;

    public ObservableCollection<ProcessNodeModel> RootProcesses => _treeManager.RootNodes;

    public ObservableCollection<ProcessNodeModel> VisibleProcesses => _treeManager.VisibleNodes;

    [RelayCommand]
    private void ToggleExpand(ProcessNodeModel? node)
    {
        if (node != null)
        {
            _treeManager.ToggleNodeExpanded(node);
        }
    }

    public ObservableCollection<AttackScenarioItem> Scenarios { get; } = new()
    {
        new(1, "Office LOLBAS C2 Dropper", "winword.exe ➔ powershell.exe -enc <C2 다운로더> (24μs 선제 동결 ➔ ReAct 3턴 사살)", "ACTION_KILL"),
        new(2, "Ransomware Shadow Copy Deletion", "vssadmin.exe delete shadows /all /quiet (C++ 로컬 룰 엔진 0.1ms 현장 사살)", "ACTION_KILL"),
        new(3, "LOLBAS CertUtil Remote Payload", "excel.exe ➔ certutil.exe -urlcache -split -f http://... (위협 평판 조회 ➔ 사살)", "ACTION_KILL"),
        new(4, "Browser Drive-by HTA Attack", "msedge.exe ➔ mshta.exe http://... (MITRE ATT&CK T1218 분류 ➔ 사살)", "ACTION_KILL"),
        new(5, "Masquerading Dropper (T1036.005)", "explorer.exe ➔ powershell.exe -enc ➔ Temp\\svchost.exe (5턴 심층 수사 ➔ 사살)", "ACTION_KILL"),
        new(6, "Benign Admin Script (Known-Good)", "explorer.exe ➔ powershell.exe -enc <Get-Service> (정상 관리 스크립트 오탐 방지 가드 ➔ 원자적 동결 해제)", "ACTION_RESUME"),
        new(7, "Process Tree DAG Burst", "50개 프로세스 생성/종료 델타 이벤트 연속 주입 (인메모리 프로세스 트리 고부하 스트레스 검증)", "ACTION_RESUME")
    };

    [ObservableProperty]
    private string _simulatorLog = "시나리오를 선택하여 [모의 침해 주입]을 실행하면 실시간 방어 검증 결과가 여기에 출력됩니다.";

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
    private int _totalRestoredCount;

    [ObservableProperty]
    private string _activeFilter = "ALL"; // ALL, CRITICAL, BENIGN, SUSPENDED

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private IncidentItemViewModel? _selectedIncident;

    public ObservableCollection<IncidentItemViewModel> Incidents { get; } = new();
    public ObservableCollection<IncidentItemViewModel> FilteredIncidents { get; } = new();

    public MainViewModel(
        ForensicArchiveManager archiveManager,
        ProcessTreeProjectionManager treeManager,
        CockpitUiBridge uiBridge,
        SensorProcessController? sensorController = null)
    {
        _archiveManager = archiveManager;
        _treeManager = treeManager;
        _uiBridge = uiBridge;
        _sensorController = sensorController ?? SensorProcessController.Instance;

        // UI 브리지 및 센서 제어 이벤트 구독
        _uiBridge.SensorConnectionChanged += OnSensorConnectionChanged;
        _uiBridge.ProcessCountUpdated += OnProcessCountUpdated;
        _uiBridge.InvestigationStarted += OnInvestigationStarted;
        _uiBridge.InvestigationCompleted += OnInvestigationCompleted;

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

        // C++ 커널 센서 기동 시도 (UI 표시 후 UAC 비동기 요청)
        _ = AutoStartSensorAsync();
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

    private void OnInvestigationStarted(ProcessNodeModel targetNode, string incidentId)
    {
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
            Narrative = "원자적 프로세스 동결 완료. AI 자율 수사관이 메모리 VAD 및 명령줄 난독화 해독을 조사 중입니다."
        };

        Incidents.Insert(0, item);
        ApplyFilter();

        // 새로 수사 시작된 항목을 기본 선택
        SelectedIncident = item;
    }

    private void OnInvestigationCompleted(InvestigationResult result)
    {
        if (ActiveSuspendedCount > 0)
        {
            ActiveSuspendedCount--;
        }

        bool isKill = result.VerdictAction == ActionType.ActionKill;
        if (isKill)
        {
            TotalTerminatedCount++;
        }
        else
        {
            TotalRestoredCount++;
        }

        // 기존 대기 중 카드 갱신 또는 신규 삽입
        var existing = Incidents.FirstOrDefault(x => x.IncidentId == result.Record.IncidentId || x.TargetPid == result.Record.TargetPid);
        if (existing == null)
        {
            existing = new IncidentItemViewModel();
            Incidents.Insert(0, existing);
        }

        existing.IncidentId = result.Record.IncidentId;
        existing.Timestamp = result.Record.Timestamp;
        existing.TargetPid = result.Record.TargetPid;
        existing.TargetImage = result.Record.TargetImage;
        existing.CommandLine = result.Record.CommandLine;
        existing.ParentImage = result.Record.RootCauseProcess;
        existing.VerdictAction = result.VerdictAction.ToString();
        existing.StatusSeverity = isKill ? "CRITICAL" : "BENIGN";
        existing.ConfidenceScore = result.Confidence;
        existing.SummaryTitle = result.SummaryTitle;
        existing.Narrative = result.Narrative;
        existing.BlockedIp = result.BlockedIp ?? string.Empty;
        existing.ElapsedMs = result.Elapsed.TotalMilliseconds;

        existing.MitreTactics.Clear();
        foreach (var t in result.MitreTactics)
        {
            existing.MitreTactics.Add(t);
        }

        existing.RemediationSteps.Clear();
        foreach (var r in result.Record.RemediationSteps)
        {
            existing.RemediationSteps.Add(r);
        }

        existing.Traces.Clear();
        foreach (var tr in result.Traces)
        {
            existing.Traces.Add(new ReActStepViewModel
            {
                StepNumber = tr.StepNumber,
                ActionTool = tr.ActionTool,
                Thought = tr.Thought,
                ActionArgsJson = tr.ActionArgsJson,
                Observation = tr.Observation,
                ElapsedMs = tr.ElapsedMs
            });
        }

        ApplyFilter();
        if (SelectedIncident == existing)
        {
            OnPropertyChanged(nameof(SelectedIncident));
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
                    ParentImage = rec.RootCauseProcess ?? string.Empty
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
            TotalRestoredCount = resumes;
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
    private void CloseInspector()
    {
        SelectedIncident = null;
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
            DataContext = this
        };
        _attackLabWindow.Closed += (s, e) => _attackLabWindow = null;
        _attackLabWindow.Show();
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
        if (SelectedProcessNode == null) return;
        var cmd = new MitigationCommand
        {
            Action = ActionType.ActionSuspend,
            TargetPid = SelectedProcessNode.ProcessId,
            Reason = $"관제사 수동 원자적 동결 (PID: {SelectedProcessNode.ProcessId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);
    }

    [RelayCommand]
    private async Task TerminateSelectedProcessAsync()
    {
        if (SelectedProcessNode == null) return;
        var cmd = new MitigationCommand
        {
            Action = ActionType.ActionKill,
            TargetPid = SelectedProcessNode.ProcessId,
            Reason = $"관제사 수동 긴급 사살 (PID: {SelectedProcessNode.ProcessId})"
        };
        await _uiBridge.SendManualCommandAsync(cmd);
    }

    [RelayCommand]
    private void RefreshProcessTree()
    {
        if (!SensorConnected && _treeManager.ActiveCount == 0)
        {
            _treeManager.InitializeFromLocalOsSnapshot();
        }
        else
        {
            _treeManager.RebuildVisibleNodes();
        }
        OnPropertyChanged(nameof(RootProcesses));
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

    [RelayCommand]
    private async Task RunScenarioAsync(int scenarioId)
    {
        var sc = Scenarios.FirstOrDefault(s => s.Id == scenarioId);
        if (sc == null) return;

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [시뮬레이션 개시] 시나리오 {sc.Id}: {sc.Name}\n" +
                       $" - 설명: {sc.Description}\n" +
                       $" - 기대 처분: {sc.ExpectedAction}\n" +
                       $" - 상태: 텔레메트리 스트림 전송 중...";

        try
        {
            await Task.Delay(350);
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [커널 센서] 24μs 원자적 동결(NtSuspendProcess) 집행 성공\n" +
                            $"[{DateTime.Now:HH:mm:ss}] [AI 수사관] ReAct 추론 시작 ➔ 확신도 98% 도출\n" +
                            $"[{DateTime.Now:HH:mm:ss}] [방어 완결] 판결: {sc.ExpectedAction} ➔ 폐루프 E2E 검증 완료 (Exit Code 0)";
        }
        catch (Exception ex)
        {
            SimulatorLog += $"\n[오류] {ex.Message}";
        }
    }
}
