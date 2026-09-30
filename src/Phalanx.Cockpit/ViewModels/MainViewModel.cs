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
            SummaryTitle = "Gemini 3.8 Flash 자율 수사 진행 중 (Process Frozen)...",
            Narrative = "24μs 원자적 동결 완료. Gemini 자율 수사관이 메모리 VAD 및 명령줄 난독화 해독을 조사 중입니다."
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
                Observation = tr.Observation
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
                    IncidentId = rec.IncidentId,
                    Timestamp = rec.Timestamp,
                    TargetPid = rec.TargetPid,
                    TargetImage = rec.TargetImage,
                    CommandLine = rec.CommandLine,
                    VerdictAction = rec.VerdictAction,
                    StatusSeverity = isKill ? "CRITICAL" : "BENIGN",
                    ConfidenceScore = rec.ConfidenceScore,
                    SummaryTitle = rec.SummaryTitle,
                    Narrative = rec.Narrative,
                    BlockedIp = rec.BlockedIp,
                    ParentImage = rec.RootCauseProcess
                };

                foreach (var m in rec.MitreTactics)
                {
                    item.MitreTactics.Add(m);
                }

                foreach (var r in rec.RemediationSteps)
                {
                    item.RemediationSteps.Add(r);
                }

                var traces = _archiveManager.GetTracesForIncident(rec.IncidentId);
                foreach (var tr in traces)
                {
                    item.Traces.Add(new ReActStepViewModel
                    {
                        StepNumber = tr.StepNumber,
                        ActionTool = tr.ActionTool,
                        Thought = tr.Thought,
                        ActionArgsJson = tr.ActionArgsJson,
                        Observation = tr.Observation
                    });
                }

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

    [RelayCommand]
    private async Task ForceTerminateAsync()
    {
        if (SelectedIncident == null) return;

        await _uiBridge.SendManualCommandAsync(new MitigationCommand
        {
            Action = ActionType.ActionKill,
            TargetPid = SelectedIncident.TargetPid,
            Reason = $"[SecOps Manual Override] 관제관 수동 강제 사살 (PID: {SelectedIncident.TargetPid})"
        });

        SelectedIncident.VerdictAction = "ACTION_KILL";
        SelectedIncident.StatusSeverity = "CRITICAL";
        SelectedIncident.SummaryTitle += " [수동 사살 집행됨]";
        TotalTerminatedCount++;
        ApplyFilter();
    }

    [RelayCommand]
    private async Task ForceResumeAsync()
    {
        if (SelectedIncident == null) return;

        await _uiBridge.SendManualCommandAsync(new MitigationCommand
        {
            Action = ActionType.ActionResume,
            TargetPid = SelectedIncident.TargetPid,
            Reason = $"[SecOps Manual Override] 관제관 수동 동결 해제 (PID: {SelectedIncident.TargetPid})"
        });

        SelectedIncident.VerdictAction = "ACTION_RESUME";
        SelectedIncident.StatusSeverity = "BENIGN";
        SelectedIncident.SummaryTitle += " [수동 동결 해제됨]";
        TotalRestoredCount++;
        ApplyFilter();
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
                bool matchesSearch = item.TargetImage.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                                     item.CommandLine.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                                     item.TargetPid.ToString().Contains(SearchQuery) ||
                                     item.SummaryTitle.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                                     item.BlockedIp.Contains(SearchQuery);
                if (!matchesSearch) continue;
            }

            FilteredIncidents.Add(item);
        }
    }
}
