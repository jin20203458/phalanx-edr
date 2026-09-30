using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Phalanx.Cockpit.ViewModels;
using Phalanx.Cockpit.Views;

namespace Phalanx.Cockpit;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("================================================================================");
        Console.WriteLine("   PHALANX COCKPIT - C# Enterprise EDR Threat Cockpit (Phase 4)                 ");
        Console.WriteLine("================================================================================");

        var builder = WebApplication.CreateBuilder(args);

        // Kestrel gRPC 서버 포트 설정 (0.0.0.0:50051)
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(50051, o => o.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2);
        });

        // 싱글톤 UI 브리지 및 센서 프로세스 컨트롤러
        var uiBridge = CockpitUiBridge.Instance;
        builder.Services.AddSingleton(uiBridge);
        var sensorController = SensorProcessController.Instance;
        builder.Services.AddSingleton(sensorController);

        // DI 등록
        builder.Services.AddSingleton<ProcessTreeProjectionManager>();
        builder.Services.AddSingleton(sp => new ForensicArchiveManager("phalanx_forensics.db"));

        // 5대 OS 수사 도구 등록
        builder.Services.AddSingleton<IInvestigationTool, DecodePayloadTool>();
        builder.Services.AddSingleton<IInvestigationTool, ProcessMemoryScanTool>();
        builder.Services.AddSingleton<IInvestigationTool, ThreatReputationTool>();
        builder.Services.AddSingleton<IInvestigationTool, MitreClassifierTool>();
        builder.Services.AddSingleton<IInvestigationTool, SystemFirewallTool>();

        builder.Services.AddSingleton<AutonomousHunterAgent>();
        builder.Services.AddSingleton<PhalanxGrpcService>();
        builder.Services.AddSingleton<MainViewModel>();
        builder.Services.AddSingleton<MainWindow>();

        builder.Services.AddGrpc();

        var webApp = builder.Build();

        webApp.MapGrpcService<PhalanxGrpcService>();
        webApp.MapGet("/", () => "Phalanx EDR Core gRPC Service is running on HTTP/2 (Port: 50051)");

        // 헌터 에이전트 이벤트 -> UI 브리지 연동
        var agent = webApp.Services.GetRequiredService<AutonomousHunterAgent>();
        agent.OnInvestigationStarted += (targetNode, incidentId) =>
            uiBridge.NotifyInvestigationStarted(targetNode, incidentId);
        agent.OnInvestigationCompleted += result =>
            uiBridge.NotifyInvestigationCompleted(result);

        if (args.Contains("--headless"))
        {
            Console.WriteLine("[HEADLESS] Headless mode enabled. Kestrel gRPC running without WPF window.");
            webApp.Run();
            return;
        }

        // 백그라운드 Kestrel gRPC 서버 동기 기동
        Console.WriteLine("[SERVER] gRPC 관제 서버가 0.0.0.0:50051 에서 백그라운드 구동 중입니다...");
        webApp.Start();

        // WPF 애플리케이션 및 메인 윈도우 기동 (동기 STA 유지)
        var wpfApp = new App();
        var mainWindow = webApp.Services.GetRequiredService<MainWindow>();

        // Gate 1 지침: wpfApp.Run(mainWindow) 종료 대기 후 순차 동기 정리
        wpfApp.Run(mainWindow);

        try
        {
            Console.WriteLine("[SHUTDOWN] Cockpit 윈도우 종료 감지 -> C++ 커널 센서 안전 종료 진행...");
            sensorController.StopSensorAsync().GetAwaiter().GetResult();

            Console.WriteLine("[SHUTDOWN] Kestrel gRPC 관제 서버 정리 중...");
            webApp.StopAsync().GetAwaiter().GetResult();
            webApp.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SHUTDOWN WARNING] {ex.Message}");
        }
    }
}
