using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Reporting;
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

        // QuestPDF Community 라이선스 초기화
        ForensicPdfReportGenerator.EnsureLicenseConfigured();

        var builder = WebApplication.CreateBuilder(args);

        // AppSettings.json 또는 구성 파라미터 로드
        int grpcPort = builder.Configuration.GetValue<int>("Sensor:Port", 50051);
        string sensorHost = builder.Configuration.GetValue<string>("Sensor:Host", "127.0.0.1") ?? "127.0.0.1";
        string dbPath = builder.Configuration.GetValue<string>("Storage:DatabasePath", "phalanx_forensics.db") ?? "phalanx_forensics.db";

        // Kestrel gRPC 서버 포트 설정 (0.0.0.0:grpcPort)
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(grpcPort, o => o.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2);
            options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(5);
            options.Limits.Http2.KeepAlivePingDelay = TimeSpan.FromSeconds(30);
            options.Limits.Http2.KeepAlivePingTimeout = TimeSpan.FromSeconds(15);
        });

        // 싱글톤 UI 브리지 및 센서 프로세스 컨트롤러
        var uiBridge = CockpitUiBridge.Instance;
        builder.Services.AddSingleton(uiBridge);
        var sensorController = SensorProcessController.Instance;
        sensorController.Endpoint = $"{sensorHost}:{grpcPort}";
        builder.Services.AddSingleton(sensorController);

        // DI 등록
        builder.Services.AddSingleton<ProcessTreeProjectionManager>();
        builder.Services.AddSingleton(sp => new ForensicArchiveManager(dbPath));

        // 7대 OS 수사 도구 등록
        builder.Services.AddSingleton<IInvestigationTool, DecodePayloadTool>();
        builder.Services.AddSingleton<IInvestigationTool, ProcessMemoryScanTool>();
        builder.Services.AddSingleton<IInvestigationTool, ThreatReputationTool>();
        builder.Services.AddSingleton<IInvestigationTool, MitreClassifierTool>();
        builder.Services.AddSingleton<IInvestigationTool, SystemFirewallTool>();
        builder.Services.AddSingleton<IInvestigationTool, FileInspectionTool>();
        builder.Services.AddSingleton<IInvestigationTool, RegistryInspectionTool>();

        builder.Services.AddSingleton<AutonomousHunterAgent>();
        builder.Services.AddSingleton<AttackLabScenarioRunner>();
        builder.Services.AddSingleton<PhalanxGrpcService>();
        builder.Services.AddSingleton<IForensicReportGenerator, ForensicPdfReportGenerator>();
        builder.Services.AddSingleton<SettingsViewModel>();
        builder.Services.AddSingleton<MainViewModel>();
        builder.Services.AddSingleton<MainWindow>();

        builder.Services.AddGrpc();

        var webApp = builder.Build();

        webApp.MapGrpcService<PhalanxGrpcService>();
        webApp.MapGet("/", () => $"Phalanx EDR Core gRPC Service is running on HTTP/2 (Port: {grpcPort})");

        // 헌터 에이전트 이벤트 -> UI 브리지 연동
        var agent = webApp.Services.GetRequiredService<AutonomousHunterAgent>();
        agent.OnInvestigationStarted += (targetNode, incidentId) =>
            uiBridge.NotifyInvestigationStarted(targetNode, incidentId);
        agent.OnReActStepProgress += (incidentId, trace) =>
            uiBridge.NotifyReActStepCompleted(incidentId, trace);
        agent.OnInvestigationCompleted += result =>
            uiBridge.NotifyInvestigationCompleted(result);
        uiBridge.InvestigationCancelHandler = id => agent.CancelInvestigation(id);

        if (args.Contains("--headless"))
        {
            Console.WriteLine("[HEADLESS] Headless mode enabled. Kestrel gRPC running without WPF window.");
            webApp.Run();
            return;
        }

        // 백그라운드 Kestrel gRPC 서버 동기 기동
        Console.WriteLine($"[SERVER] gRPC 관제 서버가 0.0.0.0:{grpcPort} 에서 백그라운드 구동 중입니다...");
        try
        {
            webApp.Start();
        }
        catch (Exception ex) when (ex is System.IO.IOException || ex.InnerException is System.Net.Sockets.SocketException)
        {
            string msg = $"[포트 충돌 오류] gRPC 수신 포트({grpcPort})가 이미 다른 프로세스(기존 Cockpit 또는 dotnet 등)에서 점유 중입니다.\n\n작업 관리자 또는 PowerShell(Get-NetTCPConnection -LocalPort {grpcPort})에서 해당 프로세스를 종료한 후 다시 실행하십시오.\n\n세부 오류: {ex.Message}";
            Console.Error.WriteLine($"\n[ERROR] {msg}");
            System.Windows.MessageBox.Show(msg, "Phalanx Cockpit - 포트 충돌", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            return;
        }

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
