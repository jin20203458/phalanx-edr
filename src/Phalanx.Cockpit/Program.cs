using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Services;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;

namespace Phalanx.Cockpit;

public static class Program
{
    [STAThread]
    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("================================================================================");
        Console.WriteLine("   PHALANX COCKPIT - C# 자율 AI 위협 헌터 & 관제 허브 (Phase 3)                   ");
        Console.WriteLine("================================================================================");

        var builder = WebApplication.CreateBuilder(args);

        // Kestrel gRPC 서버 포트 설정 (0.0.0.0:50051)
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(50051, o => o.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2);
        });

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
        builder.Services.AddGrpc();

        var app = builder.Build();

        app.MapGrpcService<PhalanxGrpcService>();
        app.MapGet("/", () => "Phalanx EDR Core gRPC Service is running on HTTP/2 (Port: 50051)");

        Console.WriteLine("🚀 [Server] gRPC 관제 서버가 0.0.0.0:50051 에서 대기 중입니다...");
        await app.RunAsync();
    }
}
