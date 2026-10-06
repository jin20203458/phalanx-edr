using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading.Tasks;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class SystemFirewallToolTests
{
    private readonly SystemFirewallTool _tool = new();

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    [Fact]
    public async Task ExecuteAsync_RepeatedBlocks_MaintainsIdempotency()
    {
        // 멱등성 검증: 동일한 악성 IP(185.220.101.5)에 대해 3회 연속 block을 실행하더라도
        // 에러 없이 항상 성공해야 하며, Admin 환경인 경우 방화벽에 단 1쌍(IN 1개, OUT 1개)만 유지되어야 함
        string testIp = "185.220.101.5";

        for (int i = 0; i < 3; i++)
        {
            var result = await _tool.ExecuteAsync(new() { ["maliciousIp"] = testIp, ["action"] = "block" });
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.Equal(testIp, result.Data["BlockedIp"]);
            Assert.Equal("Phalanx_EDR_Block_185.220.101.5", result.Data["RuleName"]);
        }

        // 실제 관리자 권한 환경인 경우 netsh 규칙 수 실측 단언
        if (IsAdministrator())
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = "advfirewall firewall show rule name=\"Phalanx_EDR_Block_185.220.101.5_IN\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            string output = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();

            // "Rule Name:" 라인이 정확히 1개만 매칭되어야 함 (중복 누적 0건 실증)
            int matchCount = 0;
            foreach (var line in output.Split('\n'))
            {
                if (line.Trim().StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase) ||
                    line.Trim().StartsWith("규칙 이름:", StringComparison.OrdinalIgnoreCase))
                {
                    matchCount++;
                }
            }
            Assert.Equal(1, matchCount);
        }
    }

    [Fact]
    public async Task ExecuteAsync_Unblock_SucceedsCleanly()
    {
        string testIp = "185.220.101.5";

        // 먼저 block 후 unblock
        await _tool.ExecuteAsync(new() { ["maliciousIp"] = testIp, ["action"] = "block" });
        var unblockRes = await _tool.ExecuteAsync(new() { ["maliciousIp"] = testIp, ["action"] = "unblock" });

        Assert.True(unblockRes.Success);
        Assert.NotNull(unblockRes.Data);
        Assert.Equal("unblock", unblockRes.Data["Action"]);
    }

    [Fact]
    public async Task ExecuteAsync_InvalidOrLoopbackIp_IsRejectedByGuard()
    {
        // 1. 잘못된 IP 형식 거부
        var res1 = await _tool.ExecuteAsync(new() { ["maliciousIp"] = "not_an_ip" });
        Assert.False(res1.Success);
        Assert.Contains("유효하지 않은", res1.Output);

        // 2. 루프백 IP 거부 (자폭 방어)
        var res2 = await _tool.ExecuteAsync(new() { ["maliciousIp"] = "127.0.0.1" });
        Assert.False(res2.Success);
        Assert.Contains("루프백", res2.Output);
    }
}
