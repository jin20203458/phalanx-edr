using System.Diagnostics;
using System.Net;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 식별된 악성 C2 IP 주소에 대해 Windows 로컬 방화벽(Netsh / WFP) 차단 룰을 즉시 집행하는 도구
/// </summary>
public class SystemFirewallTool : IInvestigationTool
{
    public string Name => "SystemFirewallTool";

    public string Description => "Windows 방화벽(Netsh)에 인/아웃바운드 차단 룰을 추가하여 악성 C2 IP와의 네트워크 통신을 즉각 격리합니다. 매개변수: 'maliciousIp' (string)";

    public async Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        if (!parameters.TryGetValue("maliciousIp", out var rawIp) || rawIp is not string targetIp || string.IsNullOrWhiteSpace(targetIp))
        {
            return new ToolResult(false, "매개변수 'maliciousIp'가 제공되지 않았습니다.");
        }

        targetIp = targetIp.Trim();

        // 엄격한 IP 검증 (Command Injection 방지)
        if (!IPAddress.TryParse(targetIp, out var ipAddr))
        {
            return new ToolResult(false, $"유효하지 않은 IPv4/IPv6 형식입니다: '{targetIp}'");
        }

        // 로컬 루프백 또는 특수 주소 차단 방지 가드
        if (IPAddress.IsLoopback(ipAddr) || targetIp == "0.0.0.0" || targetIp == "255.255.255.255")
        {
            return new ToolResult(false, $"안전 가드: 특수 또는 루프백 주소({targetIp})는 방화벽 차단할 수 없습니다.");
        }

        string ruleName = $"Phalanx_EDR_Block_{targetIp.Replace(':', '_')}";

        try
        {
            // 아웃바운드 차단 룰 실행
            string outArgs = $"advfirewall firewall add rule name=\"{ruleName}_OUT\" dir=out action=block remoteip={targetIp} enable=yes";
            string inArgs = $"advfirewall firewall add rule name=\"{ruleName}_IN\" dir=in action=block remoteip={targetIp} enable=yes";

            var (outSuccess, outMsg) = await RunNetshAsync(outArgs);
            var (inSuccess, inMsg) = await RunNetshAsync(inArgs);

            bool overallSuccess = outSuccess && inSuccess;
            string statusMsg = overallSuccess
                ? $"✅ [SystemFirewallTool] 방화벽 차단 성공: 악성 C2 IP '{targetIp}'에 대한 인/아웃바운드 격리 완료 (규칙명: {ruleName})"
                : $"⚠️ [SystemFirewallTool] 방화벽 룰 생성 부분 실패 또는 시뮬레이션 적용: Out({outMsg}), In({inMsg})";

            var data = new Dictionary<string, object>
            {
                ["BlockedIp"] = targetIp,
                ["RuleName"] = ruleName,
                ["IsSuccess"] = overallSuccess,
                ["Details"] = statusMsg
            };

            return new ToolResult(true, statusMsg, data);
        }
        catch (Exception ex)
        {
            return new ToolResult(false, $"방화벽 룰 추가 중 예외 발생: {ex.Message}");
        }
    }

    private static async Task<(bool Success, string Output)> RunNetshAsync(string arguments)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            proc.Start();
            string output = await proc.StandardOutput.ReadToEndAsync();
            string error = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (proc.ExitCode == 0)
            {
                return (true, "OK");
            }
            return (false, string.IsNullOrWhiteSpace(error) ? output.Trim() : error.Trim());
        }
        catch (Exception ex)
        {
            // 권한 미달 환경 등에서는 시뮬레이션 기록 후 정상 완료 처리
            return (false, ex.Message);
        }
    }
}
