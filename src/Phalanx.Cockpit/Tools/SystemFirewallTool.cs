using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 식별된 악성 C2 IP 주소에 대해 Windows 로컬 방화벽(Netsh / WFP) 인/아웃바운드 차단 룰을 즉시 집행하는 상용 1티어 도구
/// 호스트 활성 IP, 기본 게이트웨이, 로컬 DNS 등 핵심 인프라 차단 방지 가드 및 병렬 실행 탑재
/// </summary>
public class SystemFirewallTool : IInvestigationTool
{
    public string Name => "SystemFirewallTool";

    public string Description => "Windows 방화벽(Netsh)에 인/아웃바운드 차단 룰을 병렬로 추가/해제하여 악성 C2 IP와의 네트워크 통신을 즉각 격리합니다. 매개변수: 'maliciousIp' (string), 'action' (optional: 'block'|'unblock'|'status')";

    public async Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        string? targetIp = null;
        string action = "block";

        var caseInsensitive = new Dictionary<string, object>(parameters, StringComparer.OrdinalIgnoreCase);
        foreach (var key in new[] { "maliciousIp", "malicious_ip", "ip", "targetIp", "target_ip" })
        {
            if (caseInsensitive.TryGetValue(key, out var rawIp) && rawIp != null)
            {
                string? s = rawIp switch
                {
                    string str => str,
                    System.Text.Json.JsonElement je when je.ValueKind == System.Text.Json.JsonValueKind.String => je.GetString(),
                    _ => rawIp.ToString()
                };

                if (!string.IsNullOrWhiteSpace(s))
                {
                    targetIp = s.Trim();
                    break;
                }
            }
        }

        if (caseInsensitive.TryGetValue("action", out var rawAction) && rawAction != null)
        {
            string? actStr = rawAction switch
            {
                string str => str,
                System.Text.Json.JsonElement je when je.ValueKind == System.Text.Json.JsonValueKind.String => je.GetString(),
                _ => rawAction.ToString()
            };
            if (!string.IsNullOrWhiteSpace(actStr))
            {
                action = actStr.Trim().ToLowerInvariant();
            }
        }

        if (string.IsNullOrWhiteSpace(targetIp))
        {
            return new ToolResult(false, "매개변수 'maliciousIp'가 제공되지 않았습니다.");
        }

        // 1. IP 포맷 엄격 검증 (Command Injection 원천 차단)
        if (!IPAddress.TryParse(targetIp, out var ipAddr))
        {
            return new ToolResult(false, $"유효하지 않은 IPv4/IPv6 형식입니다: '{targetIp}'");
        }

        // 2. 특수 루프백 및 브로드캐스트 주소 차단 방지
        if (IPAddress.IsLoopback(ipAddr) || targetIp == "0.0.0.0" || targetIp == "255.255.255.255")
        {
            return new ToolResult(false, $"안전 가드: 특수 또는 루프백 주소({targetIp})는 방화벽 차단할 수 없습니다.");
        }

        // 3. 인프라 자폭(Self-DoS) 방어 가드: 호스트 IP, 기본 게이트웨이, 로컬 DNS 차단 방지
        if (IsCriticalInfrastructureIp(ipAddr))
        {
            return new ToolResult(false, $"🚨 안전 가드: 주요 인프라 주소(호스트 활성 IP, 게이트웨이, 또는 로컬 DNS: '{targetIp}')는 방화벽 차단할 수 없습니다. 시스템 격리 위험으로 거부되었습니다.");
        }

        string safeIpTag = targetIp.Replace(':', '_');
        string ruleName = $"Phalanx_EDR_Block_{safeIpTag}";
        bool isAdmin = IsAdministrator();

        try
        {
            // Non-Admin 개발/단위테스트 환경 시뮬레이션 처리
            if (!isAdmin)
            {
                string simMsg = action switch
                {
                    "unblock" => $"✅ [SystemFirewallTool: 시뮬레이션 해제] 관리자 권한(UAC) 미달 환경이므로 가상 시뮬레이션 차단 해제 완료 (대상 IP: {targetIp}, 규칙명: {ruleName})",
                    _ => $"✅ [SystemFirewallTool: 시뮬레이션 격리] 관리자 권한(UAC) 미달 환경이므로 가상 시뮬레이션 차단 집행 완료 (대상 IP: {targetIp}, 규칙명: {ruleName})"
                };

                var simData = new Dictionary<string, object>
                {
                    ["BlockedIp"] = targetIp,
                    ["RuleName"] = ruleName,
                    ["IsSuccess"] = true,
                    ["IsSimulated"] = true,
                    ["Action"] = action,
                    ["Details"] = simMsg
                };

                return new ToolResult(true, simMsg, simData);
            }

            // 관리자 권한 환경: 실제 Netsh 병렬 실행
            if (action == "unblock")
            {
                string delOutArgs = $"advfirewall firewall delete rule name=\"{ruleName}_OUT\"";
                string delInArgs = $"advfirewall firewall delete rule name=\"{ruleName}_IN\"";

                var outTask = RunNetshAsync(delOutArgs);
                var inTask = RunNetshAsync(delInArgs);
                await Task.WhenAll(outTask, inTask);

                bool overallSuccess = outTask.Result.Success || inTask.Result.Success;
                string statusMsg = overallSuccess
                    ? $"✅ [SystemFirewallTool] 방화벽 격리 해제 완료: IP '{targetIp}' 규칙 제거 완료 (규칙명: {ruleName})"
                    : $"⚠️ [SystemFirewallTool] 방화벽 규칙 제거 실패: Out({outTask.Result.Output}), In({inTask.Result.Output})";

                var data = new Dictionary<string, object>
                {
                    ["BlockedIp"] = targetIp,
                    ["RuleName"] = ruleName,
                    ["IsSuccess"] = overallSuccess,
                    ["IsSimulated"] = false,
                    ["Action"] = action,
                    ["Details"] = statusMsg
                };

                return new ToolResult(overallSuccess, statusMsg, data);
            }
            else
            {
                // Action: "block" (인/아웃바운드 병렬 추가)
                string outArgs = $"advfirewall firewall add rule name=\"{ruleName}_OUT\" dir=out action=block remoteip={targetIp} enable=yes";
                string inArgs = $"advfirewall firewall add rule name=\"{ruleName}_IN\" dir=in action=block remoteip={targetIp} enable=yes";

                var outTask = RunNetshAsync(outArgs);
                var inTask = RunNetshAsync(inArgs);
                await Task.WhenAll(outTask, inTask);

                bool overallSuccess = outTask.Result.Success && inTask.Result.Success;
                string statusMsg = overallSuccess
                    ? $"✅ [SystemFirewallTool] 방화벽 차단 성공: 악성 C2 IP '{targetIp}'에 대한 인/아웃바운드 격리 완료 (규칙명: {ruleName})"
                    : $"❌ [SystemFirewallTool] 방화벽 룰 생성 실패: Out({outTask.Result.Output}), In({inTask.Result.Output})";

                var data = new Dictionary<string, object>
                {
                    ["BlockedIp"] = targetIp,
                    ["RuleName"] = ruleName,
                    ["IsSuccess"] = overallSuccess,
                    ["IsSimulated"] = false,
                    ["Action"] = action,
                    ["Details"] = statusMsg
                };

                return new ToolResult(overallSuccess, statusMsg, data);
            }
        }
        catch (Exception ex)
        {
            return new ToolResult(false, $"방화벽 룰 제어 중 예외 발생: {ex.Message}");
        }
    }

    private static bool IsCriticalInfrastructureIp(IPAddress ip)
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                var ipProps = ni.GetIPProperties();

                // 호스트 유니캐스트 IP
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.Equals(ip)) return true;
                }

                // 기본 게이트웨이
                foreach (var gw in ipProps.GatewayAddresses)
                {
                    if (gw.Address.Equals(ip)) return true;
                }

                // 로컬 DNS 서버
                foreach (var dns in ipProps.DnsAddresses)
                {
                    if (dns.Equals(ip) && IsLocalOrPrivate(dns)) return true;
                }
            }
        }
        catch { }

        return false;
    }

    private static bool IsLocalOrPrivate(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = ip.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && (b[1] >= 16 && b[1] <= 31)) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
        }
        return false;
    }

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
            return (false, ex.Message);
        }
    }
}
