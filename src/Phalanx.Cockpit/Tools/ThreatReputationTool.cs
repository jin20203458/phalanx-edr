using System.Net;
using System.Net.Sockets;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 로컬 내장 위협 인텔리전스 DB(IoC), RFC 1918 사설망 분류기, 공공 DNS 화이트리스트 및 도메인/IP 평판을 조회하는 상용 1티어 도구
/// </summary>
public class ThreatReputationTool : IInvestigationTool
{
    public string Name => "ThreatReputationTool";

    public string Description => "추출된 IP 주소, 도메인, URL의 위협 평판 점수(0~100)와 알려진 APT 공격 그룹 정보를 조회합니다. 매개변수: 'targetIndicator' (string)";

    private record ThreatEntry(int Score, string Category, string ThreatGroup, string Description);

    private static readonly Dictionary<string, ThreatEntry> KnownThreatDb = new(StringComparer.OrdinalIgnoreCase)
    {
        // 악성 C2 및 APT IoC
        ["185.220.101.5"] = new(98, "Cobalt Strike / C2 Beacon", "APT29 (Cozy Bear)", "Tor Exit Node 기반 악성 C2 인프라 및 다단계 로더 통신"),
        ["194.165.16.11"] = new(95, "Ransomware Delivery C2", "LockBit 3.0 Affiliate", "초기 침투 및 정보 유출용 리버스 쉘 엔드포인트"),
        ["45.33.32.156"] = new(92, "Meterpreter Reverse TCP", "FIN7 (Carbanak)", "금전 목적 사이버 범죄 그룹 백도어"),
        ["193.142.59.183"] = new(96, "QakBot / BlackCat Loader", "Black Basta", "랜섬웨어 2차 페이로드 스테이징 서버"),
        ["103.145.13.22"] = new(94, "PlugX C2 Node", "APT41", "국가 배후 위협 그룹 C2 인프라"),
        ["evil-c2.darknet"] = new(99, "Fileless C2 Domain", "Lazarus Group", "난독화 매크로를 통한 2차 페이로드 다운로더"),
        ["malicious-download.com"] = new(90, "Dropper Server", "Generic Malware", "파워셸 인라인 스크립트 배포 서버"),
        ["c2-delivery.live"] = new(91, "Beacon Staging Node", "UNC2452", "공급망 공격 C2 엔드포인트"),

        // 공공 DNS 및 합법적 인프라 화이트리스트 (Score 0)
        ["127.0.0.1"] = new(0, "Local Loopback", "Benign", "로컬 루프백 정상 주소"),
        ["8.8.8.8"] = new(0, "Public DNS", "Google", "Google Public Anycast DNS"),
        ["8.8.4.4"] = new(0, "Public DNS", "Google", "Google Public Anycast DNS Secondary"),
        ["1.1.1.1"] = new(0, "Public DNS", "Cloudflare", "Cloudflare 1.1.1.1 DNS Resolver"),
        ["1.0.0.1"] = new(0, "Public DNS", "Cloudflare", "Cloudflare 1.0.0.1 DNS Secondary"),
        ["9.9.9.9"] = new(0, "Public DNS", "Quad9", "Quad9 Secure Anycast DNS"),
        ["208.67.222.222"] = new(0, "Public DNS", "Cisco OpenDNS", "OpenDNS Home Resolver"),
        ["168.126.63.1"] = new(0, "ISP DNS", "KT", "KT 한국 통신 기본 네임서버"),
        ["168.126.63.2"] = new(0, "ISP DNS", "KT", "KT 한국 통신 보조 네임서버"),
        ["219.250.36.130"] = new(0, "ISP DNS", "SK Broadband", "SK브로드밴드 기본 네임서버"),
        ["164.124.101.2"] = new(0, "ISP DNS", "LG Uplus", "LG유플러스 기본 네임서버")
    };

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        string? indicator = null;
        var caseInsensitive = new Dictionary<string, object>(parameters, StringComparer.OrdinalIgnoreCase);
        foreach (var key in new[] { "targetIndicator", "target_indicator", "indicator", "ip", "domain", "url" })
        {
            if (caseInsensitive.TryGetValue(key, out var rawInd) && rawInd != null)
            {
                string? s = rawInd switch
                {
                    string str => str,
                    System.Text.Json.JsonElement je when je.ValueKind == System.Text.Json.JsonValueKind.String => je.GetString(),
                    _ => rawInd.ToString()
                };

                if (!string.IsNullOrWhiteSpace(s))
                {
                    indicator = s;
                    break;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(indicator))
        {
            return Task.FromResult(new ToolResult(false, "매개변수 'targetIndicator'가 제공되지 않았습니다."));
        }

        string cleaned = SanitizeIndicator(indicator);

        // 1. 사전 등록된 위협 및 화이트리스트 DB 조회
        if (KnownThreatDb.TryGetValue(cleaned, out var entry))
        {
            string verdict = entry.Score >= 80 ? "HIGH_RISK_MALICIOUS" : (entry.Score >= 50 ? "SUSPICIOUS" : "BENIGN");
            string output = $"[ThreatReputationTool 조회 결과 - {cleaned}]\n" +
                           $"• 위협 점수: {entry.Score} / 100 ({verdict})\n" +
                           $"• 위협 유형: {entry.Category}\n" +
                           $"• 연관 공격 그룹: {entry.ThreatGroup}\n" +
                           $"• 상세 설명: {entry.Description}";

            var data = new Dictionary<string, object>
            {
                ["Indicator"] = cleaned,
                ["Score"] = entry.Score,
                ["Verdict"] = verdict,
                ["Category"] = entry.Category,
                ["ThreatGroup"] = entry.ThreatGroup
            };

            return Task.FromResult(new ToolResult(true, output, data));
        }

        // 2. IP 형식 검증 및 RFC 1918 사설망/특수 주소 판별
        if (IPAddress.TryParse(cleaned, out var ipAddr))
        {
            if (IsPrivateOrInternalIp(ipAddr))
            {
                string internalOutput = $"[ThreatReputationTool 조회 결과 - {cleaned}]\n" +
                                        $"• 위협 점수: 0 / 100 (BENIGN_INTERNAL)\n" +
                                        $"• 위협 유형: 내부 사설 네트워크 주소 (RFC 1918 / Loopback / Link-Local)\n" +
                                        $"• 연관 공격 그룹: None\n" +
                                        $"• 비고: 엔터프라이즈 사내 인트라넷 또는 로컬 인터페이스 주소로 안전합니다.";

                var internalData = new Dictionary<string, object>
                {
                    ["Indicator"] = cleaned,
                    ["Score"] = 0,
                    ["Verdict"] = "BENIGN_INTERNAL",
                    ["Category"] = "Internal Private Network",
                    ["ThreatGroup"] = "None"
                };

                return Task.FromResult(new ToolResult(true, internalOutput, internalData));
            }

            // 미확인 외부 공인 IP (75점 오탐 폭탄 제거 -> 중립 30점 판정)
            const int unknownPublicScore = 30;
            string unknownVerdict = "INCONCLUSIVE_EXTERNAL_IP";
            string publicOutput = $"[ThreatReputationTool 조회 결과 - {cleaned}]\n" +
                                  $"• 위협 점수: {unknownPublicScore} / 100 ({unknownVerdict})\n" +
                                  $"• 위협 유형: 미등록 외부 공인 IP (Inconclusive)\n" +
                                  $"• 연관 공격 그룹: 미확인 (Unattributed)\n" +
                                  $"• 수사 지침: 알려진 블랙리스트에 없으나 외부 통신 IP입니다. 본 지표 단독으로 프로세스를 사살(ActionKill)하지 마십시오. 메모리 인젝션, 난독화 명령줄 등 복합 증거가 필요합니다.";

            var publicData = new Dictionary<string, object>
            {
                ["Indicator"] = cleaned,
                ["Score"] = unknownPublicScore,
                ["Verdict"] = unknownVerdict,
                ["Category"] = "Inconclusive External",
                ["ThreatGroup"] = "None"
            };

            return Task.FromResult(new ToolResult(true, publicOutput, publicData));
        }

        // 3. 미등록 도메인/호스트명
        const int unknownDomainScore = 20;
        string domainOutput = $"[ThreatReputationTool 조회 결과 - {cleaned}]\n" +
                              $"• 위협 점수: {unknownDomainScore} / 100 (UNKNOWN_BENIGN)\n" +
                              $"• 위협 유형: 미등록 도메인/엔드포인트\n" +
                              $"• 연관 공격 그룹: None\n" +
                              $"• 비고: 내장 위협 인텔리전스에 등록되지 않은 식별자입니다.";

        var domainData = new Dictionary<string, object>
        {
            ["Indicator"] = cleaned,
            ["Score"] = unknownDomainScore,
            ["Verdict"] = "UNKNOWN_BENIGN",
            ["Category"] = "Unknown",
            ["ThreatGroup"] = "None"
        };

        return Task.FromResult(new ToolResult(true, domainOutput, domainData));
    }

    private static string SanitizeIndicator(string raw)
    {
        string s = raw.Trim().Trim('\'', '\"', '`');

        // Defanged 패턴 복구: 185[.]220[.]101[.]5 -> 185.220.101.5, hxxp -> http
        s = s.Replace("[.]", ".").Replace("[:]", ":");
        if (s.StartsWith("hxxp://", StringComparison.OrdinalIgnoreCase)) s = "http://" + s[7..];
        else if (s.StartsWith("hxxps://", StringComparison.OrdinalIgnoreCase)) s = "https://" + s[8..];

        // URL 프로토콜 제거 및 호스트 추출
        if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var uri = new Uri(s);
                s = uri.Host;
            }
            catch { }
        }

        // 포트 번호 제거: 185.220.101.5:443 -> 185.220.101.5
        int colonIdx = s.IndexOf(':');
        if (colonIdx > 0 && !s.Contains("::")) // IPv6 :: 포트 구분 주의
        {
            string candidateIp = s[..colonIdx];
            if (IPAddress.TryParse(candidateIp, out _))
            {
                s = candidateIp;
            }
        }

        return s.ToLowerInvariant();
    }

    private static bool IsPrivateOrInternalIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = ip.GetAddressBytes();
            uint val = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

            // 10.0.0.0/8 (0x0A000000)
            if ((val & 0xFF000000) == 0x0A000000) return true;

            // 172.16.0.0/12 (0xAC100000 ~ 0xAC1FFFFF) - RFC 1918 Class B 완벽 판별
            if ((val & 0xFFF00000) == 0xAC100000) return true;

            // 192.168.0.0/16 (0xC0A80000)
            if ((val & 0xFFFF0000) == 0xC0A80000) return true;

            // 127.0.0.0/8 (Loopback)
            if ((val & 0xFF000000) == 0x7F000000) return true;

            // 169.254.0.0/16 (APIPA)
            if ((val & 0xFFFF0000) == 0xA9FE0000) return true;

            // 100.64.0.0/10 (CGNAT)
            if ((val & 0xFFC00000) == 0x64400000) return true;

            // 0.0.0.0/8
            if ((val & 0xFF000000) == 0x00000000) return true;

            // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
            if ((val & 0xF0000000) >= 0xE0000000) return true;

            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;

            byte[] b = ip.GetAddressBytes();
            // Unique Local Address (fc00::/7)
            if ((b[0] & 0xFE) == 0xFC) return true;
        }

        return false;
    }
}
