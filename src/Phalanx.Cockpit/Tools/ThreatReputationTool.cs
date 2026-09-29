namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 로컬 내장 위협 인텔리전스 DB(IoC) 및 도메인/IP 평판을 조회하여
/// 악성 위협 점수(0~100) 및 알려진 APT/랜섬웨어 캠페인 정보를 제공하는 도구
/// </summary>
public class ThreatReputationTool : IInvestigationTool
{
    public string Name => "ThreatReputationTool";

    public string Description => "추출된 IP 주소, 도메인, URL의 위협 평판 점수(0~100)와 알려진 APT 공격 그룹 정보를 조회합니다. 매개변수: 'targetIndicator' (string)";

    private record ThreatEntry(int Score, string Category, string ThreatGroup, string Description);

    private static readonly Dictionary<string, ThreatEntry> KnownThreatDb = new(StringComparer.OrdinalIgnoreCase)
    {
        ["185.220.101.5"] = new(98, "Cobalt Strike / C2 Beacon", "APT29 (Cozy Bear)", "Tor Exit Node 기반 악성 C2 인프라 및 다단계 로더 통신"),
        ["194.165.16.11"] = new(95, "Ransomware Delivery C2", "LockBit 3.0 Affiliate", "초기 침투 및 정보 유출용 리버스 쉘 엔드포인트"),
        ["45.33.32.156"] = new(92, "Meterpreter Reverse TCP", "FIN7 (Carbanak)", "금전 목적 사이버 범죄 그룹 백도어"),
        ["evil-c2.darknet"] = new(99, "Fileless C2 Domain", "Lazarus Group", "난독화 매크로를 통한 2차 페이로드 다운로더"),
        ["malicious-download.com"] = new(90, "Dropper Server", "Generic Malware", "파워셸 인라인 스크립트 배포 서버"),
        ["127.0.0.1"] = new(0, "Local Loopback", "Benign", "로컬 루프백 정상 주소"),
        ["8.8.8.8"] = new(0, "Public DNS", "Google", "공공 DNS 서비스")
    };

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        if (!parameters.TryGetValue("targetIndicator", out var rawIndicator) || rawIndicator is not string indicator || string.IsNullOrWhiteSpace(indicator))
        {
            return Task.FromResult(new ToolResult(false, "매개변수 'targetIndicator'가 제공되지 않았습니다."));
        }

        string cleaned = indicator.Trim().ToLowerInvariant();
        if (cleaned.StartsWith("http://") || cleaned.StartsWith("https://"))
        {
            try
            {
                var uri = new Uri(cleaned);
                cleaned = uri.Host;
            }
            catch { }
        }

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

        // 알 수 없는 공인 IP인 경우 휴리스틱 평가
        bool isPublicIp = System.Net.IPAddress.TryParse(cleaned, out var ip) &&
                          !System.Net.IPAddress.IsLoopback(ip) &&
                          !cleaned.StartsWith("10.") &&
                          !cleaned.StartsWith("192.168.");

        int heuristicScore = isPublicIp ? 75 : 20;
        string hVerdict = isPublicIp ? "SUSPICIOUS_UNKNOWN_EXTERNAL_IP" : "UNKNOWN_BENIGN";
        string hOutput = $"[ThreatReputationTool 조회 결과 - {cleaned}]\n" +
                        $"• 위협 점수: {heuristicScore} / 100 ({hVerdict})\n" +
                        $"• 위협 유형: {(isPublicIp ? "미확인 외부 공인 IP (의심 통신)" : "미등록 내부 또는 일반 주소")}\n" +
                        $"• 연관 공격 그룹: 미확인 (Unattributed)\n" +
                        $"• 비고: 사전 등록된 블랙리스트에는 없으나 외부 통신 문맥 고려 필요";

        var hData = new Dictionary<string, object>
        {
            ["Indicator"] = cleaned,
            ["Score"] = heuristicScore,
            ["Verdict"] = hVerdict,
            ["Category"] = isPublicIp ? "Suspicious External" : "Unknown",
            ["ThreatGroup"] = "None"
        };

        return Task.FromResult(new ToolResult(true, hOutput, hData));
    }
}
