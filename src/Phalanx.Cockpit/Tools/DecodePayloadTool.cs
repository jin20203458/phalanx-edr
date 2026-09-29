using System.Text;
using System.Text.RegularExpressions;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// Base64, Hex 등 다단계 난독화 인자를 재귀적으로 해독하고 잠재적 C2 URL/IP 및 명령어를 추출하는 도구
/// </summary>
public class DecodePayloadTool : IInvestigationTool
{
    public string Name => "DecodePayloadTool";

    public string Description => "Base64 또는 Hex로 인코딩된 난독화 명령줄을 재귀적으로 해독하여 원본 스크립트, URL, IP를 추출합니다. 매개변수: 'encodedCommand' (string)";

    private static readonly Regex Base64CandidateRegex = new(@"[A-Za-z0-9+/]{20,}={0,2}", RegexOptions.Compiled);
    private static readonly Regex UrlRegex = new(@"https?://[^\s""'>]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex IpRegex = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled);

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        if (!parameters.TryGetValue("encodedCommand", out var rawCmd) || rawCmd is not string input || string.IsNullOrWhiteSpace(input))
        {
            return Task.FromResult(new ToolResult(false, "매개변수 'encodedCommand'가 제공되지 않았거나 비어있습니다."));
        }

        var decodedChain = new List<string>();
        string current = input;
        int depth = 0;
        const int maxDepth = 5;

        while (depth < maxDepth)
        {
            string? nextDecoded = TryDecodeStage(current);
            if (string.IsNullOrWhiteSpace(nextDecoded) || nextDecoded == current)
            {
                break;
            }
            decodedChain.Add(nextDecoded);
            current = nextDecoded;
            depth++;
        }

        string finalPayload = decodedChain.Count > 0 ? decodedChain[^1] : input;

        // URL 및 IP 추출
        var urls = UrlRegex.Matches(finalPayload).Select(m => m.Value).Distinct().ToList();
        var ips = IpRegex.Matches(finalPayload).Select(m => m.Value).Distinct().ToList();

        var sb = new StringBuilder();
        sb.AppendLine($"[DecodePayloadTool 해독 완료 - 총 {depth}단계 디코딩]");
        if (decodedChain.Count > 0)
        {
            sb.AppendLine($"최종 해독 텍스트:\n{finalPayload}\n");
        }
        else
        {
            sb.AppendLine($"직접 난독화 해독 대상이 없어 원본 텍스트 분석 수행:\n{input}\n");
        }

        if (urls.Count > 0)
        {
            sb.AppendLine($"발견된 C2 URL 목록: {string.Join(", ", urls)}");
        }
        if (ips.Count > 0)
        {
            sb.AppendLine($"발견된 IP 목록: {string.Join(", ", ips)}");
        }

        var data = new Dictionary<string, object>
        {
            ["DecodedPayload"] = finalPayload,
            ["DecodeDepth"] = depth,
            ["ExtractedUrls"] = urls,
            ["ExtractedIps"] = ips,
        };

        return Task.FromResult(new ToolResult(true, sb.ToString(), data));
    }

    private static string? TryDecodeStage(string text)
    {
        // 1. Base64 패턴 추출 후 디코딩 시도
        var matches = Base64CandidateRegex.Matches(text);
        foreach (Match match in matches)
        {
            string candidate = match.Value;
            try
            {
                byte[] bytes = Convert.FromBase64String(candidate);
                // Windows PowerShell 은 주로 UTF-16LE(Unicode)로 인코딩
                string unicodeStr = Encoding.Unicode.GetString(bytes);
                if (IsPrintable(unicodeStr) && (unicodeStr.Contains(" ") || unicodeStr.Contains("-") || unicodeStr.Contains("http")))
                {
                    return text.Replace(candidate, unicodeStr);
                }

                string utf8Str = Encoding.UTF8.GetString(bytes);
                if (IsPrintable(utf8Str) && (utf8Str.Contains(" ") || utf8Str.Contains("-") || utf8Str.Contains("http")))
                {
                    return text.Replace(candidate, utf8Str);
                }
            }
            catch
            {
                // 변환 실패 시 다음 후보 계속
            }
        }

        // 2. 전체 문자열이 Base64인 경우
        try
        {
            string trimmed = text.Trim();
            if (trimmed.Length >= 8 && trimmed.Length % 4 == 0)
            {
                byte[] bytes = Convert.FromBase64String(trimmed);
                string unicodeStr = Encoding.Unicode.GetString(bytes);
                if (IsPrintable(unicodeStr)) return unicodeStr;

                string utf8Str = Encoding.UTF8.GetString(bytes);
                if (IsPrintable(utf8Str)) return utf8Str;
            }
        }
        catch { }

        return null;
    }

    private static bool IsPrintable(string str)
    {
        if (string.IsNullOrEmpty(str)) return false;
        int printable = str.Count(c => !char.IsControl(c) || c == '\r' || c == '\n' || c == '\t');
        return (double)printable / str.Length > 0.85;
    }
}
