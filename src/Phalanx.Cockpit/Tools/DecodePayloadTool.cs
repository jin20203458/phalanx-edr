using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// Base64, Hex, Gzip/Deflate 등 다단계 난독화 인자를 재귀적으로 해독하고 잠재적 C2 URL/IP 및 명령어를 추출하는 도구 (상용 1티어 EDR 규격)
/// </summary>
public class DecodePayloadTool : IInvestigationTool
{
    public string Name => "DecodePayloadTool";

    public string Description => "Base64, Hex, Gzip 압축 등으로 난독화된 명령줄을 재귀적으로 해독하여 원본 스크립트, URL, IP를 추출합니다. 매개변수: 'encodedCommand' (string)";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex Base64CandidateRegex = new(@"[A-Za-z0-9+/_\-]{8,}={0,2}", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex DelimitedHexRegex = new(@"(?:(?:0x|\\x|\s|^)([0-9a-fA-F]{2}))+", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex ContinuousHexRegex = new(@"\b[0-9a-fA-F]{8,}\b", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex UrlRegex = new(@"https?://[^\s""'>]+", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);
    private static readonly Regex IpRegex = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled, RegexTimeout);

    private const int MaxInputChars = 131072; // 128 KB
    private const int MaxDecompressedBytes = 524288; // 512 KB (Zip Bomb 방어)
    private const int MaxRecursionDepth = 5;

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        string? input = null;
        var caseInsensitive = new Dictionary<string, object>(parameters, StringComparer.OrdinalIgnoreCase);
        foreach (var key in new[] { "encodedCommand", "encoded_command", "command", "payload", "cmd" })
        {
            if (caseInsensitive.TryGetValue(key, out var rawCmd) && rawCmd != null)
            {
                string? s = rawCmd switch
                {
                    string str => str,
                    System.Text.Json.JsonElement je when je.ValueKind == System.Text.Json.JsonValueKind.String => je.GetString(),
                    _ => rawCmd.ToString()
                };

                if (!string.IsNullOrWhiteSpace(s))
                {
                    input = s;
                    break;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(input))
        {
            return Task.FromResult(new ToolResult(false, "매개변수 'encodedCommand'가 제공되지 않았거나 비어있습니다."));
        }

        if (input.Length > MaxInputChars)
        {
            input = input[..MaxInputChars];
        }

        var decodedChain = new List<string>();
        string current = input;
        int depth = 0;

        while (depth < MaxRecursionDepth)
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
        try
        {
            var matches = Base64CandidateRegex.Matches(text);
            foreach (Match match in matches)
            {
                string candidate = match.Value;
                if (candidate.Length < 4) continue;

                string normalized = candidate.Replace('-', '+').Replace('_', '/');
                if (normalized.Length % 4 != 0)
                {
                    normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4), '=');
                }

                try
                {
                    byte[] bytes = Convert.FromBase64String(normalized);
                    string? decoded = TryBytesToString(bytes);
                    if (!string.IsNullOrEmpty(decoded) && decoded != candidate)
                    {
                        return text.Replace(candidate, decoded);
                    }
                }
                catch { }
            }
        }
        catch { }

        // 2. 구분자 있는 Hex 패턴 탐색 (예: 0x41 0x42 또는 \x41\x42)
        try
        {
            var hexMatches = DelimitedHexRegex.Matches(text);
            foreach (Match m in hexMatches)
            {
                if (m.Length >= 8)
                {
                    byte[]? bytes = TryParseHex(m.Value);
                    if (bytes != null)
                    {
                        string? decoded = TryBytesToString(bytes);
                        if (!string.IsNullOrEmpty(decoded))
                        {
                            return text.Replace(m.Value, decoded);
                        }
                    }
                }
            }
        }
        catch { }

        // 3. 연속된 Hex 패턴 탐색
        try
        {
            var contHexMatches = ContinuousHexRegex.Matches(text);
            foreach (Match m in contHexMatches)
            {
                if (m.Length >= 8 && m.Length % 2 == 0)
                {
                    byte[]? bytes = TryParseHex(m.Value);
                    if (bytes != null)
                    {
                        string? decoded = TryBytesToString(bytes);
                        if (!string.IsNullOrEmpty(decoded))
                        {
                            return text.Replace(m.Value, decoded);
                        }
                    }
                }
            }
        }
        catch { }

        // 4. 전체 문자열이 Base64인 경우
        try
        {
            string trimmed = text.Trim();
            if (trimmed.Length >= 4)
            {
                string normalized = trimmed.Replace('-', '+').Replace('_', '/');
                if (normalized.Length % 4 != 0)
                {
                    normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4), '=');
                }

                byte[] bytes = Convert.FromBase64String(normalized);
                string? decoded = TryBytesToString(bytes);
                if (!string.IsNullOrEmpty(decoded)) return decoded;
            }
        }
        catch { }

        // 5. 전체 문자열이 Hex인 경우
        try
        {
            byte[]? bytes = TryParseHex(text);
            if (bytes != null)
            {
                string? decoded = TryBytesToString(bytes);
                if (!string.IsNullOrEmpty(decoded)) return decoded;
            }
        }
        catch { }

        return null;
    }

    private static byte[]? TryDecompress(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B) // GZip Magic (1F 8B)
        {
            try
            {
                using var ms = new MemoryStream(data);
                using var gz = new GZipStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                byte[] buf = new byte[8192];
                int read;
                while ((read = gz.Read(buf, 0, buf.Length)) > 0)
                {
                    outMs.Write(buf, 0, read);
                    if (outMs.Length > MaxDecompressedBytes) break; // Zip Bomb Guard
                }
                return outMs.ToArray();
            }
            catch { }
        }
        else if (data.Length >= 2 && data[0] == 0x78 && (data[1] == 0x9C || data[1] == 0x01 || data[1] == 0xDA || data[1] == 0x5E)) // zlib / Deflate
        {
            try
            {
                using var ms = new MemoryStream(data, 2, data.Length - 2); // Skip 2-byte zlib header
                using var def = new DeflateStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                byte[] buf = new byte[8192];
                int read;
                while ((read = def.Read(buf, 0, buf.Length)) > 0)
                {
                    outMs.Write(buf, 0, read);
                    if (outMs.Length > MaxDecompressedBytes) break;
                }
                return outMs.ToArray();
            }
            catch { }
        }
        return null;
    }

    private static string? TryBytesToString(byte[] rawBytes)
    {
        byte[] bytes = TryDecompress(rawBytes) ?? rawBytes;

        // 1. UTF-8 / ASCII 우선 시도 (일반 텍스트, 스크립트, Hex 결과물)
        try
        {
            string utf8 = Encoding.UTF8.GetString(bytes);
            if (IsPrintable(utf8) && (utf8.Contains(' ') || utf8.Contains('-') || utf8.Contains('/') || utf8.Contains('.') || utf8.Contains('(') || utf8.Contains('$') || utf8.Contains('=')))
            {
                return utf8;
            }
        }
        catch { }

        // 2. Windows PowerShell UTF-16LE 인코딩 (모든 ASCII 문자의 짝수 오프셋 0x00 바이트 패턴 검증)
        try
        {
            if (bytes.Length >= 4 && bytes.Length % 2 == 0)
            {
                string unicode = Encoding.Unicode.GetString(bytes);
                if (IsPrintable(unicode) && (unicode.Contains(' ') || unicode.Contains('-') || unicode.Contains('/') || unicode.Contains('.') || unicode.Contains('(') || unicode.Contains('$') || unicode.Contains('=')))
                {
                    return unicode;
                }
            }
        }
        catch { }

        // 3. 단일 명령어 (공백 없는 경우)
        try
        {
            string utf8 = Encoding.UTF8.GetString(bytes);
            if (IsPrintable(utf8) && utf8.Length >= 3) return utf8;
        }
        catch { }

        try
        {
            if (bytes.Length >= 4 && bytes.Length % 2 == 0)
            {
                string unicode = Encoding.Unicode.GetString(bytes);
                if (IsPrintable(unicode) && unicode.Length >= 3) return unicode;
            }
        }
        catch { }

        return null;
    }

    private static byte[]? TryParseHex(string hex)
    {
        string clean = hex.Replace("0x", "").Replace("\\x", "").Replace(" ", "").Replace(",", "").Trim();
        if (clean.Length < 4 || clean.Length % 2 != 0) return null;

        try
        {
            return Convert.FromHexString(clean);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsPrintable(string str)
    {
        if (string.IsNullOrWhiteSpace(str) || str.Length < 2) return false;
        int printable = 0;
        foreach (char c in str)
        {
            if ((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t' || (c >= 0xAC00 && c <= 0xD7A3))
            {
                printable++;
            }
        }
        return (double)printable / str.Length >= 0.85;
    }
}
