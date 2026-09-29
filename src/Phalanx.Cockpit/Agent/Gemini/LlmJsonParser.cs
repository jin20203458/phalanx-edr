using System.Text.Json;

namespace Phalanx.Cockpit.Agent.Gemini;

/// <summary>
/// LLM 응답 텍스트에서 마크다운 코드블록이나 불필요한 사설을 제거하고 순수 JSON을 안전하게 추출 및 역직렬화하는 헬퍼
/// </summary>
public static class LlmJsonParser
{
    private static readonly JsonSerializerOptions LenientOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        AllowTrailingCommas = true,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    public static string ExtractJson(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return string.Empty;
        }

        string trimmed = rawText.Trim();

        // 1. 마크다운 코드블록 (```json ... ```) 제거
        if (trimmed.StartsWith("```json", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[7..].Trim();
        }
        else if (trimmed.StartsWith("```"))
        {
            trimmed = trimmed[3..].Trim();
        }

        if (trimmed.EndsWith("```"))
        {
            trimmed = trimmed[..^3].Trim();
        }

        // 2. 균형 잡힌 중괄호({ ... }) 추출
        int startIdx = trimmed.IndexOf('{');
        if (startIdx >= 0)
        {
            int depth = 0;
            int endIdx = -1;
            for (int i = startIdx; i < trimmed.Length; i++)
            {
                if (trimmed[i] == '{') depth++;
                else if (trimmed[i] == '}')
                {
                    depth--;
                    if (depth == 0)
                    {
                        endIdx = i;
                        break;
                    }
                }
            }

            if (endIdx > startIdx)
            {
                return trimmed[startIdx..(endIdx + 1)];
            }
        }

        return trimmed;
    }

    public static T? DeserializeSafe<T>(string rawText, JsonSerializerOptions? options = null)
    {
        string json = ExtractJson(rawText);
        if (string.IsNullOrWhiteSpace(json)) return default;

        try
        {
            return JsonSerializer.Deserialize<T>(json, options ?? LenientOptions);
        }
        catch
        {
            return default;
        }
    }
}
