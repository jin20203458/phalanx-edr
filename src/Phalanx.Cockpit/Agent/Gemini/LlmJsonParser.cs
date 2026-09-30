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

    public static string? ExtractJson(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText)) return null;

        int startIndex = rawText.IndexOf('{');
        if (startIndex < 0) return null; // JSON 객체가 아예 없음

        int openCount = 0;
        int endIndex = -1;
        bool inString = false;
        bool isEscaped = false;

        // MundusVivens & GRC 표준: 문자열 내부("...") 및 이스케이프(\")를 완벽히 추적하여 문자열 내 중괄호 오작동 방지
        for (int i = startIndex; i < rawText.Length; i++)
        {
            char c = rawText[i];

            if (inString)
            {
                if (c == '\\') isEscaped = !isEscaped;
                else if (c == '"' && !isEscaped) { inString = false; isEscaped = false; }
                else isEscaped = false;
            }
            else
            {
                if (c == '"') inString = true;
                else if (c == '{') openCount++;
                else if (c == '}')
                {
                    openCount--;
                    if (openCount == 0)
                    {
                        endIndex = i;
                        break;
                    }
                }
            }
        }

        if (endIndex > startIndex)
        {
            return rawText.Substring(startIndex, endIndex - startIndex + 1);
        }

        return null; // 괄호 짝이 맞지 않아 추출 실패
    }

    public static T? DeserializeSafe<T>(string rawText, JsonSerializerOptions? options = null)
    {
        string? json = ExtractJson(rawText);
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
