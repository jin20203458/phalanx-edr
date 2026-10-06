namespace Phalanx.Cockpit.Tools;

using System;
using System.Collections.Generic;
using System.Text.Json;

/// <summary>
/// IInvestigationTool 파라미터 추출을 위한 고성능 공통 확장 메서드.
/// 딕셔너리 재할당 없이 대소문자 무시 키 조회 및 타입(string, JsonElement, number) 안전 변환을 지원합니다.
/// </summary>
public static class ToolParameterExtensions
{
    public static string? GetString(this IReadOnlyDictionary<string, object>? parameters, params string[] keys)
    {
        if (parameters == null || parameters.Count == 0 || keys == null || keys.Length == 0)
            return null;

        foreach (var key in keys)
        {
            if (TryGetCaseInsensitive(parameters, key, out var val) && val != null)
            {
                var extracted = val switch
                {
                    string s => s,
                    JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString(),
                    JsonElement je => je.ToString(),
                    _ => val.ToString()
                };

                if (!string.IsNullOrWhiteSpace(extracted))
                    return extracted;
            }
        }
        return null;
    }

    public static string? GetStringFallback(this IReadOnlyDictionary<string, object>? parameters, string[] directKeys, params string[] substringFallbacks)
    {
        var result = parameters.GetString(directKeys);
        if (!string.IsNullOrWhiteSpace(result))
            return result;

        if (parameters == null || parameters.Count == 0 || substringFallbacks == null || substringFallbacks.Length == 0)
            return null;

        foreach (var kvp in parameters)
        {
            foreach (var fallback in substringFallbacks)
            {
                if (kvp.Key.IndexOf(fallback, StringComparison.OrdinalIgnoreCase) >= 0 && kvp.Value != null)
                {
                    var extracted = kvp.Value switch
                    {
                        string s => s,
                        JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString(),
                        JsonElement je => je.ToString(),
                        _ => kvp.Value.ToString()
                    };
                    if (!string.IsNullOrWhiteSpace(extracted))
                        return extracted;
                }
            }
        }
        return null;
    }

    public static uint? GetUInt32(this IReadOnlyDictionary<string, object>? parameters, params string[] keys)
    {
        if (parameters == null || parameters.Count == 0 || keys == null || keys.Length == 0)
            return null;

        foreach (var key in keys)
        {
            if (TryGetCaseInsensitive(parameters, key, out var val) && val != null)
            {
                switch (val)
                {
                    case uint u: return u;
                    case int i when i >= 0: return (uint)i;
                    case long l when l >= 0 && l <= uint.MaxValue: return (uint)l;
                    case string s when uint.TryParse(s, out var parsed): return parsed;
                    case JsonElement je when je.ValueKind == JsonValueKind.Number && je.TryGetUInt32(out var ju): return ju;
                    case JsonElement je when je.ValueKind == JsonValueKind.Number && je.TryGetInt32(out var ji) && ji >= 0: return (uint)ji;
                    case JsonElement je when je.ValueKind == JsonValueKind.String && uint.TryParse(je.GetString(), out var js): return js;
                }
            }
        }
        return null;
    }

    public static int? GetInt32(this IReadOnlyDictionary<string, object>? parameters, params string[] keys)
    {
        if (parameters == null || parameters.Count == 0 || keys == null || keys.Length == 0)
            return null;

        foreach (var key in keys)
        {
            if (TryGetCaseInsensitive(parameters, key, out var val) && val != null)
            {
                switch (val)
                {
                    case int i: return i;
                    case uint u when u <= int.MaxValue: return (int)u;
                    case long l when l >= int.MinValue && l <= int.MaxValue: return (int)l;
                    case string s when int.TryParse(s, out var parsed): return parsed;
                    case JsonElement je when je.ValueKind == JsonValueKind.Number && je.TryGetInt32(out var ji): return ji;
                    case JsonElement je when je.ValueKind == JsonValueKind.String && int.TryParse(je.GetString(), out var js): return js;
                }
            }
        }
        return null;
    }

    private static bool TryGetCaseInsensitive(IReadOnlyDictionary<string, object> dict, string targetKey, out object? value)
    {
        if (dict.TryGetValue(targetKey, out value))
            return true;

        foreach (var kvp in dict)
        {
            if (string.Equals(kvp.Key, targetKey, StringComparison.OrdinalIgnoreCase))
            {
                value = kvp.Value;
                return true;
            }
        }
        value = null;
        return false;
    }
}
