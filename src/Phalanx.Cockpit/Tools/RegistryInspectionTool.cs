using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 윈도우 레지스트리(CLSID, InprocServer32, Run/RunOnce, ScriptletURL 등)의 무결성,
/// LOLBAS 간접 실행 인자, COM 하이재킹(T1546.015), Squiblydoo(T1218.010) 기법을 정밀 분석하는 EDR 7대 포렌식 도구.
/// </summary>
public sealed class RegistryInspectionTool : IInvestigationTool
{
    public string Name => "RegistryInspectionTool";

    public string Description =>
        "윈도우 레지스트리(CLSID, InprocServer32, Run/RunOnce, ScriptletURL)의 무결성, " +
        "LOLBAS 간접 실행 인자, COM 하이재킹(T1546.015), Squiblydoo(T1218.010) 기법을 정밀 분석합니다. " +
        "인자: { \"registryKey\": \"HKCU\\\\...\" 또는 \"keyPath\": \"Software\\\\...\" }";

    #region Clean-Room 시뮬레이션 지원

    public record SimulatedRegistryEntry : Phalanx.Cockpit.Tools.SimulatedRegistryEntry
    {
        public SimulatedRegistryEntry(
            bool Exists,
            string KeyPath,
            string? DefaultValue,
            Dictionary<string, object> Values,
            List<string> SubKeys,
            bool IsIndirectExecution,
            bool IsComHijack,
            int AnomalyScore,
            string DiagnosticReason,
            List<string> ExtractedUrls,
            List<string> ExtractedIps)
            : base(Exists, KeyPath, DefaultValue, Values, SubKeys, IsIndirectExecution,
                   IsComHijack, AnomalyScore, DiagnosticReason, ExtractedUrls, ExtractedIps) { }
    }

    public static void RegisterSimulatedKey(string path, Phalanx.Cockpit.Tools.SimulatedRegistryEntry entry)
    {
        string norm = NormalizeKeyPath(path);
        CleanRoomSimulationStore.RegisterKey(norm, entry);
    }

    public static void ClearSimulatedKeys()
    {
        CleanRoomSimulationStore.ClearKeys();
    }

    public static SimulatedRegistryEntry CreateSimulatedEntry(
        string keyPath,
        bool exists,
        string? defaultValue,
        Dictionary<string, object>? values = null,
        List<string>? subKeys = null)
    {
        string norm = NormalizeKeyPath(keyPath);
        var valDict = new Dictionary<string, object>(values ?? new Dictionary<string, object>(), StringComparer.OrdinalIgnoreCase);
        var subList = subKeys ?? new List<string>();

        var (isIndirect, isComHijack, score, reasons, urls, ips) = AnalyzeRegistryData(norm, defaultValue, valDict, subList);

        return new SimulatedRegistryEntry(
            Exists: exists,
            KeyPath: norm,
            DefaultValue: defaultValue,
            Values: valDict,
            SubKeys: subList,
            IsIndirectExecution: isIndirect,
            IsComHijack: isComHijack,
            AnomalyScore: score,
            DiagnosticReason: reasons.Count > 0 ? string.Join("; ", reasons) : "정상 레지스트리 키 (특이 이상 징후 없음)",
            ExtractedUrls: urls,
            ExtractedIps: ips
        );
    }

    #endregion

    #region 도구 실행 로직 (ExecuteAsync)

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        string? rawPath = parameters.GetStringFallback(new[] { "registryKey", "keyPath", "key", "path", "targetKey" }, "key", "path");
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            return Task.FromResult(new ToolResult(false, "[RegistryInspectionTool 오류] 'registryKey' 또는 'keyPath' 인자가 누락되었거나 비어 있습니다."));
        }

        string normalized = NormalizeKeyPath(rawPath);

        // 1. Clean-Room 모의 레지스트리 우선 조회
        if (CleanRoomSimulationStore.TryGetKey(normalized, out var sim))
        {
            return Task.FromResult(FormatResult(sim, normalized, isSimulated: true));
        }

        // 2. 실제 OS 레지스트리 안전 조회 (플랫폼 가드 및 읽기 전용)
        if (!OperatingSystem.IsWindows())
        {
            var nonWinData = new Dictionary<string, object>
            {
                ["Exists"] = false,
                ["KeyPath"] = normalized,
                ["IsIndirectExecution"] = false,
                ["IsComHijack"] = false,
                ["AnomalyScore"] = 0,
                ["DiagnosticReason"] = "비Windows 환경에서는 실제 레지스트리 조회가 지원되지 않습니다."
            };
            return Task.FromResult(new ToolResult(true, $"[RegistryInspectionTool] 비Windows 환경: '{normalized}'", nonWinData));
        }

        try
        {
            var (hive, subPath) = ParseHiveAndSubPath(normalized);
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var targetKey = baseKey.OpenSubKey(subPath, writable: false);

            if (targetKey == null)
            {
                var notFoundData = new Dictionary<string, object>
                {
                    ["Exists"] = false,
                    ["KeyPath"] = normalized,
                    ["DefaultValue"] = null!,
                    ["IsIndirectExecution"] = false,
                    ["IsComHijack"] = false,
                    ["AnomalyScore"] = 0,
                    ["DiagnosticReason"] = $"레지스트리 키가 존재하지 않습니다: '{normalized}'",
                    ["ExtractedUrls"] = new List<string>(),
                    ["ExtractedIps"] = new List<string>()
                };
                return Task.FromResult(new ToolResult(true, $"[RegistryInspectionTool] 레지스트리 키 미발견: '{normalized}'", notFoundData));
            }

            string? defaultValue = targetKey.GetValue(string.Empty)?.ToString();
            var valDict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (var valName in targetKey.GetValueNames())
            {
                valDict[valName] = targetKey.GetValue(valName) ?? string.Empty;
            }

            var subList = new List<string>(targetKey.GetSubKeyNames());

            var (isIndirect, isComHijack, score, reasons, urls, ips) = AnalyzeRegistryData(normalized, defaultValue, valDict, subList);

            var entry = new SimulatedRegistryEntry(
                Exists: true,
                KeyPath: normalized,
                DefaultValue: defaultValue,
                Values: valDict,
                SubKeys: subList,
                IsIndirectExecution: isIndirect,
                IsComHijack: isComHijack,
                AnomalyScore: score,
                DiagnosticReason: reasons.Count > 0 ? string.Join("; ", reasons) : "정상 레지스트리 키 (특이 이상 징후 없음)",
                ExtractedUrls: urls,
                ExtractedIps: ips
            );

            return Task.FromResult(FormatResult(entry, normalized, isSimulated: false));
        }
        catch (SecurityException sex)
        {
            return Task.FromResult(new ToolResult(true, $"[RegistryInspectionTool 접근 거부] 권한 부족: {sex.Message}"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new ToolResult(false, $"[RegistryInspectionTool 예외] 레지스트리 분석 중 오류 발생: {ex.Message}"));
        }
    }

    #endregion

    #region 레지스트리 이상 징후 분석 및 휴리스틱 (AnalyzeRegistryData)

    private static (bool IsIndirect, bool IsComHijack, int Score, List<string> Reasons, List<string> Urls, List<string> Ips)
        AnalyzeRegistryData(string keyPath, string? defaultValue, Dictionary<string, object> values, List<string> subKeys)
    {
        bool isIndirect = false;
        bool isComHijack = false;
        int score = 0;
        var reasons = new List<string>();
        var urls = new List<string>();
        var ips = new List<string>();

        // 텍스트 집합 수집
        var allTexts = new List<string>();
        if (!string.IsNullOrEmpty(defaultValue)) allTexts.Add(defaultValue);
        foreach (var v in values.Values)
        {
            if (v != null) allTexts.Add(v.ToString()!);
        }

        string fullCombined = string.Join(" ", allTexts);

        // 1. URL 및 IP 추출
        var urlMatches = Regex.Matches(fullCombined, @"https?://[^\s""'>)]+", RegexOptions.IgnoreCase);
        foreach (Match m in urlMatches) urls.Add(m.Value);

        var ipMatches = Regex.Matches(fullCombined, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
        foreach (Match m in ipMatches)
        {
            if (!m.Value.StartsWith("0.") && !m.Value.StartsWith("127."))
            {
                ips.Add(m.Value);
            }
        }

        // 2. Squiblydoo / Scriptlet 간접 실행 분석 (T1218.010)
        bool hasScriptletUrl = values.ContainsKey("ScriptletURL") || fullCombined.Contains(".sct", StringComparison.OrdinalIgnoreCase);
        bool hasScriptletPayload = fullCombined.Contains("<scriptlet", StringComparison.OrdinalIgnoreCase) ||
                                  fullCombined.Contains("<component", StringComparison.OrdinalIgnoreCase) ||
                                  fullCombined.Contains("ActiveXObject", StringComparison.OrdinalIgnoreCase) ||
                                  fullCombined.Contains("WScript.Shell", StringComparison.OrdinalIgnoreCase) ||
                                  fullCombined.Contains("scrobj.dll", StringComparison.OrdinalIgnoreCase);

        if (hasScriptletUrl || (keyPath.Contains("CLSID", StringComparison.OrdinalIgnoreCase) && hasScriptletPayload))
        {
            isIndirect = true;
            score += 50;
            reasons.Add("레지스트리 내 스크립틀릿(ScriptletURL/scrobj.dll) 간접 실행 페이로드 검출 (T1218.010)");

            if (urls.Count > 0 || ips.Count > 0)
            {
                score += 30;
                reasons.Add($"스크립틀릿 내 원격 C2 통신 지표 포착 (URL: {string.Join(", ", urls)}, IP: {string.Join(", ", ips)})");
            }
        }

        // 3. COM 하이재킹 분석 (T1546.015)
        if (keyPath.Contains("CLSID", StringComparison.OrdinalIgnoreCase))
        {
            string serverPath = string.Empty;
            if (values.TryGetValue("InprocServer32", out var serverObj) || values.TryGetValue("", out serverObj))
            {
                serverPath = serverObj?.ToString() ?? string.Empty;
            }
            else if (!string.IsNullOrEmpty(defaultValue))
            {
                serverPath = defaultValue;
            }

            if (!string.IsNullOrEmpty(serverPath))
            {
                bool isUserPath = serverPath.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ||
                                  serverPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                  serverPath.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) ||
                                  serverPath.Contains(@"\Public\", StringComparison.OrdinalIgnoreCase);

                if (isUserPath)
                {
                    isComHijack = true;
                    score += 50;
                    reasons.Add($"사용자/임시 디렉터리 바이너리를 가리키는 COM 서버 등록 포착 (T1546.015 COM Hijacking: '{serverPath}')");
                }
            }
        }

        // 4. Run / RunOnce 지속성 의심 분석 (T1547.001)
        if (keyPath.Contains(@"\Run", StringComparison.OrdinalIgnoreCase) || keyPath.Contains(@"\RunOnce", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var kvp in values)
            {
                string cmd = kvp.Value?.ToString()?.ToLowerInvariant() ?? string.Empty;
                if (cmd.Contains("powershell") || cmd.Contains("mshta") || cmd.Contains("cmd.exe") || cmd.Contains("regsvr32") || cmd.Contains("rundll32"))
                {
                    score += 40;
                    reasons.Add($"Run/RunOnce 키에 LOLBAS 실행 명령 등록 포착 ('{kvp.Key}' -> '{cmd}')");
                }
            }
        }

        score = Math.Clamp(score, 0, 100);
        return (isIndirect, isComHijack, score, reasons, urls, ips);
    }

    #endregion

    #region 보조 헬퍼 메서드


    private static string NormalizeKeyPath(string keyPath)
    {
        string trimmed = keyPath.Trim(' ', '\t', '"', '\'');
        if (trimmed.StartsWith(@"/i:", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[3..].Trim(' ', '\t', '"', '\'');
        }

        // 슬래시 표준화 (단, URL 제외)
        if (!trimmed.Contains("://"))
        {
            trimmed = trimmed.Replace('/', '\\');
        }

        if (trimmed.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase)) return "HKEY_CURRENT_USER\\" + trimmed[5..];
        if (trimmed.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase)) return "HKEY_LOCAL_MACHINE\\" + trimmed[5..];
        if (trimmed.StartsWith("HKCR\\", StringComparison.OrdinalIgnoreCase)) return "HKEY_CLASSES_ROOT\\" + trimmed[5..];

        if (trimmed.StartsWith("Software\\", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("CLSID\\", StringComparison.OrdinalIgnoreCase))
        {
            return "HKEY_CURRENT_USER\\" + trimmed;
        }

        return trimmed;
    }

    private static (RegistryHive Hive, string SubPath) ParseHiveAndSubPath(string normalizedPath)
    {
        string norm = normalizedPath.Trim('\\');
        if (norm.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
            return (RegistryHive.CurrentUser, norm.Length > 17 ? norm[17..].TrimStart('\\') : string.Empty);
        if (norm.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
            return (RegistryHive.LocalMachine, norm.Length > 18 ? norm[18..].TrimStart('\\') : string.Empty);
        if (norm.StartsWith("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase))
            return (RegistryHive.ClassesRoot, norm.Length > 17 ? norm[17..].TrimStart('\\') : string.Empty);
        if (norm.StartsWith("HKEY_USERS", StringComparison.OrdinalIgnoreCase))
            return (RegistryHive.Users, norm.Length > 10 ? norm[10..].TrimStart('\\') : string.Empty);

        return (RegistryHive.CurrentUser, norm);
    }

    private static ToolResult FormatResult(Phalanx.Cockpit.Tools.SimulatedRegistryEntry entry, string normalizedPath, bool isSimulated)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[RegistryInspectionTool 포렌식 검증 결과{(isSimulated ? " (Clean-Room Simulation)" : "")}]");
        sb.AppendLine($"• 대상 키: {normalizedPath}");
        sb.AppendLine($"• 키 존재: {(entry.Exists ? "O (Exists)" : "X (NotFound)")}");
        if (!string.IsNullOrEmpty(entry.DefaultValue)) sb.AppendLine($"• 기본값: {entry.DefaultValue}");
        sb.AppendLine($"• 포함된 값(Values): {entry.Values.Count}개");
        sb.AppendLine($"• 포함된 하위키(SubKeys): {entry.SubKeys.Count}개");
        sb.AppendLine($"• 간접 실행(Indirect Execution T1218.010): {(entry.IsIndirectExecution ? "DETECTED (Squiblydoo / Scriptlet)" : "Normal")}");
        sb.AppendLine($"• COM 하이재킹(COM Hijack T1546.015): {(entry.IsComHijack ? "DETECTED (Suspicious Server Path)" : "Normal")}");
        if (entry.ExtractedUrls.Count > 0) sb.AppendLine($"• 추출된 C2 URL: {string.Join(", ", entry.ExtractedUrls)}");
        if (entry.ExtractedIps.Count > 0) sb.AppendLine($"• 추출된 C2 IP: {string.Join(", ", entry.ExtractedIps)}");
        sb.AppendLine($"• 복합 이상 징후 위험도: {entry.AnomalyScore}/100");
        sb.AppendLine($"• 정밀 진단 소견: {entry.DiagnosticReason}");

        var data = new Dictionary<string, object>
        {
            ["Exists"] = entry.Exists,
            ["KeyPath"] = normalizedPath,
            ["DefaultValue"] = entry.DefaultValue ?? string.Empty,
            ["Values"] = entry.Values,
            ["SubKeys"] = entry.SubKeys,
            ["IsIndirectExecution"] = entry.IsIndirectExecution,
            ["IsComHijack"] = entry.IsComHijack,
            ["ExtractedUrls"] = entry.ExtractedUrls,
            ["ExtractedIps"] = entry.ExtractedIps,
            ["AnomalyScore"] = entry.AnomalyScore,
            ["DiagnosticReason"] = entry.DiagnosticReason
        };

        return new ToolResult(Success: true, Output: sb.ToString().TrimEnd(), Data: data);
    }

    #endregion
}
