using System;
using System.Text.RegularExpressions;

namespace Phalanx.Cockpit.Agent;

/// <summary>
/// 자율 위협 헌팅 에이전트(AutonomousHunterAgent)의 클라우드 ReAct 루프 및 오프라인 룰 엔진에서
/// 공통으로 사용하는 무상태(Stateless) 공격 패턴 정규식 및 휴리스틱 분석 유틸리티.
/// </summary>
public static class AttackPatternHeuristics
{
    /// <summary>
    /// 의심스러운 상위 프로세스(오피스, 브라우저 등 비정상 자식 프로세스 유발자) 여부를 검사합니다.
    /// </summary>
    public static bool IsSuspiciousParent(string rootCause)
    {
        string rc = rootCause.ToLowerInvariant();
        return rc.Contains("winword") || rc.Contains("excel") || rc.Contains("powerpnt") ||
               rc.Contains("outlook") || rc.Contains("acrord32") || rc.Contains("acrobat") ||
               rc.Contains("hwp") || rc.Contains("chrome") || rc.Contains("msedge");
    }

    /// <summary>
    /// 커맨드라인 및 디코딩된 스크립트 내 인라인 C2 다운로드 및 실행 패턴을 탐지합니다.
    /// </summary>
    public static bool HasInlineC2Pattern(string? decodedScript, string commandLine)
    {
        string target = $"{commandLine} {decodedScript}".ToLowerInvariant();

        // 127.0.0.1 또는 localhost 로컬 루프백만을 대상으로 하는 내부 개발/헬스체크 명령은 외부 C2 패턴에서 제외
        bool isLoopbackOnly = (target.Contains("127.0.0.1") || target.Contains("localhost")) &&
                              !target.Contains("185.220.") && !target.Contains("194.165.") &&
                              !target.Contains("45.33.") && !target.Contains("198.51.");
        if (isLoopbackOnly && (target.Contains("curl") || target.Contains("http://127.0.0.1") || target.Contains("http://localhost")))
        {
            return false;
        }

        return target.Contains("downloadstring") ||
               target.Contains("downloadfile") ||
               target.Contains("net.webclient") ||
               target.Contains("invoke-webrequest") ||
               target.Contains("curl") ||
               target.Contains("wget") ||
               target.Contains("http://") ||
               target.Contains("https://") ||
               target.Contains("iex ") ||
               target.Contains("iex(") ||
               target.Contains("invoke-expression");
    }

    /// <summary>
    /// 랜섬웨어 섀도 복사본 삭제 및 부팅 복구 비활성화 등 파괴적 명령 여부를 검사합니다.
    /// </summary>
    public static bool IsRansomwareDestructiveCommand(string commandLine, string imageName)
    {
        string target = $"{imageName} {commandLine}".ToLowerInvariant();
        if (target.Contains("vssadmin") && target.Contains("delete") && target.Contains("shadows")) return true;
        if (target.Contains("bcdedit") && (target.Contains("recoveryenabled") || target.Contains("ignoreallfailures"))) return true;
        if (target.Contains("wbadmin") && (target.Contains("delete catalog") || target.Contains("systemstatebackup"))) return true;
        return false;
    }

    /// <summary>
    /// 내부 관리용 도메인 및 정상 관리 명령어 기반의 신뢰 프로세스 여부를 판별합니다.
    /// </summary>
    public static bool IsKnownInternalOrTrusted(string? decodedScript, string commandLine, string? extractedIp)
    {
        string target = $"{commandLine} {decodedScript}".ToLowerInvariant();

        bool hasInternalDomain = target.Contains(".corp.local") ||
                                target.Contains(".internal") ||
                                target.Contains(".local") ||
                                target.Contains("localhost") ||
                                target.Contains("127.0.0.1");

        bool hasInternalCmd = target.Contains("get-service") ||
                              target.Contains("restart-service") ||
                              target.Contains("get-wmiobject") ||
                              target.Contains("get-process") ||
                              target.Contains("curl") ||
                              target.Contains("backup") ||
                              target.Contains("inventory");

        if (hasInternalDomain || hasInternalCmd)
        {
            if (extractedIp == null || extractedIp.StartsWith("10.") || extractedIp.StartsWith("192.168.") || extractedIp.StartsWith("127."))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 커맨드라인 및 디코딩된 페이로드에서 타깃 파일 시스템 절대 경로를 정규식으로 추출합니다.
    /// </summary>
    public static string? ExtractTargetFilePath(string? decodedScript, string commandLine)
    {
        string full = $"{commandLine} {decodedScript}";
        var match = Regex.Match(full, @"[a-zA-Z]:\\[^'""\s,;)]+", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            return match.Value;
        }
        return null;
    }

    /// <summary>
    /// 커맨드라인 및 디코딩된 페이로드에서 타깃 윈도우 레지스트리 키 경로를 정규식으로 추출합니다.
    /// </summary>
    public static string? ExtractTargetRegistryKey(string? decodedScript, string commandLine)
    {
        string full = $"{commandLine} {decodedScript}";

        // 1. regsvr32 /i: 인자 추출 (/i: 또는 /i:"...")
        var iMatch = Regex.Match(
            full,
            @"/i:(?:""([^""]+)""|([^\s]+))",
            RegexOptions.IgnoreCase);
        if (iMatch.Success)
        {
            string candidate = !string.IsNullOrEmpty(iMatch.Groups[1].Value)
                ? iMatch.Groups[1].Value
                : iMatch.Groups[2].Value;

            // 원격 HTTP(S) URL은 ThreatReputationTool 대상이므로 레지스트리 키 추출 대상에서 제외
            if (!candidate.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return candidate.Trim(' ', '\t', '"', '\'');
            }
        }

        // 2. 표준 Hive 또는 CLSID 직접 경로 추출
        var regMatch = Regex.Match(
            full,
            @"(?:HKCU|HKLM|HKCR|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|Software\\Classes\\CLSID|CLSID)\\[^\s""',;)]+",
            RegexOptions.IgnoreCase);
        if (regMatch.Success)
        {
            return regMatch.Value.Trim(' ', '\t', '"', '\'');
        }

        return null;
    }
}
