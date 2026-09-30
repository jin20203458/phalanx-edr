using System.Text;
using System.Text.RegularExpressions;

namespace Phalanx.Cockpit.Tools;

public record MitreTechnique(string Id, string Name, string Tactic, string Description, int KillChainOrder);

/// <summary>
/// 관찰된 공격 행위 및 족보 패턴을 기반으로 MITRE ATT&CK Matrix TTP 기법을 단어 경계 정규식과
/// 10단계 사이버 킬체인(Cyber Kill Chain)으로 정밀 분류하는 상용 1티어 도구
/// </summary>
public class MitreClassifierTool : IInvestigationTool
{
    public string Name => "MitreClassifierTool";

    public string Description => "관찰된 프로세스 족보, 커맨드라인, 네트워크 행위를 분석하여 MITRE ATT&CK Matrix TTP 기법으로 자동 매핑합니다. 매개변수: 'observedBehavior' (string)";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private record MitreRule(Regex Pattern, MitreTechnique Technique);

    private static readonly List<MitreRule> Rules = new()
    {
        // 1. Initial Access (Order: 1)
        new(
            new Regex(@"\b(?:winword|excel|powerpnt|outlook)(?:\.exe)?\b.*?(?:->|spawn|\s).*?\b(?:powershell|cmd|mshta|wscript|cscript)(?:\.exe)?\b|\b(?:winword|excel|powerpnt|outlook)\b.*?\b(?:powershell|cmd|mshta|wscript)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1566.001", "Spearphishing Attachment (Office LOLBAS Spawn)", "Initial Access", "사용자 오피스 매크로 또는 첨부파일을 통해 자식 스크립트 실행기를 기동하여 초기 접근을 획득하는 기법", 1)
        ),
        new(
            new Regex(@"\b(?:chrome|msedge|firefox|brave)(?:\.exe)?\b.*?(?:->|spawn|\s).*?\b(?:powershell|cmd|certutil|bitsadmin)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1189", "Drive-by Compromise", "Initial Access", "웹 브라우저를 통해 신뢰되지 않은 웹사이트 방문 중 악성 스크립트/바이너리가 기동되는 기법", 1)
        ),

        // 2. Execution (Order: 2)
        new(
            new Regex(@"\b(?:powershell|pwsh)(?:\.exe)?\b.*?(?:-enc\b|-encodedcommand|-nop\b|-noprofile|-w\s+hidden|invoke-expression|\biex\b|downloadstring)|-enc\s+[A-Za-z0-9+/=]{4,}|\b(?:invoke-expression|\biex\b)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "탐지 우회를 위해 인자를 난독화하거나 메모리 상에서 직접 파워셸 스크립트를 실행하는 기법", 2)
        ),
        new(
            new Regex(@"\bcmd(?:\.exe)?\b\s+(?:/c|/k)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution", "Windows cmd.exe 명령어 인터프리터를 통해 스크립트 또는 배치 명령을 은밀히 실행하는 기법", 2)
        ),
        new(
            new Regex(@"\b(?:wscript|cscript)(?:\.exe)?\b.*?\.(?:vbs|js|vbe|jse)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1059.005", "Command and Scripting Interpreter: Visual Basic / JScript", "Execution", "Windows 스크립트 호스트를 악용하여 난독화된 VBScript/JScript를 실행하는 기법", 2)
        ),

        // 3. Persistence (Order: 3)
        new(
            new Regex(@"\b(?:reg(?:\.exe)?\s+add\b.*?\\currentversion\\(?:run|runonce)|new-itemproperty.*?\\currentversion\\run)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence", "시스템 부팅 시 악성 페이로드가 자동 실행되도록 레지스트리 Run 키를 등록하는 기법", 3)
        ),
        new(
            new Regex(@"\bschtasks(?:\.exe)?\s+/(?:create|change)\b|\bnew-scheduledtask\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence", "윈도우 작업 스케줄러를 등록하여 주기적으로 악성 코드를 백그라운드에서 기동하는 기법", 3)
        ),

        // 4. Privilege Escalation (Order: 4)
        new(
            new Regex(@"\b(?:fodhelper|eventvwr|slui|sdclt|computerdefaults)(?:\.exe)?\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1548.002", "Abuse Elevation Control Mechanism: Bypass UAC", "Privilege Escalation", "자동 승인 바이너리의 레지스트리 하이재킹을 통해 UAC 알림창 없이 최고 관리자 권한을 획득하는 기법", 4)
        ),

        // 5. Defense Evasion (Order: 5)
        new(
            new Regex(@"\b(?:readprocessmemory|virtualalloc(?:ex)?|createremotethread|writeprocessmemory|ntqueueapcthread|hollowing|reflective\s+dll)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1055", "Process Injection", "Defense Evasion, Privilege Escalation", "정상 프로세스의 가상 메모리 공간에 악성 코드를 주입하여 백신 검사를 우회하고 은밀히 실행하는 기법", 5)
        ),
        new(
            new Regex(@"\brundll32(?:\.exe)?\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion", "rundll32.exe 신뢰 바이너리를 악용하여 임의의 악성 DLL 내보내기 함수를 우회 실행하는 기법", 5)
        ),
        new(
            new Regex(@"\bregsvr32(?:\.exe)?\b.*?(?:/s|/u|/i)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1218.010", "System Binary Proxy Execution: Regsvr32 (Squiblydoo)", "Defense Evasion", "regsvr32.exe를 이용하여 원격 COM 스크립트릿(sct)을 로드하고 애플리케이션 화이트리스트를 우회하는 기법", 5)
        ),
        new(
            new Regex(@"\b(?:bitsadmin(?:\.exe)?\s+/transfer|certutil(?:\.exe)?\s+-urlcache)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1197", "BITS Jobs / Living off the Land", "Defense Evasion", "백그라운드 지능형 전송 서비스(BITS)를 악용하여 방화벽을 우회해 악성 페이로드를 다운로드하는 기법", 5)
        ),
        new(
            new Regex(@"\bcertutil(?:\.exe)?\s+(?:-decode|-encode)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "인증서 관리 도구 certutil을 악용하여 Base64로 인코딩된 악성 페이로드를 디코딩하는 기법", 5)
        ),
        new(
            new Regex(@"\b(?:set-mppreference\s+-disablerealtimemonitoring|fltmc\s+unload\s+sysmon)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion", "Windows Defender 실시간 감시를 무력화하거나 보안 에이전트 미니필터를 언로드하는 기법", 5)
        ),

        // 6. Credential Access (Order: 6)
        new(
            new Regex(@"\b(?:mimikatz|sekurlsa|procdump(?:\.exe)?\s+.*?lsass|comsvcs(?:\.dll)?\s+.*?minidump)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access", "LSASS 프로세스 메모리를 덤프하여 일반 텍스트 비밀번호, NTLM 해시, 커버로스 티켓을 탈취하는 기법", 6)
        ),

        // 7. Discovery (Order: 7)
        new(
            new Regex(@"\b(?:whoami(?:\.exe)?\s+/(?:priv|all)|whoami\b|net\s+user\b|net\s+localgroup\b)", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1087", "Account Discovery", "Discovery", "시스템에 존재하는 사용자 계정, 소속 관리자 그룹 및 현재 획득한 시스템 권한을 탐색하는 기법", 7)
        ),
        new(
            new Regex(@"\b(?:ipconfig(?:\.exe)?\s+/all|route\s+print|netstat\s+-an|arp\s+-a)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1016", "System Network Configuration Discovery", "Discovery", "감염된 엔드포인트의 네트워크 인터페이스, 라우팅 테이블, 활성 포트를 정찰하는 기법", 7)
        ),

        // 8. Lateral Movement (Order: 8)
        new(
            new Regex(@"\b(?:psexec|net\s+use\s+.*\\admin\$|wmic(?:\.exe)?\s+.*?process\s+call\s+create)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "SMB 관리 공유 폴더(ADMIN$, C$) 또는 PsExec을 통해 사내망 다른 엔드포인트로 전파하는 기법", 8)
        ),

        // 9. Command and Control (Order: 9)
        new(
            new Regex(@"\b(?:https?://|downloadstring|downloadfile|webclient|curl|wget)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "HTTP/HTTPS 표준 웹 프로토콜을 통하여 외부 C2 서버와 통신하거나 2차 악성 페이로드를 다운로드하는 기법", 9)
        ),
        new(
            new Regex(@"\b(?:beacon|meterpreter|reverse_tcp|c2\s+download|c2\s+beacon|\bc2\b)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1095", "Non-Application Layer / Specialized C2 Protocol", "Command and Control", "전용 C2 프레임워크(Cobalt Strike, Metasploit)의 양방향 원격 제어 비콘을 유지하는 기법", 9)
        ),

        // 10. Impact (Order: 10)
        new(
            new Regex(@"\b(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|bcdedit(?:\.exe)?.*?recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+catalog)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1490", "Inhibit System Recovery", "Impact", "랜섬웨어 감염 후 복구를 방해하기 위해 볼륨 섀도 복사본을 영구 삭제하거나 부팅 복구 설정을 파괴하는 기법", 10)
        ),
        new(
            new Regex(@"\b(?:ransomware|encrypt.*files|\.locked|\.crypted|\.lockbit)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout),
            new MitreTechnique("T1486", "Data Encrypted for Impact", "Impact", "피해 시스템의 중요 문서를 비대칭/대칭 키로 암호화하여 금전을 요구하는 랜섬웨어 파괴 기법", 10)
        )
    };

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        string? behavior = null;
        var caseInsensitive = new Dictionary<string, object>(parameters, StringComparer.OrdinalIgnoreCase);
        foreach (var key in new[] { "observedBehavior", "observed_behavior", "behavior", "command", "log" })
        {
            if (caseInsensitive.TryGetValue(key, out var rawB) && rawB != null)
            {
                string? s = rawB switch
                {
                    string str => str,
                    System.Text.Json.JsonElement je when je.ValueKind == System.Text.Json.JsonValueKind.String => je.GetString(),
                    _ => rawB.ToString()
                };

                if (!string.IsNullOrWhiteSpace(s))
                {
                    behavior = s;
                    break;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(behavior))
        {
            return Task.FromResult(new ToolResult(false, "매개변수 'observedBehavior'가 제공되지 않았습니다."));
        }

        var matched = new List<MitreTechnique>();

        foreach (var rule in Rules)
        {
            try
            {
                if (rule.Pattern.IsMatch(behavior) && !matched.Any(t => t.Id == rule.Technique.Id))
                {
                    matched.Add(rule.Technique);
                }
            }
            catch (RegexMatchTimeoutException) { }
        }

        // 킬체인 순서(Initial Access -> Execution -> ... -> Impact)로 엄격 정렬
        matched.Sort((a, b) => a.KillChainOrder.CompareTo(b.KillChainOrder));

        if (matched.Count == 0)
        {
            if (Regex.IsMatch(behavior, @"\b(?:cmd|powershell|bash|sh|cscript|wscript)\b", RegexOptions.IgnoreCase, RegexTimeout))
            {
                matched.Add(new MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution", "범용 명령줄 또는 스크립트 실행", 2));
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine($"[MitreClassifierTool 매핑 완료 - 총 {matched.Count}개 기법 식별 (킬체인 정렬)]");
        foreach (var t in matched)
        {
            sb.AppendLine($"• [{t.Id}] {t.Name} (전술: {t.Tactic})");
            sb.AppendLine($"  ↳ {t.Description}");
        }

        if (matched.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("📋 [공격 킬체인 종합 서사 (Kill Chain Narrative)]");
            var distinctTactics = matched.Select(m => m.Tactic).Distinct().ToList();
            sb.AppendLine($"  {string.Join(" ➔ ", distinctTactics)}");
        }

        var data = new Dictionary<string, object>
        {
            ["Techniques"] = matched,
            ["TacticIds"] = matched.Select(m => m.Id).ToList(),
            ["PrimaryTactic"] = matched.Count > 0 ? matched[0].Tactic : "None"
        };

        return Task.FromResult(new ToolResult(true, sb.ToString(), data));
    }
}
