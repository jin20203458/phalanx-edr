using System.Text;

namespace Phalanx.Cockpit.Tools;

public record MitreTechnique(string Id, string Name, string Tactic, string Description);

/// <summary>
/// 관찰된 공격 행위 및 족보 패턴을 기반으로 MITRE ATT&CK Matrix TTP 기법을 자동 분류하는 도구
/// </summary>
public class MitreClassifierTool : IInvestigationTool
{
    public string Name => "MitreClassifierTool";

    public string Description => "관찰된 프로세스 족보, 커맨드라인, 네트워크 행위를 분석하여 MITRE ATT&CK Matrix TTP 기법으로 자동 매핑합니다. 매개변수: 'observedBehavior' (string)";

    private static readonly List<(Func<string, bool> Matcher, MitreTechnique Technique)> Rules = new()
    {
        (
            s => (s.Contains("winword") || s.Contains("excel") || s.Contains("powerpnt") || s.Contains("outlook")) &&
                 (s.Contains("powershell") || s.Contains("cmd.exe") || s.Contains("mshta") || s.Contains("wscript")),
            new MitreTechnique("T1566.001", "Spearphishing Attachment (Office LOLBAS Spawn)", "Initial Access",
                "사용자 오피스 매크로 또는 첨부파일을 통해 자식 스크립트 실행기를 기동하여 초기 접근을 획득하는 기법")
        ),
        (
            s => s.Contains("powershell") || s.Contains("-enc") || s.Contains("-nop") || s.Contains("invoke-expression") || s.Contains("iex"),
            new MitreTechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
                "탐지 우회를 위해 인자를 난독화하거나 메모리 상에서 직접 파워셸 스크립트를 실행하는 기법")
        ),
        (
            s => s.Contains("http://") || s.Contains("https://") || s.Contains("downloadstring") || s.Contains("downloadfile") || s.Contains("c2"),
            new MitreTechnique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
                "HTTP/HTTPS 표준 웹 프로토콜을 통하여 외부 C2 서버와 통신하거나 2차 악성 페이로드를 다운로드하는 기법")
        ),
        (
            s => s.Contains("vssadmin") || s.Contains("delete shadows") || s.Contains("bcdedit") || s.Contains("wbadmin"),
            new MitreTechnique("T1490", "Inhibit System Recovery", "Impact",
                "랜섬웨어 감염 후 복구를 방해하기 위해 볼륨 섀도 복사본을 삭제하거나 부팅 설정을 조작하는 파괴적 기법")
        ),
        (
            s => s.Contains("readprocessmemory") || s.Contains("virtualalloc") || s.Contains("createremotethread") || s.Contains("hollowing"),
            new MitreTechnique("T1055", "Process Injection", "Defense Evasion, Privilege Escalation",
                "정상 프로세스의 메모리 공간에 악성 코드를 주입하여 은밀히 실행하는 기법")
        ),
        (
            s => s.Contains("certutil") || s.Contains("bitsadmin") || s.Contains("rundll32") || s.Contains("regsvr32"),
            new MitreTechnique("T1218", "System Binary Proxy Execution (LOLBAS)", "Defense Evasion",
                "신뢰할 수 있는 윈도우 기본 탑재 유틸리티를 악용하여 악성 페이로드를 우회 실행하는 기법")
        )
    };

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        if (!parameters.TryGetValue("observedBehavior", out var rawBehavior) || rawBehavior is not string behavior || string.IsNullOrWhiteSpace(behavior))
        {
            return Task.FromResult(new ToolResult(false, "매개변수 'observedBehavior'가 제공되지 않았습니다."));
        }

        string lower = behavior.ToLowerInvariant();
        var matched = new List<MitreTechnique>();

        foreach (var (matcher, tech) in Rules)
        {
            if (matcher(lower) && !matched.Any(t => t.Id == tech.Id))
            {
                matched.Add(tech);
            }
        }

        if (matched.Count == 0)
        {
            matched.Add(new MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution", "범용 명령줄 또는 스크립트 실행"));
        }

        var sb = new StringBuilder();
        sb.AppendLine($"[MitreClassifierTool 매핑 완료 - 총 {matched.Count}개 기법 식별]");
        foreach (var t in matched)
        {
            sb.AppendLine($"• [{t.Id}] {t.Name} (전술: {t.Tactic})");
            sb.AppendLine($"  ↳ {t.Description}");
        }

        var data = new Dictionary<string, object>
        {
            ["Techniques"] = matched,
            ["TacticIds"] = matched.Select(m => m.Id).ToList(),
            ["PrimaryTactic"] = matched[0].Tactic
        };

        return Task.FromResult(new ToolResult(true, sb.ToString(), data));
    }
}
