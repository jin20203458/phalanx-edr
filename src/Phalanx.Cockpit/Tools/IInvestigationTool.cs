namespace Phalanx.Cockpit.Tools;

public record ToolResult(bool Success, string Output, Dictionary<string, object>? Data = null);

/// <summary>
/// AI 위협 헌터 에이전트가 자율 호출하는 OS 조사 도구 공통 인터페이스
/// </summary>
public interface IInvestigationTool
{
    string Name { get; }
    string Description { get; }
    Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters);
}
