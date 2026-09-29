using System.Text.Json.Serialization;

namespace Phalanx.Cockpit.Agent.Gemini;

#region Google Gemini REST API Request & Response DTOs
public record GeminiRequest(
    [property: JsonPropertyName("contents")] List<Content> Contents,
    [property: JsonPropertyName("systemInstruction")] Content? SystemInstruction = null,
    [property: JsonPropertyName("generationConfig")] GenerationConfig? GenerationConfig = null,
    [property: JsonPropertyName("tools")] List<object>? Tools = null
);

public record Content(
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("parts")] List<Part> Parts
);

public record Part(
    [property: JsonPropertyName("text")] string? Text = null,
    [property: JsonPropertyName("thought")] bool? Thought = null,
    [property: JsonPropertyName("functionCall")] FunctionCallDto? FunctionCall = null,
    [property: JsonPropertyName("functionResponse")] FunctionResponseDto? FunctionResponse = null
);

public record FunctionCallDto(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("args")] Dictionary<string, object>? Args
);

public record FunctionResponseDto(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("response")] Dictionary<string, object>? Response
);

public record GenerationConfig(
    [property: JsonPropertyName("temperature")] float? Temperature = 0.2f,
    [property: JsonPropertyName("maxOutputTokens")] int MaxOutputTokens = 4096,
    [property: JsonPropertyName("responseMimeType")] string? ResponseMimeType = "application/json",
    [property: JsonPropertyName("responseSchema")] object? ResponseSchema = null
);

public record GeminiResponse(
    [property: JsonPropertyName("candidates")] List<Candidate>? Candidates,
    [property: JsonPropertyName("usageMetadata")] UsageMetadata? UsageMetadata
);

public record Candidate(
    [property: JsonPropertyName("content")] Content? Content,
    [property: JsonPropertyName("finishReason")] string? FinishReason
);

public record UsageMetadata(
    [property: JsonPropertyName("promptTokenCount")] int PromptTokenCount,
    [property: JsonPropertyName("candidatesTokenCount")] int CandidatesTokenCount,
    [property: JsonPropertyName("totalTokenCount")] int TotalTokenCount
);
#endregion

#region Structured AI Investigation Models (ReAct Response)
/// <summary>
/// Gemini 2.0 Flash가 반환하는 구조화된 수사 판단 및 액션 DTO
/// </summary>
public record AiInvestigationDecision(
    [property: JsonPropertyName("thought")] string Thought,
    [property: JsonPropertyName("action_tool")] string ActionTool,
    [property: JsonPropertyName("action_args")] Dictionary<string, object>? ActionArgs,
    [property: JsonPropertyName("is_final_verdict")] bool IsFinalVerdict,
    [property: JsonPropertyName("verdict_action")] string? VerdictAction, // ACTION_KILL or ACTION_RESUME
    [property: JsonPropertyName("confidence_score")] double ConfidenceScore,
    [property: JsonPropertyName("summary_title")] string? SummaryTitle,
    [property: JsonPropertyName("narrative")] string? Narrative,
    [property: JsonPropertyName("mitre_tactics")] List<string>? MitreTactics
);
#endregion
