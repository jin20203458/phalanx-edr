using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Phalanx.Cockpit.Agent.Gemini;

/// <summary>
/// Google AI Studio의 Gemini 2.0 Flash REST API 엔드포인트와 통신하는 비동기 클라이언트
/// </summary>
public class GeminiRestClient
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;
    private readonly string _modelName;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public GeminiRestClient(HttpClient httpClient, string apiKey, string modelName = "gemini-2.0-flash")
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        _modelName = modelName;
    }

    /// <summary>
    /// Gemini 2.0 Flash 모델에 프롬프트를 전송하고 텍스트/JSON 응답을 수신합니다.
    /// EDR SLA(3초) 준수를 위해 기본 2.5초 내부 타임아웃 링크가 적용됩니다.
    /// </summary>
    public async Task<string> GenerateContentAsync(
        string userPrompt,
        string? systemInstruction = null,
        CancellationToken cancellationToken = default)
    {
        // 2.5초 SLA 타임아웃 CTS 및 외부 취소 토큰 결합 (Linked CancellationToken)
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(2500));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        string url = $"https://generativelanguage.googleapis.com/v1beta/models/{_modelName}:generateContent?key={_apiKey}";

        var requestBody = new GeminiRequest(
            Contents: new List<Content>
            {
                new Content("user", new List<Part> { new Part(userPrompt) })
            },
            SystemInstruction: !string.IsNullOrWhiteSpace(systemInstruction)
                ? new Content("system", new List<Part> { new Part(systemInstruction) })
                : null,
            GenerationConfig: new GenerationConfig(
                Temperature: 0.2f,
                MaxOutputTokens: 4096,
                ResponseMimeType: "application/json"
            )
        );

        string jsonPayload = JsonSerializer.Serialize(requestBody, JsonOptions);
        using var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.PostAsync(url, content, linkedCts.Token);
        response.EnsureSuccessStatusCode();

        string responseJson = await response.Content.ReadAsStringAsync(linkedCts.Token);
        var geminiResponse = JsonSerializer.Deserialize<GeminiResponse>(responseJson, JsonOptions);

        if (geminiResponse?.Candidates == null || geminiResponse.Candidates.Count == 0)
        {
            throw new InvalidOperationException("Gemini API가 빈 응답(Candidates 0건)을 반환했습니다.");
        }

        var candidate = geminiResponse.Candidates[0];
        if (candidate.Content?.Parts == null || candidate.Content.Parts.Count == 0)
        {
            throw new InvalidOperationException("Gemini API 응답 내부에 유효한 Part가 없습니다.");
        }

        // Part 중 텍스트 추출 (Thought 토큰 필터링)
        var textParts = candidate.Content.Parts
            .Where(p => p.Thought != true && !string.IsNullOrWhiteSpace(p.Text))
            .Select(p => p.Text);

        string fullText = string.Join("\n", textParts);
        return fullText;
    }
}
