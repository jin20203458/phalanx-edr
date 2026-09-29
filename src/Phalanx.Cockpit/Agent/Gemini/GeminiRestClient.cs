using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Google.Apis.Auth.OAuth2;

namespace Phalanx.Cockpit.Agent.Gemini;

/// <summary>
/// Google AI Studio(API Key) 및 Google Cloud Vertex AI(Service Account OAuth2)와 통신하는 비동기 Gemini REST 클라이언트
/// </summary>
public class GeminiRestClient
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;
    private readonly string? _projectId;
    private readonly string _location;
    private readonly string _modelName;
    private readonly Func<CancellationToken, Task<string>>? _tokenProvider;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Google AI Studio API Key 기반 생성자
    /// </summary>
    public GeminiRestClient(HttpClient httpClient, string apiKey, string modelName = "gemini-2.0-flash")
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        _modelName = modelName;
        _location = "global";
    }

    /// <summary>
    /// Google Cloud Vertex AI Bearer Token 기반 생성자
    /// </summary>
    public GeminiRestClient(
        HttpClient httpClient,
        Func<CancellationToken, Task<string>> tokenProvider,
        string projectId,
        string location = "global",
        string modelName = "gemini-2.5-flash")
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        _projectId = projectId ?? throw new ArgumentNullException(nameof(projectId));
        _location = string.IsNullOrWhiteSpace(location) ? "global" : location;
        _modelName = modelName;
    }

    /// <summary>
    /// MundusVivens의 AppSettings.json 및 Config/google-credentials.json을 자동 탐색하여 Vertex AI 클라이언트 생성
    /// </summary>
    public static async Task<GeminiRestClient?> TryCreateFromMundusVivensConfigAsync(
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            string mvBasePath = @"C:\Users\user\Documents\GitHub\MundusVivens\MundusVivens.Prototype";
            string appSettingsPath = Path.Combine(mvBasePath, "AppSettings.json");
            string credentialsPath = Path.Combine(mvBasePath, "Config", "google-credentials.json");

            if (!File.Exists(credentialsPath))
            {
                return null;
            }

            string projectId = "grc0-494913";
            string location = "global";
            string model = "gemini-2.5-flash";

            if (File.Exists(appSettingsPath))
            {
                var json = await File.ReadAllTextAsync(appSettingsPath, cancellationToken);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("ProjectId", out var p) && !string.IsNullOrWhiteSpace(p.GetString()))
                {
                    projectId = p.GetString()!;
                }
                if (doc.RootElement.TryGetProperty("Location", out var loc) && !string.IsNullOrWhiteSpace(loc.GetString()))
                {
                    location = loc.GetString()!.ToLowerInvariant();
                }
            }

            string credJson = await File.ReadAllTextAsync(credentialsPath, cancellationToken);
            var specCred = CredentialFactory.FromJson<ServiceAccountCredential>(credJson);
            var googleCred = specCred.ToGoogleCredential().CreateScoped("https://www.googleapis.com/auth/cloud-platform");

            return new GeminiRestClient(
                httpClient: httpClient ?? new HttpClient(),
                tokenProvider: async (ct) => await ((ITokenAccess)googleCred).GetAccessTokenForRequestAsync(null, ct),
                projectId: projectId,
                location: location,
                modelName: model
            );
        }
        catch (Exception ex)
        {
            Trace.WriteLine($"[GeminiRestClient] MV Config 로드 실패: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gemini 모델에 프롬프트를 전송하고 텍스트/JSON 응답을 수신합니다.
    /// 실전 클라우드 네트워크 왕복 및 토큰 교환을 고려하여 기본 10초 타임아웃 링크가 적용됩니다.
    /// </summary>
    /// <summary>
    /// Gemini REST API에 임의의 GeminiRequest를 전송하고 원본 응답 및 GeminiResponse 객체를 반환합니다.
    /// </summary>
    public async Task<(GeminiResponse Response, string RawJson)> SendRequestRawAsync(
        GeminiRequest requestBody,
        CancellationToken cancellationToken = default,
        int timeoutMs = 15000)
    {
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeoutMs));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        string url;
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, "");

        if (_tokenProvider != null && !string.IsNullOrWhiteSpace(_projectId))
        {
            // Vertex AI 엔드포인트
            string hostName = (_location == "global" || string.IsNullOrWhiteSpace(_location))
                ? "aiplatform.googleapis.com"
                : $"{_location}-aiplatform.googleapis.com";
            string loc = string.IsNullOrWhiteSpace(_location) ? "global" : _location;
            url = $"https://{hostName}/v1beta1/projects/{_projectId}/locations/{loc}/publishers/google/models/{_modelName}:generateContent";

            string token = await _tokenProvider(linkedCts.Token);
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        else
        {
            // Google AI Studio 엔드포인트
            url = $"https://generativelanguage.googleapis.com/v1beta/models/{_modelName}:generateContent?key={_apiKey}";
        }

        string jsonPayload = JsonSerializer.Serialize(requestBody, JsonOptions);
        httpRequest.RequestUri = new Uri(url);
        httpRequest.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(httpRequest, linkedCts.Token);
        string responseJson = await response.Content.ReadAsStringAsync(linkedCts.Token);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Gemini API HTTP {(int)response.StatusCode} 에러: {responseJson}");
        }

        var geminiResponse = JsonSerializer.Deserialize<GeminiResponse>(responseJson, JsonOptions);
        if (geminiResponse == null)
        {
            throw new InvalidOperationException($"Gemini API 응답 역직렬화 실패: {responseJson}");
        }

        return (geminiResponse, responseJson);
    }

    /// <summary>
    /// Gemini 모델에 프롬프트를 전송하고 텍스트/JSON 응답을 수신합니다.
    /// </summary>
    public async Task<string> GenerateContentAsync(
        string userPrompt,
        string? systemInstruction = null,
        CancellationToken cancellationToken = default,
        int timeoutMs = 10000)
    {
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

        var (geminiResponse, _) = await SendRequestRawAsync(requestBody, cancellationToken, timeoutMs);

        if (geminiResponse.Candidates == null || geminiResponse.Candidates.Count == 0)
        {
            throw new InvalidOperationException("Gemini API가 빈 응답(Candidates 0건)을 반환했습니다.");
        }

        var candidate = geminiResponse.Candidates[0];
        if (candidate.Content?.Parts == null || candidate.Content.Parts.Count == 0)
        {
            throw new InvalidOperationException("Gemini API 응답 내부에 유효한 Part가 없습니다.");
        }

        var textParts = candidate.Content.Parts
            .Where(p => p.Thought != true && !string.IsNullOrWhiteSpace(p.Text))
            .Select(p => p.Text);

        string fullText = string.Join("\n", textParts);
        return fullText;
    }
}
