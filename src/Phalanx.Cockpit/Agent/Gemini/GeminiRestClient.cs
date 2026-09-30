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
    public string ModelName => _modelName;
    private readonly Func<CancellationToken, Task<string>>? _tokenProvider;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly List<SafetySetting> DefaultSafetySettings = new()
    {
        new("HARM_CATEGORY_HARASSMENT", BlockThreshold.BLOCK_NONE),
        new("HARM_CATEGORY_HATE_SPEECH", BlockThreshold.BLOCK_NONE),
        new("HARM_CATEGORY_SEXUALLY_EXPLICIT", BlockThreshold.BLOCK_NONE),
        new("HARM_CATEGORY_DANGEROUS_CONTENT", BlockThreshold.BLOCK_NONE)
    };

    /// <summary>
    /// Google AI Studio API Key 기반 생성자
    /// </summary>
    public GeminiRestClient(HttpClient httpClient, string apiKey, string modelName = "gemini-3.7-flash")
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
        string modelName = "gemini-3.7-flash")
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        _projectId = projectId ?? throw new ArgumentNullException(nameof(projectId));
        _location = string.IsNullOrWhiteSpace(location) ? "global" : location;
        _modelName = modelName;
    }

    /// <summary>
    /// <summary>
    /// Phalanx 자체 Config/google-credentials.json 및 AppSettings.json을 탐색하여 Vertex AI 클라이언트 생성
    /// </summary>
    public static GeminiRestClient? TryCreateFromLocalConfig(
        HttpClient? httpClient = null,
        string? modelName = null)
    {
        try
        {
            // 1. Google Cloud 표준 환경 변수 확인
            string? envCredPath = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");
            string? credentialsPath = null;

            if (!string.IsNullOrWhiteSpace(envCredPath) && File.Exists(envCredPath))
            {
                credentialsPath = envCredPath;
            }
            else
            {
                // 2. Phalanx 자체 로컬 Config 디렉터리 순회 탐색
                string[] candidates = new[]
                {
                    Path.Combine(AppContext.BaseDirectory, "Config", "google-credentials.json"),
                    Path.Combine(Directory.GetCurrentDirectory(), "Config", "google-credentials.json"),
                    Path.Combine(Directory.GetCurrentDirectory(), "src", "Phalanx.Cockpit", "Config", "google-credentials.json"),
                    Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\src\Phalanx.Cockpit\Config\google-credentials.json")),
                    Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\Config\google-credentials.json"))
                };

                foreach (var candidate in candidates)
                {
                    if (File.Exists(candidate))
                    {
                        credentialsPath = candidate;
                        break;
                    }
                }
            }

            if (credentialsPath == null || !File.Exists(credentialsPath))
            {
                return null;
            }

            string projectId = "grc0-494913";
            string location = "global";
            string model = modelName ?? "gemini-3.7-flash";

            // AppSettings.json 탐색
            string[] appSettingsCandidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "AppSettings.json"),
                Path.Combine(Directory.GetCurrentDirectory(), "AppSettings.json"),
                Path.Combine(Directory.GetCurrentDirectory(), "src", "Phalanx.Cockpit", "AppSettings.json"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\src\Phalanx.Cockpit\AppSettings.json")),
                Path.Combine(Path.GetDirectoryName(credentialsPath) ?? string.Empty, "..", "AppSettings.json")
            };

            foreach (var appSettingPath in appSettingsCandidates)
            {
                if (File.Exists(appSettingPath))
                {
                    try
                    {
                        var json = File.ReadAllText(appSettingPath);
                        using var doc = JsonDocument.Parse(json);
                        var root = doc.RootElement;
                        JsonElement geminiSection = root;
                        if (root.TryGetProperty("Gemini", out var gSec))
                        {
                            geminiSection = gSec;
                        }

                        if (geminiSection.TryGetProperty("ProjectId", out var p) && !string.IsNullOrWhiteSpace(p.GetString()))
                        {
                            projectId = p.GetString()!;
                        }
                        if (geminiSection.TryGetProperty("Location", out var loc) && !string.IsNullOrWhiteSpace(loc.GetString()))
                        {
                            location = loc.GetString()!.ToLowerInvariant();
                        }
                        if (geminiSection.TryGetProperty("ModelName", out var m) && !string.IsNullOrWhiteSpace(m.GetString()))
                        {
                            model = m.GetString()!;
                        }
                        break;
                    }
                    catch { }
                }
            }

            string credJson = File.ReadAllText(credentialsPath);
            using (var credDoc = JsonDocument.Parse(credJson))
            {
                if (credDoc.RootElement.TryGetProperty("project_id", out var pidElem) && !string.IsNullOrWhiteSpace(pidElem.GetString()))
                {
                    projectId = pidElem.GetString()!;
                }
            }

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
            Trace.WriteLine($"[GeminiRestClient] Phalanx 로컬 Config 로드 실패: {ex.Message}");
            return null;
        }
    }

    [Obsolete("Use TryCreateFromLocalConfig instead.")]
    public static GeminiRestClient? TryCreateFromMundusVivensConfig(
        HttpClient? httpClient = null,
        string? modelName = null) => TryCreateFromLocalConfig(httpClient, modelName);

    /// <summary>
    /// Phalanx 자체 AppSettings.json 및 Config/google-credentials.json을 자동 탐색하여 Vertex AI 클라이언트 비동기 생성
    /// </summary>
    public static Task<GeminiRestClient?> TryCreateFromLocalConfigAsync(
        HttpClient? httpClient = null,
        string? modelName = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(TryCreateFromLocalConfig(httpClient, modelName));
    }

    [Obsolete("Use TryCreateFromLocalConfigAsync instead.")]
    public static Task<GeminiRestClient?> TryCreateFromMundusVivensConfigAsync(
        HttpClient? httpClient = null,
        string? modelName = null,
        CancellationToken cancellationToken = default)
    {
        return TryCreateFromLocalConfigAsync(httpClient, modelName, cancellationToken);
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
        int timeoutMs = 25000)
    {
        string url;
        if (_tokenProvider != null && !string.IsNullOrWhiteSpace(_projectId))
        {
            // Vertex AI 엔드포인트
            string hostName = (_location == "global" || string.IsNullOrWhiteSpace(_location))
                ? "aiplatform.googleapis.com"
                : $"{_location}-aiplatform.googleapis.com";
            string loc = string.IsNullOrWhiteSpace(_location) ? "global" : _location;
            url = $"https://{hostName}/v1beta1/projects/{_projectId}/locations/{loc}/publishers/google/models/{_modelName}:generateContent";
        }
        else
        {
            // Google AI Studio 엔드포인트
            url = $"https://generativelanguage.googleapis.com/v1beta/models/{_modelName}:generateContent?key={_apiKey}";
        }

        string jsonPayload = JsonSerializer.Serialize(requestBody, JsonOptions);
        int maxRetries = 2;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            using var attemptTimeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(timeoutMs));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, attemptTimeoutCts.Token);

            try
            {
                using var httpRequest = new HttpRequestMessage(HttpMethod.Post, url);
                if (_tokenProvider != null && !string.IsNullOrWhiteSpace(_projectId))
                {
                    string token = await _tokenProvider(linkedCts.Token);
                    httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                }

                httpRequest.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                using var response = await _httpClient.SendAsync(httpRequest, linkedCts.Token);
                string responseJson = await response.Content.ReadAsStringAsync(linkedCts.Token);

                if ((int)response.StatusCode == 429 && attempt < maxRetries)
                {
                    // Quota cooldown 지수 백오프
                    await Task.Delay(2500 * (attempt + 1), cancellationToken);
                    continue;
                }

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
            catch (OperationCanceledException) when (attempt < maxRetries && !cancellationToken.IsCancellationRequested)
            {
                // 타임아웃 발생 시 1회 재시도
                await Task.Delay(1000, cancellationToken);
                continue;
            }
        }

        throw new HttpRequestException("Gemini API 호출 최대 재시도 횟수 초과.");
    }

    /// <summary>
    /// 멀티턴 대화 히스토리(List<Content>)를 전송하여 연속 추론을 수행합니다.
    /// </summary>
    public async Task<string> GenerateContentAsync(
        List<Content> contents,
        string? systemInstruction = null,
        CancellationToken cancellationToken = default,
        int timeoutMs = 25000,
        ThinkingLevel thinkingLevel = ThinkingLevel.low)
    {
        var requestBody = new GeminiRequest(
            Contents: contents,
            SystemInstruction: !string.IsNullOrWhiteSpace(systemInstruction)
                ? new Content("system", new List<Part> { new Part(systemInstruction) })
                : null,
            GenerationConfig: new GenerationConfig(
                Temperature: null,
                MaxOutputTokens: 4096,
                ResponseMimeType: "application/json",
                ThinkingConfig: new ThinkingConfig(thinkingLevel)
            ),
            SafetySettings: DefaultSafetySettings
        );

        var (geminiResponse, _) = await SendRequestRawAsync(requestBody, cancellationToken, timeoutMs);

        if (geminiResponse.Candidates == null || geminiResponse.Candidates.Count == 0)
        {
            string reason = geminiResponse.PromptFeedback?.BlockReason ?? "빈 응답(Candidates 0건)";
            throw new InvalidOperationException($"Gemini API가 응답을 반환하지 않았습니다. (이유: {reason})");
        }

        var candidate = geminiResponse.Candidates[0];
        if (candidate.FinishReason == "SAFETY")
        {
            throw new InvalidOperationException("Gemini API가 안전 필터(SAFETY)에 의해 응답 생성을 차단했습니다.");
        }

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

    /// <summary>
    /// 단일 프롬프트를 전송하고 텍스트/JSON 응답을 수신합니다.
    /// </summary>
    public Task<string> GenerateContentAsync(
        string userPrompt,
        string? systemInstruction = null,
        CancellationToken cancellationToken = default,
        int timeoutMs = 25000,
        ThinkingLevel thinkingLevel = ThinkingLevel.low)
    {
        var contents = new List<Content>
        {
            new Content("user", new List<Part> { new Part(userPrompt) })
        };
        return GenerateContentAsync(contents, systemInstruction, cancellationToken, timeoutMs, thinkingLevel);
    }
}
