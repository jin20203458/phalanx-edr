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

    private static readonly List<SafetySetting> DefaultSafetySettings =
    [
        new("HARM_CATEGORY_HARASSMENT", BlockThreshold.BLOCK_NONE),
        new("HARM_CATEGORY_HATE_SPEECH", BlockThreshold.BLOCK_NONE),
        new("HARM_CATEGORY_SEXUALLY_EXPLICIT", BlockThreshold.BLOCK_NONE),
        new("HARM_CATEGORY_DANGEROUS_CONTENT", BlockThreshold.BLOCK_NONE)
    ];

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
    /// 런타임 설정 파일의 단일 고정 경로 (실행 폴더의 AppSettings.json).
    /// 유료 API 오남용 방지를 위해 다른 위치는 탐색하지 않습니다.
    /// </summary>
    public static string SettingsFilePath => Phalanx.Cockpit.Config.PhalanxConfigurationManager.DefaultConfigPath;

    /// <summary>
    /// 실행 폴더의 AppSettings.json에 명시된 값만으로 Gemini 클라이언트를 생성합니다.
    /// 환경 변수나 기본 위치의 인증 파일을 자동 탐색하지 않으며, 설정 파일이 없거나 값이 유효하지 않으면 null을 반환합니다.
    /// </summary>
    public static GeminiRestClient? TryCreateFromSettings(
        HttpClient? httpClient,
        out string? error,
        string? settingsPath = null)
    {
        string path = settingsPath ?? SettingsFilePath;
        if (!File.Exists(path))
        {
            error = $"설정 파일 없음: {path}";
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            var gemini = root.TryGetProperty("Gemini", out var gSec) ? gSec : root;

            bool useVertexAi = ReadBool(gemini, "UseVertexAI") ?? ReadBool(root, "UseVertexAI") ?? true;
            string? modelName = ReadString(gemini, "ModelName");

            if (!useVertexAi)
            {
                string? apiKey = ReadString(gemini, "ApiKey") ?? ReadString(root, "ApiKey");
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    error = "API Key 모드이지만 설정 파일에 ApiKey가 없습니다.";
                    return null;
                }
                error = null;
                return new GeminiRestClient(httpClient ?? new HttpClient(), apiKey, modelName ?? "gemini-3.7-flash");
            }

            string? credentialsPath = ReadString(gemini, "CredentialsPath");
            if (string.IsNullOrWhiteSpace(credentialsPath))
            {
                error = "Vertex AI 모드이지만 설정 파일에 CredentialsPath가 없습니다.";
                return null;
            }

            return TryCreateVertexClient(
                httpClient,
                credentialsPath,
                ReadString(gemini, "ProjectId") ?? ReadString(root, "ProjectId"),
                ReadString(gemini, "Location") ?? ReadString(root, "Location"),
                modelName,
                out error);
        }
        catch (Exception ex)
        {
            error = $"설정 파일 파싱 실패: {ex.Message}";
            return null;
        }
    }

    /// <summary>
    /// 명시적으로 지정된 서비스 계정 키 파일 하나로만 Vertex AI 클라이언트를 생성합니다.
    /// 상대 경로는 실행 폴더 기준으로 해석하며, 파일이 없으면 다른 위치로 대체하지 않고 null을 반환합니다.
    /// </summary>
    public static GeminiRestClient? TryCreateVertexClient(
        HttpClient? httpClient,
        string credentialsPath,
        string? projectId,
        string? location,
        string? modelName,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(credentialsPath))
        {
            error = "인증 파일 경로가 비어 있습니다.";
            return null;
        }

        string resolvedPath = Path.IsPathRooted(credentialsPath)
            ? credentialsPath
            : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, credentialsPath));

        if (!File.Exists(resolvedPath))
        {
            error = $"인증 파일 없음: {resolvedPath}";
            return null;
        }

        try
        {
            string credJson = File.ReadAllText(resolvedPath);
            string effectiveProjectId = !string.IsNullOrWhiteSpace(projectId) ? projectId : "grc0-494913";
            using (var credDoc = JsonDocument.Parse(credJson))
            {
                if (credDoc.RootElement.TryGetProperty("project_id", out var pidElem) && !string.IsNullOrWhiteSpace(pidElem.GetString()))
                {
                    effectiveProjectId = pidElem.GetString()!;
                }
            }

            var specCred = CredentialFactory.FromJson<ServiceAccountCredential>(credJson);
            var googleCred = specCred.ToGoogleCredential().CreateScoped("https://www.googleapis.com/auth/cloud-platform");

            error = null;
            return new GeminiRestClient(
                httpClient: httpClient ?? new HttpClient(),
                tokenProvider: async (ct) => await ((ITokenAccess)googleCred).GetAccessTokenForRequestAsync(null, ct),
                projectId: effectiveProjectId,
                location: string.IsNullOrWhiteSpace(location) ? "global" : location.ToLowerInvariant(),
                modelName: string.IsNullOrWhiteSpace(modelName) ? "gemini-3.7-flash" : modelName
            );
        }
        catch (Exception ex)
        {
            error = $"인증 파일 로드 실패 ({resolvedPath}): {ex.Message}";
            Trace.WriteLine($"[GeminiRestClient] {error}");
            return null;
        }
    }

    private static string? ReadString(JsonElement section, string name)
    {
        return section.ValueKind == JsonValueKind.Object
            && section.TryGetProperty(name, out var v)
            && v.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(v.GetString())
            ? v.GetString()
            : null;
    }

    private static bool? ReadBool(JsonElement section, string name)
    {
        if (section.ValueKind == JsonValueKind.Object && section.TryGetProperty(name, out var v))
        {
            if (v.ValueKind == JsonValueKind.True) return true;
            if (v.ValueKind == JsonValueKind.False) return false;
        }
        return null;
    }

    /// <summary>
    /// Gemini REST API에 임의의 GeminiRequest를 전송하고 원본 응답 및 GeminiResponse 객체를 반환합니다.
    /// 실전 클라우드 네트워크 왕복 및 토큰 교환을 고려하여 기본 타임아웃 링크가 적용됩니다.
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
                    throw new HttpRequestException($"LLM API HTTP {(int)response.StatusCode} 에러: {responseJson}");
                }

                var geminiResponse = JsonSerializer.Deserialize<GeminiResponse>(responseJson, JsonOptions);
                if (geminiResponse == null)
                {
                    throw new InvalidOperationException($"LLM API 응답 역직렬화 실패: {responseJson}");
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

        throw new HttpRequestException("LLM API 호출 최대 재시도 횟수 초과.");
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
                ? new Content("system", [new Part(systemInstruction)])
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
            throw new InvalidOperationException($"LLM API가 응답을 반환하지 않았습니다. (이유: {reason})");
        }

        var candidate = geminiResponse.Candidates[0];
        if (candidate.FinishReason == "SAFETY")
        {
            throw new InvalidOperationException("LLM API가 안전 필터(SAFETY)에 의해 응답 생성을 차단했습니다.");
        }

        if (candidate.Content?.Parts == null || candidate.Content.Parts.Count == 0)
        {
            throw new InvalidOperationException("LLM API 응답 내부에 유효한 Part가 없습니다.");
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
        List<Content> contents =
        [
            new Content("user", [new Part(userPrompt)])
        ];
        return GenerateContentAsync(contents, systemInstruction, cancellationToken, timeoutMs, thinkingLevel);
    }
}
