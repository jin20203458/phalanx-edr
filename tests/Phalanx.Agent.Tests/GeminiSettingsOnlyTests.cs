using System.IO;
using System.Net.Http;
using Phalanx.Cockpit.Agent;
using Phalanx.Cockpit.Agent.Gemini;
using Phalanx.Cockpit.CQRS;
using Phalanx.Cockpit.Storage;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

/// <summary>
/// 유료 Gemini API 보호 회귀 테스트: 설정 파일(AppSettings.json)에 명시된 인증 정보만 사용하고,
/// 환경 변수나 기본 위치의 인증 파일을 자동 탐색하여 대체하지 않는지 검증합니다.
/// 실행 폴더의 공유 AppSettings.json을 건드리지 않도록 모든 케이스는 임시 파일 경로를 명시합니다.
/// </summary>
[Trait("Category", "Unit")]
public class GeminiSettingsOnlyTests : IDisposable
{
    private readonly string _tempDir;
    private static readonly string BundledCredentials = Path.Combine(AppContext.BaseDirectory, "Config", "google-credentials.json");

    public GeminiSettingsOnlyTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "phalanx-settings-only-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private string WriteSettings(string geminiSectionJson)
    {
        string path = Path.Combine(_tempDir, "AppSettings.json");
        File.WriteAllText(path, $"{{ \"Gemini\": {geminiSectionJson} }}");
        return path;
    }

    private static AutonomousHunterAgent CreateOfflineAgent()
    {
        return new AutonomousHunterAgent(
            new ProcessTreeProjectionManager(),
            ForensicArchiveManager.CreateInMemory(),
            Array.Empty<IInvestigationTool>(),
            geminiApiKey: string.Empty);
    }

    [Fact]
    public void TryCreateFromSettings_MissingSettingsFile_ReturnsNull()
    {
        var client = GeminiRestClient.TryCreateFromSettings(new HttpClient(), out var error, Path.Combine(_tempDir, "absent.json"));

        Assert.Null(client);
        Assert.Contains("설정 파일 없음", error);
    }

    [Fact]
    public void TryCreateFromSettings_WrongCredentialsPath_DoesNotFallBackToBundledOrEnvCredentials()
    {
        string? originalEnv = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");
        try
        {
            // 유효한 인증 파일이 환경 변수와 기본 위치(Config/)에 모두 존재하더라도 대체 사용하면 안 됨
            if (File.Exists(BundledCredentials))
            {
                Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", BundledCredentials);
            }

            string settings = WriteSettings("""{ "UseVertexAI": true, "CredentialsPath": "Config/does-not-exist.json" }""");
            var client = GeminiRestClient.TryCreateFromSettings(new HttpClient(), out var error, settings);

            Assert.Null(client);
            Assert.Contains("인증 파일 없음", error);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", originalEnv);
        }
    }

    [Fact]
    public void TryCreateFromSettings_VertexWithoutCredentialsPath_ReturnsNull()
    {
        string settings = WriteSettings("""{ "UseVertexAI": true }""");

        var client = GeminiRestClient.TryCreateFromSettings(new HttpClient(), out var error, settings);

        Assert.Null(client);
        Assert.Contains("CredentialsPath", error);
    }

    [Fact]
    public void TryCreateFromSettings_ApiKeyModeWithoutKey_IgnoresEnvironmentKey()
    {
        string? originalEnv = Environment.GetEnvironmentVariable("GEMINI_API_KEY");
        try
        {
            Environment.SetEnvironmentVariable("GEMINI_API_KEY", "env-key-must-not-be-used");
            string settings = WriteSettings("""{ "UseVertexAI": false, "ApiKey": "" }""");

            var client = GeminiRestClient.TryCreateFromSettings(new HttpClient(), out var error, settings);

            Assert.Null(client);
            Assert.Contains("ApiKey", error);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GEMINI_API_KEY", originalEnv);
        }
    }

    [Fact]
    public void TryCreateFromSettings_ExplicitValidCredentials_CreatesClientWithConfiguredModel()
    {
        if (!File.Exists(BundledCredentials)) return; // 인증 파일이 없는 환경에서는 생성 경로를 검증할 수 없음

        string escaped = BundledCredentials.Replace("\\", "\\\\");
        string settings = WriteSettings($$"""{ "UseVertexAI": true, "CredentialsPath": "{{escaped}}", "Location": "global", "ModelName": "gemini-3.7-flash" }""");

        var client = GeminiRestClient.TryCreateFromSettings(new HttpClient(), out var error, settings);

        Assert.NotNull(client);
        Assert.Null(error);
        Assert.Equal("gemini-3.7-flash", client!.ModelName);
    }

    [Fact]
    public void ReloadConfiguration_WrongCredentialsPath_StaysOffline()
    {
        string? originalEnv = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");
        try
        {
            if (File.Exists(BundledCredentials))
            {
                Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", BundledCredentials);
            }

            var agent = CreateOfflineAgent();
            bool online = agent.ReloadConfiguration(useVertexAi: true, credentialsPath: @"Z:\nowhere\bogus.json");

            Assert.False(online);
            Assert.False(agent.IsOnlineGemini);
            Assert.Contains("인증 파일 없음", agent.LastClientError);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", originalEnv);
        }
    }

    [Fact]
    public void ReloadConfiguration_ApiKeyModeWithoutKey_IgnoresEnvironmentKey()
    {
        string? originalEnv = Environment.GetEnvironmentVariable("GEMINI_API_KEY");
        try
        {
            Environment.SetEnvironmentVariable("GEMINI_API_KEY", "env-key-must-not-be-used");

            var agent = CreateOfflineAgent();
            bool online = agent.ReloadConfiguration(geminiApiKey: null, useVertexAi: false);

            Assert.False(online);
            Assert.False(agent.IsOnlineGemini);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GEMINI_API_KEY", originalEnv);
        }
    }
}

/// <summary>
/// Live 테스트 전용: 자동 탐색 없이 테스트 출력 폴더의 인증 파일을 명시적으로 지정하여 Vertex AI 클라이언트를 생성합니다.
/// </summary>
internal static class LiveGeminiTestConfig
{
    public const string CredentialsPath = "Config/google-credentials.json";

    public static GeminiRestClient? CreateClient()
    {
        return GeminiRestClient.TryCreateVertexClient(
            new HttpClient(), CredentialsPath, projectId: null, location: "global", modelName: "gemini-3.7-flash", out _);
    }
}
