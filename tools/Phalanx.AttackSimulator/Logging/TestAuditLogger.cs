using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Phalanx.AttackSimulator.Logging;

public sealed class InjectedProcessInfo
{
    [JsonPropertyName("pid")]
    public uint Pid { get; set; }

    [JsonPropertyName("ppid")]
    public uint Ppid { get; set; }

    [JsonPropertyName("image_name")]
    public string ImageName { get; set; } = string.Empty;

    [JsonPropertyName("command_line")]
    public string CommandLine { get; set; } = string.Empty;

    [JsonPropertyName("is_suspended")]
    public bool IsSuspended { get; set; }
}

public sealed class CockpitVerdictInfo
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;

    [JsonPropertyName("target_pid")]
    public uint TargetPid { get; set; }

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;

    [JsonPropertyName("latency_ms")]
    public double LatencyMs { get; set; }
}

public sealed class TestRunRecord
{
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = DateTimeOffset.Now.ToString("o");

    [JsonPropertyName("scenario_id")]
    public int ScenarioId { get; set; }

    [JsonPropertyName("scenario_name")]
    public string ScenarioName { get; set; } = string.Empty;

    [JsonPropertyName("execution_mode")]
    public string ExecutionMode { get; set; } = "grpc";

    [JsonPropertyName("target_cockpit")]
    public string TargetCockpit { get; set; } = string.Empty;

    [JsonPropertyName("injected_process")]
    public InjectedProcessInfo? InjectedProcess { get; set; }

    [JsonPropertyName("cockpit_verdict")]
    public CockpitVerdictInfo? CockpitVerdict { get; set; }

    [JsonPropertyName("expected_action")]
    public string ExpectedAction { get; set; } = string.Empty;

    [JsonPropertyName("test_result")]
    public string TestResult { get; set; } = "UNKNOWN";
}

public static class TestAuditLogger
{
    private static readonly object FileLock = new();
    private static readonly string LogDirectory;
    private static readonly string LatestRunJsonPath;
    private static readonly string HistoryLogPath;

    static TestAuditLogger()
    {
        string baseDir = AppContext.BaseDirectory;
        string? repoRoot = FindRepositoryRoot(baseDir);
        LogDirectory = repoRoot != null
            ? Path.Combine(repoRoot, "logs", "simulator")
            : Path.Combine(baseDir, "logs", "simulator");

        Directory.CreateDirectory(LogDirectory);
        LatestRunJsonPath = Path.Combine(LogDirectory, "latest_run.json");
        HistoryLogPath = Path.Combine(LogDirectory, "test_history.log");
    }

    public static string LogDirPath => LogDirectory;
    public static string LatestJsonFilePath => LatestRunJsonPath;
    public static string HistoryLogFilePath => HistoryLogPath;

    public static void RecordTestRun(TestRunRecord record)
    {
        lock (FileLock)
        {
            try
            {
                // 1. JSON 직렬화 및 latest_run.json 원자적 쓰기
                var jsonOptions = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                };
                string jsonString = JsonSerializer.Serialize(record, jsonOptions);
                File.WriteAllText(LatestRunJsonPath, jsonString);

                // 2. test_history.log 한 줄 어펜드
                string logLine = $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [{record.TestResult}] " +
                                 $"Scenario #{record.ScenarioId} ({record.ScenarioName}) | " +
                                 $"Mode: {record.ExecutionMode.ToUpperInvariant()} | " +
                                 $"PID: {record.InjectedProcess?.Pid} | " +
                                 $"Expected: {record.ExpectedAction} | " +
                                 $"Verdict: {record.CockpitVerdict?.Action ?? "NO_RESPONSE"} ({record.CockpitVerdict?.LatencyMs:F1}ms) | " +
                                 $"Reason: {record.CockpitVerdict?.Reason ?? "N/A"}{Environment.NewLine}";

                File.AppendAllText(HistoryLogPath, logLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AUDIT LOGGER WARNING] 로그 기록 실패: {ex.Message}");
            }
        }
    }

    private static string? FindRepositoryRoot(string startDir)
    {
        var dir = new DirectoryInfo(startDir);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Phalanx.sln")) ||
                Directory.Exists(Path.Combine(dir.FullName, ".git")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        return null;
    }
}
