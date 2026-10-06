namespace Phalanx.Cockpit.Config;

/// <summary>
/// AppSettings.json의 스키마를 표현하는 순수 POCO 모델.
/// </summary>
public class PhalanxConfiguration
{
    public GeminiSettings Gemini { get; set; } = new();
    public SensorSettings Sensor { get; set; } = new();
    public StorageSettings Storage { get; set; } = new();
    public string Theme { get; set; } = "System";
}

public class GeminiSettings
{
    public string ProjectId { get; set; } = "";
    public string Location { get; set; } = "global";
    public string ModelName { get; set; } = "gemini-3.7-flash";
    public string ApiKey { get; set; } = "";
    public bool UseVertexAI { get; set; } = true;
    public string CredentialsPath { get; set; } = "";
    public int MaxSteps { get; set; } = 5;
    public int WatchdogTimeoutSec { get; set; } = 10;
    public int CtsTimeoutSec { get; set; } = 50;
    public bool OfflineFallback { get; set; } = true;
    public bool FailSecure { get; set; } = true;
}

public class SensorSettings
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 50051;
}

public class StorageSettings
{
    public string DatabasePath { get; set; } = "phalanx_forensics.db";
    public string ReportExportPath { get; set; } = "IncidentReports";
}
