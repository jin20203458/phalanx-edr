using System;
using System.IO;
using Phalanx.Cockpit.Config;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class PhalanxConfigurationTests : IDisposable
{
    private readonly string _tempConfigDir;
    private readonly string _tempConfigFile;

    public PhalanxConfigurationTests()
    {
        _tempConfigDir = Path.Combine(Path.GetTempPath(), "PhalanxCfgTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempConfigDir);
        _tempConfigFile = Path.Combine(_tempConfigDir, "AppSettings.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempConfigDir))
            {
                Directory.Delete(_tempConfigDir, true);
            }
        }
        catch { }
    }

    [Fact]
    public void Load_NonExistentFile_ReturnsDefaultValuesMatchingProductionSpec()
    {
        var nonExistentPath = Path.Combine(_tempConfigDir, "NonExistent.json");

        var config = PhalanxConfigurationManager.Load(nonExistentPath);

        Assert.NotNull(config);
        Assert.Equal("gemini-3.7-flash", config.Gemini.ModelName);
        Assert.Equal("global", config.Gemini.Location);
        Assert.True(config.Gemini.UseVertexAI);
        Assert.Equal(5, config.Gemini.MaxSteps);
        Assert.Equal(10, config.Gemini.WatchdogTimeoutSec);
        Assert.Equal(50, config.Gemini.CtsTimeoutSec);
        Assert.True(config.Gemini.OfflineFallback);
        Assert.True(config.Gemini.FailSecure);
        Assert.Equal("127.0.0.1", config.Sensor.Host);
        Assert.Equal(50051, config.Sensor.Port);
        Assert.Equal("phalanx_forensics.db", config.Storage.DatabasePath);
        Assert.Equal("IncidentReports", config.Storage.ReportExportPath);
        Assert.Equal("System", config.Theme);
    }

    [Fact]
    public void Load_ProductionSchemaWithThemeString_ParsesSuccessfullyWithoutException()
    {
        var rawJson = """
        {
          "Gemini": {
            "ProjectId": "my-vertex-proj",
            "Location": "asia-northeast3",
            "ModelName": "gemini-3.7-flash",
            "CredentialsPath": "config/service-account.json",
            "ApiKey": "test-key-1234",
            "UseVertexAI": true,
            "MaxSteps": 7,
            "WatchdogTimeoutSec": 15,
            "CtsTimeoutSec": 60,
            "OfflineFallback": false,
            "FailSecure": true
          },
          "Sensor": {
            "Host": "192.168.1.100",
            "Port": 50052
          },
          "Storage": {
            "DatabasePath": "custom_forensics.db",
            "ReportExportPath": "MyReports"
          },
          "Theme": "Dark"
        }
        """;

        File.WriteAllText(_tempConfigFile, rawJson);

        var config = PhalanxConfigurationManager.Load(_tempConfigFile);

        Assert.NotNull(config);
        Assert.Equal("my-vertex-proj", config.Gemini.ProjectId);
        Assert.Equal("asia-northeast3", config.Gemini.Location);
        Assert.Equal("test-key-1234", config.Gemini.ApiKey);
        Assert.Equal(7, config.Gemini.MaxSteps);
        Assert.False(config.Gemini.OfflineFallback);
        Assert.Equal("192.168.1.100", config.Sensor.Host);
        Assert.Equal(50052, config.Sensor.Port);
        Assert.Equal("custom_forensics.db", config.Storage.DatabasePath);
        Assert.Equal("Dark", config.Theme);
    }

    [Fact]
    public void SaveAndLoad_RoundTrip_PreservesAllSettingsAccurately()
    {
        var original = new PhalanxConfiguration
        {
            Gemini = new GeminiSettings
            {
                ProjectId = "round-trip-proj",
                Location = "us-west1",
                ModelName = "gemini-3.7-pro",
                ApiKey = "sec-key-5678",
                UseVertexAI = false,
                CredentialsPath = "auth.json",
                MaxSteps = 9,
                WatchdogTimeoutSec = 20,
                CtsTimeoutSec = 80,
                OfflineFallback = true,
                FailSecure = false
            },
            Sensor = new SensorSettings
            {
                Host = "10.0.0.5",
                Port = 55555
            },
            Storage = new StorageSettings
            {
                DatabasePath = "rt_db.db",
                ReportExportPath = "RTReports"
            },
            Theme = "Light"
        };

        PhalanxConfigurationManager.Save(original, _tempConfigFile);

        var loaded = PhalanxConfigurationManager.Load(_tempConfigFile);

        Assert.NotNull(loaded);
        Assert.Equal("round-trip-proj", loaded.Gemini.ProjectId);
        Assert.Equal("us-west1", loaded.Gemini.Location);
        Assert.Equal("gemini-3.7-pro", loaded.Gemini.ModelName);
        Assert.Equal("sec-key-5678", loaded.Gemini.ApiKey);
        Assert.False(loaded.Gemini.UseVertexAI);
        Assert.Equal("auth.json", loaded.Gemini.CredentialsPath);
        Assert.Equal(9, loaded.Gemini.MaxSteps);
        Assert.Equal(20, loaded.Gemini.WatchdogTimeoutSec);
        Assert.Equal(80, loaded.Gemini.CtsTimeoutSec);
        Assert.True(loaded.Gemini.OfflineFallback);
        Assert.False(loaded.Gemini.FailSecure);
        Assert.Equal("10.0.0.5", loaded.Sensor.Host);
        Assert.Equal(55555, loaded.Sensor.Port);
        Assert.Equal("rt_db.db", loaded.Storage.DatabasePath);
        Assert.Equal("RTReports", loaded.Storage.ReportExportPath);
        Assert.Equal("Light", loaded.Theme);
    }

    [Fact]
    public void TryLoad_ExistingAndMissing_ReturnsExpectedBoolean()
    {
        File.WriteAllText(_tempConfigFile, "{\"Theme\": \"System\"}");

        bool success = PhalanxConfigurationManager.TryLoad(_tempConfigFile, out var loaded);
        bool fail = PhalanxConfigurationManager.TryLoad(Path.Combine(_tempConfigDir, "None.json"), out var missing);

        Assert.True(success);
        Assert.NotNull(loaded);
        Assert.False(fail);
        Assert.Null(missing);
    }
}
