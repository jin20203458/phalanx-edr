namespace Phalanx.Cockpit.Config;

using System;
using System.IO;
using System.Text.Encodings.Web;
using System.Text.Json;

/// <summary>
/// AppSettings.json의 단일 공급자(SSOT)이자 런타임 캐시 및 직렬화 관리자.
/// </summary>
public static class PhalanxConfigurationManager
{
    private static readonly object _lock = new();
    private static PhalanxConfiguration? _current;

    public static string DefaultConfigPath => Path.Combine(AppContext.BaseDirectory, "AppSettings.json");

    private static readonly JsonSerializerOptions JsonReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly JsonSerializerOptions JsonWriteOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static event Action<PhalanxConfiguration>? ConfigurationChanged;

    public static PhalanxConfiguration Current
    {
        get
        {
            if (_current == null)
            {
                lock (_lock)
                {
                    _current ??= Load(DefaultConfigPath);
                }
            }
            return _current;
        }
    }

    public static PhalanxConfiguration Load(string? path = null)
    {
        var targetPath = path ?? DefaultConfigPath;
        if (!File.Exists(targetPath))
        {
            return new PhalanxConfiguration();
        }

        try
        {
            var json = File.ReadAllText(targetPath);
            var loaded = JsonSerializer.Deserialize<PhalanxConfiguration>(json, JsonReadOptions);
            return loaded ?? new PhalanxConfiguration();
        }
        catch
        {
            return new PhalanxConfiguration();
        }
    }

    public static bool TryLoad(string path, out PhalanxConfiguration? config)
    {
        config = null;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        try
        {
            var json = File.ReadAllText(path);
            config = JsonSerializer.Deserialize<PhalanxConfiguration>(json, JsonReadOptions);
            return config != null;
        }
        catch
        {
            return false;
        }
    }

    public static void Save(PhalanxConfiguration config, string? path = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        var targetPath = path ?? DefaultConfigPath;

        var json = JsonSerializer.Serialize(config, JsonWriteOptions);

        lock (_lock)
        {
            var directory = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(targetPath, json);

            if (string.IsNullOrEmpty(path) || string.Equals(Path.GetFullPath(targetPath), Path.GetFullPath(DefaultConfigPath), StringComparison.OrdinalIgnoreCase))
            {
                _current = config;
            }
        }

        ConfigurationChanged?.Invoke(config);
    }

    public static PhalanxConfiguration Reload(string? path = null)
    {
        var targetPath = path ?? DefaultConfigPath;
        var loaded = Load(targetPath);

        lock (_lock)
        {
            if (string.IsNullOrEmpty(path) || string.Equals(Path.GetFullPath(targetPath), Path.GetFullPath(DefaultConfigPath), StringComparison.OrdinalIgnoreCase))
            {
                _current = loaded;
            }
        }

        ConfigurationChanged?.Invoke(loaded);
        return loaded;
    }
}
