namespace Phalanx.Cockpit.Tools;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;

/// <summary>
/// 파일 정적 검사 Clean-Room 모의 시뮬레이션 엔트리.
/// </summary>
public record SimulatedFileEntry(
    bool Exists,
    long FileSizeBytes,
    string Sha256,
    double Entropy,
    bool IsSigned,
    string SignerSubject,
    string SignatureStatus,
    bool IsPathMasqueraded,
    bool IsDisguisedExecutable,
    int AnomalyScore,
    string DiagnosticReason
);

/// <summary>
/// 프로세스 메모리 스캔 Clean-Room 모의 시뮬레이션 엔트리.
/// </summary>
public record SimulatedMemoryEntry(
    long BaseAddress,
    long RegionSize,
    string Protect,
    string MemoryType,
    string? InjectedHeader,
    List<string> ExtractedIps,
    List<string> ExtractedUrls,
    List<string> DetectedKeywords,
    List<string>? LoadedModules = null
);

/// <summary>
/// 레지스트리 정적 검사 Clean-Room 모의 시뮬레이션 엔트리.
/// </summary>
public record SimulatedRegistryEntry(
    bool Exists,
    string KeyPath,
    string? DefaultValue,
    Dictionary<string, object> Values,
    List<string> SubKeys,
    bool IsIndirectExecution,
    bool IsComHijack,
    int AnomalyScore,
    string DiagnosticReason,
    List<string> ExtractedUrls,
    List<string> ExtractedIps
);

/// <summary>
/// EDR 수사 도구들의 Clean-Room 시뮬레이션 모의 데이터를 중앙 격리 보관하는 전용 저장소.
/// 프로덕션 도구 본체로부터 테스트/어택랩용 정적 딕셔너리를 분리하여 도구의 순수성을 보장합니다.
/// </summary>
public static class CleanRoomSimulationStore
{
    private static readonly ConcurrentDictionary<string, SimulatedFileEntry> _simulatedFiles =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly ConcurrentDictionary<uint, SimulatedMemoryEntry> _simulatedMemory = new();

    private static readonly ConcurrentDictionary<string, SimulatedRegistryEntry> _simulatedKeys =
        new(StringComparer.OrdinalIgnoreCase);

    #region 파일 시뮬레이션

    public static void RegisterFile(string path, SimulatedFileEntry entry)
    {
        _simulatedFiles[NormalizePath(path)] = entry;
    }

    public static bool TryGetFile(string path, [NotNullWhen(true)] out SimulatedFileEntry? entry)
    {
        return _simulatedFiles.TryGetValue(NormalizePath(path), out entry);
    }

    public static void ClearFiles()
    {
        _simulatedFiles.Clear();
    }

    public static ICollection<string> SimulatedFilePaths => _simulatedFiles.Keys;

    #endregion

    #region 메모리 시뮬레이션

    public static void RegisterMemory(uint pid, SimulatedMemoryEntry entry)
    {
        _simulatedMemory[pid] = entry;
    }

    public static bool TryGetMemory(uint pid, [NotNullWhen(true)] out SimulatedMemoryEntry? entry)
    {
        return _simulatedMemory.TryGetValue(pid, out entry);
    }

    public static void ClearMemory(uint pid)
    {
        _simulatedMemory.TryRemove(pid, out _);
    }

    public static void ClearAllMemory()
    {
        _simulatedMemory.Clear();
    }

    #endregion

    #region 레지스트리 시뮬레이션

    public static void RegisterKey(string path, SimulatedRegistryEntry entry)
    {
        _simulatedKeys[path] = entry;
    }

    public static bool TryGetKey(string path, [NotNullWhen(true)] out SimulatedRegistryEntry? entry)
    {
        return _simulatedKeys.TryGetValue(path, out entry);
    }

    public static void ClearKeys()
    {
        _simulatedKeys.Clear();
    }

    #endregion

    #region 전체 초기화

    public static void ResetAll()
    {
        ClearFiles();
        ClearAllMemory();
        ClearKeys();
    }

    #endregion

    private static string NormalizePath(string path)
    {
        try
        {
            string trimmed = path.Trim(' ', '\t', '"', '\'');
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return path.Trim(' ', '\t', '"', '\'').Replace('/', '\\');
        }
    }
}
