using System.Collections.Generic;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class CleanRoomSimulationStoreTests
{
    public CleanRoomSimulationStoreTests()
    {
        CleanRoomSimulationStore.ResetAll();
    }

    [Fact]
    public void RegisterAndRetrieve_File_Succeeds()
    {
        var entry = new SimulatedFileEntry(
            Exists: true,
            FileSizeBytes: 1048576,
            Sha256: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            Entropy: 7.85,
            IsSigned: false,
            SignerSubject: "",
            SignatureStatus: "UNSIGNED",
            IsPathMasqueraded: true,
            IsDisguisedExecutable: false,
            AnomalyScore: 90,
            DiagnosticReason: "High critical threat"
        );

        CleanRoomSimulationStore.RegisterFile(@"C:\Windows\Temp\malware.exe", entry);

        bool found = CleanRoomSimulationStore.TryGetFile(@"c:\windows\temp\malware.exe", out var retrieved);

        Assert.True(found);
        Assert.NotNull(retrieved);
        Assert.Equal(entry.Sha256, retrieved.Sha256);
        Assert.Equal(entry.Entropy, retrieved.Entropy);
        Assert.Equal(90, retrieved.AnomalyScore);
    }

    [Fact]
    public void RegisterAndRetrieve_Memory_Succeeds()
    {
        var entry = new SimulatedMemoryEntry(
            BaseAddress: 0x7FFF0000,
            RegionSize: 65536,
            Protect: "PAGE_EXECUTE_READWRITE",
            MemoryType: "MEM_PRIVATE",
            InjectedHeader: "MZ (PE32)",
            ExtractedIps: new List<string> { "192.168.1.50" },
            ExtractedUrls: new List<string> { "http://c2.phalanx.local/beacon" },
            DetectedKeywords: new List<string> { "mimikatz", "virtualalloc" }
        );

        CleanRoomSimulationStore.RegisterMemory(4444, entry);

        bool found = CleanRoomSimulationStore.TryGetMemory(4444, out var retrieved);

        Assert.True(found);
        Assert.NotNull(retrieved);
        Assert.Equal(0x7FFF0000, retrieved.BaseAddress);
        Assert.Equal("PAGE_EXECUTE_READWRITE", retrieved.Protect);
        Assert.Contains("192.168.1.50", retrieved.ExtractedIps);
    }

    [Fact]
    public void RegisterAndRetrieve_Registry_Succeeds()
    {
        var values = new Dictionary<string, object>
        {
            ["RunKey"] = @"C:\Users\Public\update.exe"
        };
        var entry = new SimulatedRegistryEntry(
            Exists: true,
            KeyPath: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            DefaultValue: null,
            Values: values,
            SubKeys: new List<string>(),
            IsIndirectExecution: false,
            IsComHijack: false,
            AnomalyScore: 50,
            DiagnosticReason: "Auto-run persistence",
            ExtractedUrls: new List<string>(),
            ExtractedIps: new List<string>()
        );

        CleanRoomSimulationStore.RegisterKey(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", entry);

        bool found = CleanRoomSimulationStore.TryGetKey(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", out var retrieved);

        Assert.True(found);
        Assert.NotNull(retrieved);
        Assert.Equal(50, retrieved.AnomalyScore);
        Assert.True(retrieved.Values.ContainsKey("RunKey"));
    }

    [Fact]
    public void Clear_RemovesEntriesCorrectly()
    {
        CleanRoomSimulationStore.RegisterFile(@"C:\test.exe", new SimulatedFileEntry(true, 100, "hash", 0, false, "", "", false, false, 0, ""));
        CleanRoomSimulationStore.RegisterMemory(1111, new SimulatedMemoryEntry(0, 0, "", "", null, new(), new(), new()));
        CleanRoomSimulationStore.RegisterKey(@"HKLM\Test", new SimulatedRegistryEntry(true, @"HKLM\Test", null, new(), new(), false, false, 0, "", new(), new()));

        CleanRoomSimulationStore.ClearFiles();
        Assert.False(CleanRoomSimulationStore.TryGetFile(@"C:\test.exe", out _));

        CleanRoomSimulationStore.ClearMemory(1111);
        Assert.False(CleanRoomSimulationStore.TryGetMemory(1111, out _));

        CleanRoomSimulationStore.ClearKeys();
        Assert.False(CleanRoomSimulationStore.TryGetKey(@"HKLM\Test", out _));
    }

    [Fact]
    public void ResetAll_ClearsEverything()
    {
        CleanRoomSimulationStore.RegisterFile(@"C:\test.exe", new SimulatedFileEntry(true, 100, "hash", 0, false, "", "", false, false, 0, ""));
        CleanRoomSimulationStore.RegisterMemory(1111, new SimulatedMemoryEntry(0, 0, "", "", null, new(), new(), new()));
        CleanRoomSimulationStore.RegisterKey(@"HKLM\Test", new SimulatedRegistryEntry(true, @"HKLM\Test", null, new(), new(), false, false, 0, "", new(), new()));

        CleanRoomSimulationStore.ResetAll();

        Assert.False(CleanRoomSimulationStore.TryGetFile(@"C:\test.exe", out _));
        Assert.False(CleanRoomSimulationStore.TryGetMemory(1111, out _));
        Assert.False(CleanRoomSimulationStore.TryGetKey(@"HKLM\Test", out _));
    }
}
