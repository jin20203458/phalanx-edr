using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

public class ProcessMemoryScanToolTests
{
    private readonly ProcessMemoryScanTool _tool = new();

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestProcessMemoryScan_SimulatedSuspiciousDll_Detected()
    {
        // Arrange: 시뮬레이션 메모리에 version.dll이 로드된 mock PID 등록
        uint mockPid = 9988;
        var entry = new SimulatedMemoryEntry(
            BaseAddress: 0x7FFF0000,
            RegionSize: 65536,
            Protect: "PAGE_READWRITE",
            MemoryType: "MEM_IMAGE",
            InjectedHeader: null,
            ExtractedIps: new List<string>(),
            ExtractedUrls: new List<string>(),
            DetectedKeywords: new List<string>(),
            LoadedModules: new List<string> { @"C:\Windows\System32\kernel32.dll", @"C:\Users\Public\OneDrive\version.dll" }
        );

        ProcessMemoryScanTool.RegisterSimulatedMemory(mockPid, entry);

        try
        {
            // Act
            var result = await _tool.ExecuteAsync(new() { ["targetPid"] = mockPid });

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True((bool)result.Data["HasSuspiciousDll"]);

            var suspicious = (List<string>)result.Data["SideloadedDlls"];
            Assert.Contains(@"C:\Users\Public\OneDrive\version.dll", suspicious);
            Assert.Contains("T1574.002", result.Output);
        }
        finally
        {
            ProcessMemoryScanTool.ClearSimulatedMemory(mockPid);
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestProcessMemoryScan_SimulatedCleanDll_NotDetected()
    {
        // Arrange: 시스템 표준 DLL만 로드된 정상 mock PID
        uint mockPid = 9989;
        var entry = new SimulatedMemoryEntry(
            BaseAddress: 0x7FFF0000,
            RegionSize: 65536,
            Protect: "PAGE_READONLY",
            MemoryType: "MEM_IMAGE",
            InjectedHeader: null,
            ExtractedIps: new List<string>(),
            ExtractedUrls: new List<string>(),
            DetectedKeywords: new List<string>(),
            LoadedModules: new List<string> { @"C:\Windows\System32\kernel32.dll", @"C:\Windows\System32\ntdll.dll" }
        );

        ProcessMemoryScanTool.RegisterSimulatedMemory(mockPid, entry);

        try
        {
            // Act
            var result = await _tool.ExecuteAsync(new() { ["targetPid"] = mockPid });

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.False((bool)result.Data["HasSuspiciousDll"]);
            Assert.Empty((List<string>)result.Data["SideloadedDlls"]);
        }
        finally
        {
            ProcessMemoryScanTool.ClearSimulatedMemory(mockPid);
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestProcessMemoryScan_SimulatedUnbackedMemory_Detected()
    {
        // Arrange: Unbacked 실행 메모리가 존재하는 인젝션 모의
        uint mockPid = 9990;
        var entry = new SimulatedMemoryEntry(
            BaseAddress: 0x1A2B0000,
            RegionSize: 131072,
            Protect: "PAGE_EXECUTE_READWRITE",
            MemoryType: "MEM_PRIVATE",
            InjectedHeader: "MZ",
            ExtractedIps: new List<string> { "194.165.16.2" },
            ExtractedUrls: new List<string> { "http://194.165.16.2/beacon" },
            DetectedKeywords: new List<string> { "beacon" },
            LoadedModules: new List<string>()
        );

        ProcessMemoryScanTool.RegisterSimulatedMemory(mockPid, entry);

        try
        {
            // Act
            var result = await _tool.ExecuteAsync(new() { ["targetPid"] = mockPid });

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True((bool)result.Data["HasUnbackedExecutableMemory"]);

            var ips = (List<string>)result.Data["Ips"];
            Assert.Contains("194.165.16.2", ips);
        }
        finally
        {
            ProcessMemoryScanTool.ClearSimulatedMemory(mockPid);
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestProcessMemoryScan_NonExistentMockPid_HandledGracefully()
    {
        // Arrange: 시스템에 존재하지 않을 음수/초대형 PID
        uint nonExistentPid = 99999999;

        // Act
        var result = await _tool.ExecuteAsync(new() { ["targetPid"] = nonExistentPid });

        // Assert: 크래시 없이 안전하게 에러 또는 false 반환 처리
        Assert.NotNull(result);
        Assert.NotNull(result.Output);
    }
}
