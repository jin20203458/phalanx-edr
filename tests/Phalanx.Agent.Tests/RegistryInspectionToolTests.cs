using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

public class RegistryInspectionToolTests
{
    private readonly RegistryInspectionTool _tool = new();

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestRegistryInspection_SquiblydooScriptlet_DetectedAndScore80()
    {
        // Arrange: regsvr32 /i: 를 통한 Squiblydoo 스크립틀릿 간접 실행 CLSID 키
        string keyPath = @"Software\Classes\CLSID\{F0001111-0000-0000-0000-000000000001}";
        var entry = RegistryInspectionTool.CreateSimulatedEntry(
            keyPath: keyPath,
            exists: true,
            defaultValue: "Malicious Squiblydoo Component",
            values: new Dictionary<string, object>
            {
                ["ScriptletURL"] = "http://185.220.101.5/payload.sct",
                ["InprocServer32"] = @"C:\Windows\System32\scrobj.dll"
            },
            subKeys: new List<string> { "InprocServer32" }
        );

        RegistryInspectionTool.RegisterSimulatedKey(keyPath, entry);

        try
        {
            // Act
            var result = await _tool.ExecuteAsync(new() { ["registryKey"] = keyPath });

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True((bool)result.Data["Exists"]);
            Assert.True((bool)result.Data["IsIndirectExecution"]);
            Assert.False((bool)result.Data["IsComHijack"]);

            int score = (int)result.Data["AnomalyScore"];
            Assert.True(score >= 80, $"스퀴블리두 스크립틀릿 위험도는 80점 이상이어야 함: {score}");

            var ips = Assert.IsAssignableFrom<List<string>>(result.Data["ExtractedIps"]);
            Assert.Contains("185.220.101.5", ips);

            var urls = Assert.IsAssignableFrom<List<string>>(result.Data["ExtractedUrls"]);
            Assert.Contains("http://185.220.101.5/payload.sct", urls);

            string reason = (string)result.Data["DiagnosticReason"];
            Assert.Contains("T1218.010", reason);
        }
        finally
        {
            RegistryInspectionTool.ClearSimulatedKeys();
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestRegistryInspection_ComHijacking_UserDirectoryDll_Detected()
    {
        // Arrange: 사용자 AppData 디렉터리의 무서명 DLL을 가리키는 악성 COM 서버
        string keyPath = @"HKEY_CURRENT_USER\Software\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InprocServer32";
        var entry = RegistryInspectionTool.CreateSimulatedEntry(
            keyPath: keyPath,
            exists: true,
            defaultValue: @"C:\Users\user\AppData\Local\Temp\malicious_payload.dll",
            values: new Dictionary<string, object>
            {
                ["ThreadingModel"] = "Apartment"
            }
        );

        RegistryInspectionTool.RegisterSimulatedKey(keyPath, entry);

        try
        {
            // Act
            var result = await _tool.ExecuteAsync(new() { ["keyPath"] = keyPath });

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True((bool)result.Data["Exists"]);
            Assert.True((bool)result.Data["IsComHijack"]);

            int score = (int)result.Data["AnomalyScore"];
            Assert.True(score >= 50, $"COM 하이재킹 위험도는 50점 이상이어야 함: {score}");

            string reason = (string)result.Data["DiagnosticReason"];
            Assert.Contains("T1546.015", reason);
        }
        finally
        {
            RegistryInspectionTool.ClearSimulatedKeys();
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestRegistryInspection_RunKey_LolbasExecution_Detected()
    {
        // Arrange: Run 지속성 키에 등록된 powershell 인라인 페이로드
        string keyPath = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run";
        var entry = RegistryInspectionTool.CreateSimulatedEntry(
            keyPath: keyPath,
            exists: true,
            defaultValue: null,
            values: new Dictionary<string, object>
            {
                ["WindowsSecurityUpdate"] = @"powershell.exe -w hidden -enc SQBFAFg..."
            }
        );

        RegistryInspectionTool.RegisterSimulatedKey(keyPath, entry);

        try
        {
            // Act
            var result = await _tool.ExecuteAsync(new() { ["path"] = keyPath });

            // Assert
            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True((bool)result.Data["Exists"]);

            int score = (int)result.Data["AnomalyScore"];
            Assert.True(score >= 40, $"Run 키 LOLBAS 지속성 위험도는 40점 이상이어야 함: {score}");

            string reason = (string)result.Data["DiagnosticReason"];
            Assert.Contains("LOLBAS", reason);
        }
        finally
        {
            RegistryInspectionTool.ClearSimulatedKeys();
        }
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestRegistryInspection_NonExistentKey_HandledGracefully()
    {
        // Arrange
        string nonExistent = @"HKEY_CURRENT_USER\Software\Phalanx_NonExistent_Test_Key_99999";

        // Act
        var result = await _tool.ExecuteAsync(new() { ["registryKey"] = nonExistent });

        // Assert
        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.False((bool)result.Data["Exists"]);
        Assert.Equal(0, (int)result.Data["AnomalyScore"]);
        Assert.Contains("미발견", result.Output);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task TestRegistryInspection_MissingArgument_ReturnsFailure()
    {
        // Act
        var result = await _tool.ExecuteAsync(new Dictionary<string, object>());

        // Assert
        Assert.False(result.Success);
        Assert.Contains("누락", result.Output);
    }
}
