using System.Collections.Generic;
using System.Text.Json;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class ToolParameterExtensionsTests
{
    [Fact]
    public void GetString_DirectMatching_ReturnsCorrectString()
    {
        var parameters = new Dictionary<string, object>
        {
            ["encodedCommand"] = "powershell -enc aW52b2tl"
        };

        var result = parameters.GetString("encodedCommand", "command");

        Assert.Equal("powershell -enc aW52b2tl", result);
    }

    [Fact]
    public void GetString_CaseInsensitiveMatching_ExtractsValue()
    {
        var parameters = new Dictionary<string, object>
        {
            ["ENCODEDCOMMAND"] = "whoami /all"
        };

        var result = parameters.GetString("encodedCommand", "command");

        Assert.Equal("whoami /all", result);
    }

    [Fact]
    public void GetString_JsonElementValue_ExtractsString()
    {
        using var doc = JsonDocument.Parse("{\"command\": \"netstat -ano\"}");
        var parameters = new Dictionary<string, object>
        {
            ["command"] = doc.RootElement.GetProperty("command")
        };

        var result = parameters.GetString("command");

        Assert.Equal("netstat -ano", result);
    }

    [Fact]
    public void GetString_WhiteSpaceFirstAlias_SkipsToNextValidAlias()
    {
        var parameters = new Dictionary<string, object>
        {
            ["encodedCommand"] = "   ",
            ["command"] = "ipconfig /all"
        };

        var result = parameters.GetString("encodedCommand", "command");

        Assert.Equal("ipconfig /all", result);
    }

    [Fact]
    public void GetStringFallback_DirectMiss_MatchesSubstringFallback()
    {
        var parameters = new Dictionary<string, object>
        {
            ["custom_target_path"] = @"C:\Windows\System32\cmd.exe"
        };

        var result = parameters.GetStringFallback(new[] { "filePath", "file_path" }, "path");

        Assert.Equal(@"C:\Windows\System32\cmd.exe", result);
    }

    [Fact]
    public void GetStringFallback_MultipleFallbacks_MatchesAny()
    {
        var parameters = new Dictionary<string, object>
        {
            ["reg_key_location"] = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        };

        var result = parameters.GetStringFallback(new[] { "registryKey" }, "path", "key");

        Assert.Equal(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", result);
    }

    [Fact]
    public void GetUInt32_VariousTypes_ParsesCorrectly()
    {
        var p1 = new Dictionary<string, object> { ["pid"] = (uint)1234 };
        var p2 = new Dictionary<string, object> { ["pid"] = 5678 };
        var p3 = new Dictionary<string, object> { ["pid"] = "9012" };

        using var doc = JsonDocument.Parse("{\"pid\": 4321, \"strPid\": \"8765\"}");
        var p4 = new Dictionary<string, object> { ["pid"] = doc.RootElement.GetProperty("pid") };
        var p5 = new Dictionary<string, object> { ["pid"] = doc.RootElement.GetProperty("strPid") };

        Assert.Equal(1234u, p1.GetUInt32("pid"));
        Assert.Equal(5678u, p2.GetUInt32("pid"));
        Assert.Equal(9012u, p3.GetUInt32("pid"));
        Assert.Equal(4321u, p4.GetUInt32("pid"));
        Assert.Equal(8765u, p5.GetUInt32("pid"));
    }

    [Fact]
    public void NullOrEmptyParameters_ReturnsNullSafely()
    {
        Dictionary<string, object>? nullParams = null;
        var emptyParams = new Dictionary<string, object>();

        Assert.Null(nullParams.GetString("key"));
        Assert.Null(emptyParams.GetString("key"));
        Assert.Null(nullParams.GetUInt32("pid"));
        Assert.Null(emptyParams.GetUInt32("pid"));
        Assert.Null(nullParams.GetStringFallback(new[] { "key" }, "fallback"));
        Assert.Null(emptyParams.GetStringFallback(new[] { "key" }, "fallback"));
    }
}
