using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 동결된 타깃 프로세스의 가상 메모리(RAM)를 P/Invoke로 안전하게 순회하여
/// 메모리 내부에 남아있는 C2 IP, 도메인, URL 및 악성 문자열을 탐색하는 도구
/// </summary>
public class ProcessMemoryScanTool : IInvestigationTool
{
    public string Name => "ProcessMemoryScanTool";

    public string Description => "동결된 타깃 프로세스의 RAM 영역(ReadProcessMemory)을 스캔하여 C2 IP, 도메인, URL 및 악성 문자열을 추출합니다. 매개변수: 'targetPid' (uint 또는 int)";

    private static readonly Regex UrlRegex = new(@"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+", RegexOptions.Compiled);
    private static readonly Regex IpRegex = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled);
    private static readonly string[] SuspiciousKeywords = { "invoke-expression", "iex", "downloadstring", "mimikatz", "beacon", "meterpreter", "shadows", "vssadmin" };

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        uint pid = 0;
        if (parameters.TryGetValue("targetPid", out var rawPid))
        {
            if (rawPid is uint u) pid = u;
            else if (rawPid is int i && i > 0) pid = (uint)i;
            else if (rawPid is string s && uint.TryParse(s, out var parsed)) pid = parsed;
        }

        if (pid == 0)
        {
            return Task.FromResult(new ToolResult(false, "유효한 'targetPid'가 제공되지 않았습니다."));
        }

        try
        {
            var foundUrls = new HashSet<string>();
            var foundIps = new HashSet<string>();
            var foundKeywords = new HashSet<string>();
            long totalScannedBytes = 0;

            IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return Task.FromResult(new ToolResult(false, $"타깃 PID {pid} 프로세스 핸들 획득 실패 (Win32 Error: {err}). SeDebugPrivilege 또는 권한을 확인하십시오."));
            }

            try
            {
                IntPtr currentAddress = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION mbi;
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                // 최대 50MB까지만 안전 스캔 (지연 시간 방지)
                const long maxScanBytes = 50 * 1024 * 1024;

                while (VirtualQueryEx(hProcess, currentAddress, out mbi, (uint)mbiSize) != 0 && totalScannedBytes < maxScanBytes)
                {
                    // 커밋되어 있고 읽기 가능한 페이지만 스캔
                    bool isReadable = (mbi.State == MEM_COMMIT) &&
                                     ((mbi.Protect & PAGE_READONLY) != 0 ||
                                      (mbi.Protect & PAGE_READWRITE) != 0 ||
                                      (mbi.Protect & PAGE_EXECUTE_READ) != 0 ||
                                      (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0);

                    if (isReadable && mbi.RegionSize.ToInt64() > 0 && mbi.RegionSize.ToInt64() <= 4 * 1024 * 1024)
                    {
                        byte[] buffer = new byte[mbi.RegionSize.ToInt64()];
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, (int)buffer.Length, out int bytesRead) && bytesRead > 0)
                        {
                            totalScannedBytes += bytesRead;
                            ScanBuffer(buffer, bytesRead, foundUrls, foundIps, foundKeywords);
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddr <= currentAddress.ToInt64()) break; // 오버플로우 방지
                    currentAddress = new IntPtr(nextAddr);
                }
            }
            finally
            {
                CloseHandle(hProcess);
            }

            var sb = new StringBuilder();
            sb.AppendLine($"[ProcessMemoryScanTool 완료 - PID: {pid}, 스캔 용량: {totalScannedBytes / 1024} KB]");
            sb.AppendLine($"• 발견된 잠재적 C2 URL: {(foundUrls.Count > 0 ? string.Join(", ", foundUrls) : "(없음)")}");
            sb.AppendLine($"• 발견된 IP 주소: {(foundIps.Count > 0 ? string.Join(", ", foundIps) : "(없음)")}");
            sb.AppendLine($"• 발견된 악성 키워드: {(foundKeywords.Count > 0 ? string.Join(", ", foundKeywords) : "(없음)")}");

            var data = new Dictionary<string, object>
            {
                ["ScannedBytes"] = totalScannedBytes,
                ["Urls"] = foundUrls.ToList(),
                ["Ips"] = foundIps.ToList(),
                ["Keywords"] = foundKeywords.ToList()
            };

            return Task.FromResult(new ToolResult(true, sb.ToString(), data));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new ToolResult(false, $"메모리 스캔 중 예외 발생: {ex.Message}"));
        }
    }

    private static void ScanBuffer(byte[] buffer, int length, HashSet<string> urls, HashSet<string> ips, HashSet<string> keywords)
    {
        // ASCII 및 Unicode(UTF-16LE) 문자열 동시 추출
        string asciiText = Encoding.ASCII.GetString(buffer, 0, length);
        string unicodeText = Encoding.Unicode.GetString(buffer, 0, length);

        foreach (var text in new[] { asciiText, unicodeText })
        {
            foreach (Match m in UrlRegex.Matches(text))
            {
                if (m.Value.Length >= 10 && !m.Value.Contains("schemas.microsoft.com") && !m.Value.Contains("w3.org"))
                {
                    urls.Add(m.Value);
                }
            }

            foreach (Match m in IpRegex.Matches(text))
            {
                if (!m.Value.StartsWith("127.") && !m.Value.StartsWith("0.0.") && !m.Value.StartsWith("255."))
                {
                    ips.Add(m.Value);
                }
            }

            string lower = text.ToLowerInvariant();
            foreach (var kw in SuspiciousKeywords)
            {
                if (lower.Contains(kw))
                {
                    keywords.Add(kw);
                }
            }
        }
    }

    #region Win32 P/Invoke
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    #endregion
}
