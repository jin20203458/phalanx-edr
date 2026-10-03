using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Phalanx.Cockpit.Tools;

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
/// 동결된 타깃 프로세스의 가상 메모리(RAM)를 VAD(Virtual Address Descriptor) 타깃 순회 기법으로 스캔하여
/// Unbacked Executable Memory(MEM_PRIVATE 실행 권한), Reflective DLL(MZ 헤더), C2 URL/IP 및 악성 문자열을 탐지하는 상용 1티어 도구
/// </summary>
public class ProcessMemoryScanTool : IInvestigationTool
{
    public string Name => "ProcessMemoryScanTool";

    public string Description => "동결된 타깃 프로세스의 VAD 영역(ReadProcessMemory)을 스캔하여 인메모리 DLL(MZ 헤더), C2 IP, 도메인, URL 및 악성 문자열을 추출합니다. 매개변수: 'targetPid' (uint 또는 int)";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex UrlRegex = new(@"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex IpRegex = new(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", RegexOptions.Compiled, RegexTimeout);
    private static readonly string[] SuspiciousKeywords = [ "invoke-expression", "iex", "downloadstring", "mimikatz", "beacon", "meterpreter", "shadows", "vssadmin", "virtualalloc", "createremotethread" ];

    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "services", "lsass"
    };

    private static readonly ConcurrentDictionary<uint, SimulatedMemoryEntry> SimulatedMemoryDb = new();

    public static void RegisterSimulatedMemory(uint pid, SimulatedMemoryEntry entry)
    {
        SimulatedMemoryDb[pid] = entry;
    }

    public static void ClearSimulatedMemory(uint pid)
    {
        SimulatedMemoryDb.TryRemove(pid, out _);
    }

    private const int ChunkSize = 65536; // 64 KB
    private const long MaxScanBytes = 16 * 1024 * 1024; // 최대 16MB 안전 스캔 (SLA < 10ms 보장)

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        uint pid = 0;
        var caseInsensitive = new Dictionary<string, object>(parameters, StringComparer.OrdinalIgnoreCase);
        if (caseInsensitive.TryGetValue("targetPid", out var rawPid) ||
            caseInsensitive.TryGetValue("target_pid", out rawPid) ||
            caseInsensitive.TryGetValue("pid", out rawPid))
        {
            if (rawPid is uint u) pid = u;
            else if (rawPid is int i && i > 0) pid = (uint)i;
            else if (rawPid is string s && uint.TryParse(s, out var parsed)) pid = parsed;
            else if (rawPid is System.Text.Json.JsonElement je && je.ValueKind == System.Text.Json.JsonValueKind.Number && je.TryGetUInt32(out var jPid)) pid = jPid;
        }

        if (pid == 0)
        {
            return Task.FromResult(new ToolResult(false, "유효한 'targetPid'가 제공되지 않았습니다."));
        }

        // 0. Clean-Room 모드 시뮬레이션 인젝션 메모리 검사
        if (SimulatedMemoryDb.TryGetValue(pid, out var sim))
        {
            var sbSim = new StringBuilder();
            sbSim.AppendLine($"[ProcessMemoryScanTool 완료 - PID: {pid}, 스캔 용량: {sim.RegionSize / 1024} KB, Unbacked 실행 영역: 1개]");
            sbSim.AppendLine($"• 검출된 인젝션: BaseAddress: 0x{sim.BaseAddress:X16}, Size: {sim.RegionSize / 1024} KB, Protect: {sim.Protect} ({sim.MemoryType})");
            if (!string.IsNullOrEmpty(sim.InjectedHeader))
            {
                sbSim.AppendLine($"• 메모리 헤더 시그니처: {sim.InjectedHeader}");
            }
            if (sim.ExtractedIps.Count > 0)
            {
                sbSim.AppendLine($"• 메모리 추출 IP: {string.Join(", ", sim.ExtractedIps)}");
            }
            if (sim.ExtractedUrls.Count > 0)
            {
                sbSim.AppendLine($"• 메모리 추출 URL: {string.Join(", ", sim.ExtractedUrls)}");
            }

            bool hasSuspiciousDll = false;
            var sideloadedDlls = new List<string>();
            if (sim.LoadedModules != null)
            {
                foreach (var mod in sim.LoadedModules)
                {
                    string modName = System.IO.Path.GetFileName(mod);
                    if (FileInspectionTool.KnownSideloadCandidateDlls.Contains(modName))
                    {
                        hasSuspiciousDll = true;
                        sideloadedDlls.Add(mod);
                    }
                }
            }
            if (hasSuspiciousDll)
            {
                sbSim.AppendLine($"• 의심 모듈/사이드로딩 검출(T1574.002): {string.Join(", ", sideloadedDlls)}");
            }

            bool isUnbacked = string.Equals(sim.MemoryType, "MEM_PRIVATE", StringComparison.OrdinalIgnoreCase) &&
                              sim.Protect.Contains("EXECUTE", StringComparison.OrdinalIgnoreCase);

            var simData = new Dictionary<string, object>
            {
                ["Pid"] = pid,
                ["ScannedBytes"] = sim.RegionSize,
                ["Urls"] = sim.ExtractedUrls,
                ["Ips"] = sim.ExtractedIps,
                ["SuspiciousKeywords"] = sim.DetectedKeywords,
                ["DetectedInjections"] = isUnbacked ? new List<string> { $"BaseAddress: 0x{sim.BaseAddress:X16}, Protect: {sim.Protect}, Type: {sim.MemoryType}" } : new List<string>(),
                ["HasUnbackedExecutableMemory"] = isUnbacked,
                ["UnbackedExecPages"] = isUnbacked ? 1 : 0,
                ["UnbackedExecutablePages"] = isUnbacked ? 1 : 0,
                ["HasSuspiciousDll"] = hasSuspiciousDll,
                ["SideloadedDlls"] = sideloadedDlls
            };

            return Task.FromResult(new ToolResult(true, sbSim.ToString(), simData));
        }

        // 1. 시스템 보호 프로세스 가드
        if (pid <= 4)
        {
            return Task.FromResult(new ToolResult(false, $"안전 가드: 시스템 핵심 프로세스(PID: {pid})의 메모리는 스캔할 수 없습니다."));
        }

        try
        {
            using var proc = Process.GetProcessById((int)pid);
            if (ProtectedProcessNames.Contains(proc.ProcessName))
            {
                return Task.FromResult(new ToolResult(false, $"안전 가드: 보호된 윈도우 서브시스템 프로세스 '{proc.ProcessName}'(PID: {pid})는 스캔할 수 없습니다."));
            }
        }
        catch (ArgumentException)
        {
            var notFoundData = new Dictionary<string, object>
            {
                ["Pid"] = pid,
                ["ScannedBytes"] = 0L,
                ["Urls"] = new List<string>(),
                ["Ips"] = new List<string>(),
                ["SuspiciousKeywords"] = new List<string>(),
                ["DetectedInjections"] = new List<string>(),
                ["UnbackedExecPages"] = 0,
                ["HasSuspiciousDll"] = false,
                ["SideloadedDlls"] = new List<string>()
            };
            return Task.FromResult(new ToolResult(true, $"[ProcessMemoryScanTool] 타깃 PID {pid} 프로세스가 존재하지 않거나 종료됨 (가상 스캔 완료)", notFoundData));
        }
        catch { }

        try
        {
            var foundUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var foundIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var foundKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var detectedInjections = new List<string>();
            long totalScannedBytes = 0;
            int unbackedExecPages = 0;

            IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return Task.FromResult(new ToolResult(false, $"타깃 PID {pid} 프로세스 핸들 획득 실패 (Win32 Error: {err}). SeDebugPrivilege 또는 권한을 확인하십시오."));
            }

            byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkSize);
            try
            {
                IntPtr currentAddress = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION mbi;
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                long maxUserAddress = Environment.Is64BitProcess ? 0x7FFFFFFF0000L : 0x7FFF0000L;

                while (VirtualQueryEx(hProcess, currentAddress, out mbi, (uint)mbiSize) != 0 &&
                       totalScannedBytes < MaxScanBytes &&
                       currentAddress.ToInt64() < maxUserAddress)
                {
                    bool isCommitted = mbi.State == MEM_COMMIT;
                    bool isGuardPage = (mbi.Protect & PAGE_GUARD) != 0 || (mbi.Protect & PAGE_NOACCESS) != 0;

                    // 1티어 핵심: Unbacked Executable Memory (파일 매핑 없는 사설 실행 가능 메모리 - Cobalt Strike / Shellcode 핵심 서식지)
                    bool isUnbackedExecutable = isCommitted && !isGuardPage &&
                                                (mbi.Type == MEM_PRIVATE) &&
                                                ((mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE)) != 0);

                    // 보조: 사설 읽기/쓰기 메모리 (동적 힙 및 복호화된 페이로드 탐색)
                    bool isPrivateHeap = isCommitted && !isGuardPage &&
                                         (mbi.Type == MEM_PRIVATE) &&
                                         ((mbi.Protect & PAGE_READWRITE) != 0) &&
                                         totalScannedBytes < (4 * 1024 * 1024); // 힙은 최대 4MB까지만 가볍게 스캔

                    if (isUnbackedExecutable || isPrivateHeap)
                    {
                        if (isUnbackedExecutable) unbackedExecPages++;

                        long regionSize = mbi.RegionSize.ToInt64();
                        long offset = 0;
                        bool checkedHeader = false;

                        while (offset < regionSize && totalScannedBytes < MaxScanBytes)
                        {
                            int bytesToRead = (int)Math.Min(ChunkSize, regionSize - offset);
                            IntPtr readAddr = new IntPtr(mbi.BaseAddress.ToInt64() + offset);

                            if (ReadProcessMemory(hProcess, readAddr, buffer, bytesToRead, out int bytesRead) && bytesRead > 0)
                            {
                                totalScannedBytes += bytesRead;

                                // 첫 청크에서 Reflective DLL (MZ 헤더) 탐지 (사설 실행 메모리에서 MZ는 100% 인메모리 PE 주입)
                                if (!checkedHeader && isUnbackedExecutable)
                                {
                                    checkedHeader = true;
                                    if (bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A) // 'MZ'
                                    {
                                        detectedInjections.Add($"[경고] Reflective PE/DLL 주입 발견: 주소 0x{mbi.BaseAddress.ToInt64():X} (MEM_PRIVATE + 실행 권한 영역 내 MZ 헤더 존재)");
                                    }
                                }

                                ScanBufferChunk(buffer, bytesRead, foundUrls, foundIps, foundKeywords);
                            }
                            else
                            {
                                break;
                            }

                            offset += bytesToRead;
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddr <= currentAddress.ToInt64()) break; // 오버플로우 방지
                    currentAddress = new IntPtr(nextAddr);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                CloseHandle(hProcess);
            }

            var sb = new StringBuilder();
            sb.AppendLine($"[ProcessMemoryScanTool 완료 - PID: {pid}, 스캔 용량: {totalScannedBytes / 1024} KB, Unbacked 실행 영역: {unbackedExecPages}개]");

            if (detectedInjections.Count > 0)
            {
                foreach (var inj in detectedInjections)
                {
                    sb.AppendLine(inj);
                }
            }

            sb.AppendLine($"• 발견된 잠재적 C2 URL: {(foundUrls.Count > 0 ? string.Join(", ", foundUrls) : "(없음)")}");
            sb.AppendLine($"• 발견된 IP 주소: {(foundIps.Count > 0 ? string.Join(", ", foundIps) : "(없음)")}");
            sb.AppendLine($"• 발견된 악성 키워드: {(foundKeywords.Count > 0 ? string.Join(", ", foundKeywords) : "(없음)")}");

            var loadedModules = EnumerateProcessModulesSafe(pid);
            bool hasSuspiciousModule = false;
            var sideloadedModuleList = new List<string>();
            foreach (var mod in loadedModules)
            {
                string modName = System.IO.Path.GetFileName(mod);
                if (FileInspectionTool.KnownSideloadCandidateDlls.Contains(modName))
                {
                    if (!mod.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) &&
                        !mod.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase))
                    {
                        hasSuspiciousModule = true;
                        sideloadedModuleList.Add(mod);
                    }
                }
            }
            if (hasSuspiciousModule)
            {
                sb.AppendLine($"• 비표준 디렉터리 시스템 모듈 로드 포착: {string.Join(", ", sideloadedModuleList)}");
            }

            var data = new Dictionary<string, object>
            {
                ["ScannedBytes"] = totalScannedBytes,
                ["Urls"] = foundUrls.ToList(),
                ["Ips"] = foundIps.ToList(),
                ["Keywords"] = foundKeywords.ToList(),
                ["DetectedInjections"] = detectedInjections,
                ["UnbackedExecutablePages"] = unbackedExecPages,
                ["HasSuspiciousDll"] = hasSuspiciousModule,
                ["SideloadedDlls"] = sideloadedModuleList
            };

            return Task.FromResult(new ToolResult(true, sb.ToString(), data));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new ToolResult(false, $"메모리 스캔 중 예외 발생: {ex.Message}"));
        }
    }

    private static void ScanBufferChunk(byte[] buffer, int length, HashSet<string> urls, HashSet<string> ips, HashSet<string> keywords)
    {
        // ASCII 문자열 및 UTF-16LE 유효 문자 탐색
        string asciiText = Encoding.ASCII.GetString(buffer, 0, length);
        string unicodeText = Encoding.Unicode.GetString(buffer, 0, length);

        foreach (var text in new[] { asciiText, unicodeText })
        {
            try
            {
                foreach (Match m in UrlRegex.Matches(text))
                {
                    string u = m.Value;
                    if (u.Length >= 10 &&
                        !u.Contains("schemas.microsoft.com", StringComparison.OrdinalIgnoreCase) &&
                        !u.Contains("w3.org", StringComparison.OrdinalIgnoreCase) &&
                        !u.Contains("schemas.openxmlformats.org", StringComparison.OrdinalIgnoreCase))
                    {
                        urls.Add(u);
                    }
                }
            }
            catch (RegexMatchTimeoutException) { }

            try
            {
                foreach (Match m in IpRegex.Matches(text))
                {
                    string ip = m.Value;
                    if (!ip.StartsWith("127.") && !ip.StartsWith("0.0.") && !ip.StartsWith("255."))
                    {
                        ips.Add(ip);
                    }
                }
            }
            catch (RegexMatchTimeoutException) { }

            foreach (var kw in SuspiciousKeywords)
            {
                if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
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
    private const uint MEM_PRIVATE = 0x00020000;

    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_GUARD = 0x100;

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    private const uint TH32CS_SNAPMODULE = 0x00000008;
    private const uint TH32CS_SNAPMODULE32 = 0x00000010;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    private static List<string> EnumerateProcessModulesSafe(uint pid)
    {
        var modules = new List<string>();
        if (!OperatingSystem.IsWindows()) return modules;

        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnapshot == IntPtr.Zero || hSnapshot == INVALID_HANDLE_VALUE)
        {
            return modules;
        }

        try
        {
            MODULEENTRY32 me = new MODULEENTRY32();
            me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));
            if (Module32First(hSnapshot, ref me))
            {
                do
                {
                    if (!string.IsNullOrEmpty(me.szExePath)) modules.Add(me.szExePath);
                } while (Module32Next(hSnapshot, ref me));
            }
        }
        finally
        {
            CloseHandle(hSnapshot);
        }

        return modules;
    }
    #endregion
}
