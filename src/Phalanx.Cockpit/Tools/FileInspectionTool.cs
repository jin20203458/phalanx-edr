using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Phalanx.Cockpit.Tools;

/// <summary>
/// 디스크 상의 파일 경로, 디지털 서명(Authenticode), 시스템 파일 경로 위장(Masquerading T1036.005),
/// PE 매직 바이트 정합성 및 Shannon 엔트로피를 정밀 검증하는 EDR 6대 핵심 포렌식 도구.
/// </summary>
public sealed class FileInspectionTool : IInvestigationTool
{
    public string Name => "FileInspectionTool";

    public string Description =>
        "디스크 상의 파일 경로, 디지털 서명(Authenticode), 시스템 파일 위장(Masquerading), " +
        "PE 헤더 정합성, Shannon 엔트로피를 정밀 검증합니다. 인자: { \"filePath\": \"C:\\\\...\" }";

    #region Clean-Room 시뮬레이션 지원 (결정론적 테스트 및 모의 텔레메트리 랩)

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

    private static readonly ConcurrentDictionary<string, SimulatedFileEntry> _simulatedFiles =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 단위 테스트 및 어택랩 Clean-Room 모드용 모의 파일 텔레메트리 주입
    /// </summary>
    public static void RegisterSimulatedFile(string path, SimulatedFileEntry entry)
    {
        string norm = NormalizePath(path);
        _simulatedFiles[norm] = entry;
    }

    /// <summary>
    /// 모의 파일 텔레메트리 일괄 정리 (메모리 누수 방지)
    /// </summary>
    public static void ClearSimulatedFiles()
    {
        _simulatedFiles.Clear();
    }

    #endregion

    #region Win32 WinVerifyTrust P/Invoke 선언 및 구조체

    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000000;
    private const uint WTD_STATEACTION_IGNORE = 0x00000000;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000; // 10초 세이프티 워치독 SLA 보호: 네트워크 CRL/CTL 조회 차단
    private const uint WTD_SAFER_FLAG = 0x00000100;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // WINTRUST_FILE_INFO 포인터
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    // WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

    private static (bool IsSigned, string Status) VerifyAuthenticode(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
        try
        {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOCATION_CHECK_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_IGNORE,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = null!,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            IntPtr pTrustData = Marshal.AllocHGlobal(Marshal.SizeOf(trustData));
            try
            {
                Marshal.StructureToPtr(trustData, pTrustData, false);
                int hr = WinVerifyTrust(new IntPtr(-1) /* INVALID_HANDLE_VALUE */, WINTRUST_ACTION_GENERIC_VERIFY_V2, pTrustData);
                return hr switch
                {
                    0 => (true, "Valid (Trusted Root)"),
                    unchecked((int)0x800B0100) => (false, "NotSigned (TRUST_E_NOSIGNATURE)"),
                    unchecked((int)0x80096010) => (false, "HashMismatch (TRUST_E_BAD_DIGEST)"),
                    unchecked((int)0x800B0109) => (false, "UntrustedRoot (CERT_E_UNTRUSTEDROOT)"),
                    unchecked((int)0x800B010A) => (false, "ChainingError (CERT_E_CHAINING)"),
                    unchecked((int)0x800B0101) => (false, "Expired (CERT_E_EXPIRED)"),
                    _ => (false, $"VerificationFailed (0x{hr:X8})")
                };
            }
            finally
            {
                Marshal.FreeHGlobal(pTrustData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pFileInfo);
        }
    }

    #endregion

    #region 도구 실행 로직 (ExecuteAsync)

    public Task<ToolResult> ExecuteAsync(Dictionary<string, object> parameters)
    {
        string rawPath = ExtractFilePath(parameters);
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            return Task.FromResult(new ToolResult(false, "[FileInspectionTool 오류] 'filePath' 인자가 누락되었거나 비어 있습니다."));
        }

        string normalized = NormalizePath(rawPath);

        // 1. Clean-Room 모의 파일 주입 우선 조회
        if (_simulatedFiles.TryGetValue(normalized, out var sim))
        {
            return Task.FromResult(FormatResult(sim, normalized, isSimulated: true));
        }

        // 2. 실제 디스크 파일 존재 여부 검사
        if (!File.Exists(normalized))
        {
            var notFoundData = new Dictionary<string, object>
            {
                ["Exists"] = false,
                ["NormalizedPath"] = normalized,
                ["FileSizeBytes"] = 0L,
                ["Sha256"] = string.Empty,
                ["Entropy"] = 0.0,
                ["IsSigned"] = false,
                ["SignerSubject"] = string.Empty,
                ["SignatureStatus"] = "FileNotFound",
                ["IsPathMasqueraded"] = false,
                ["IsDisguisedExecutable"] = false,
                ["AnomalyScore"] = 0,
                ["DiagnosticReason"] = $"디스크 상에 타깃 파일이 존재하지 않습니다: '{normalized}'"
            };

            return Task.FromResult(new ToolResult(
                Success: true,
                Output: $"[FileInspectionTool] 파일 미발견: '{normalized}' (경로가 아직 생성되지 않았거나 메모리 전용 페이로드일 수 있음)",
                Data: notFoundData));
        }

        try
        {
            // 3. 파일 메타데이터 수집
            var fileInfo = new FileInfo(normalized);
            long fileSizeBytes = fileInfo.Length;
            string sha256 = ComputeSha256(normalized);

            // 4. Authenticode 디지털 서명 검증 및 서명 주체 추출
            var (isSigned, sigStatus) = VerifyAuthenticode(normalized);
            string signerSubject = ExtractSignerSubject(normalized);

            // 5. 시스템 파일 경로 위장(Masquerading T1036.005) 검증
            string fileName = Path.GetFileName(normalized);
            bool isPathMasqueraded = CheckPathMasqueraded(normalized, fileName);

            // 6. 바이트 스트림 분석: Shannon 엔트로피 및 PE 매직 바이트
            var (entropy, isDisguisedExe) = InspectBytes(normalized);

            // 7. 복합 이상 징후 점수(AnomalyScore 0 ~ 100) 산출
            int anomalyScore = 0;
            var reasons = new List<string>();

            if (isPathMasqueraded)
            {
                anomalyScore += 50;
                reasons.Add("시스템 핵심 바이너리 파일명이 비인가 디렉터리에 위치함 (T1036.005 Masquerading)");

                // 시스템 경로 위장 파일이 유효한 Microsoft 서명이 없으면 즉시 크리티컬 100점
                bool isTrustedMicrosoft = isSigned && signerSubject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
                if (!isTrustedMicrosoft)
                {
                    anomalyScore += 50;
                    reasons.Add("비인가 경로에 위장된 시스템 바이너리에 공인 Microsoft Authenticode 서명이 결여됨 (High Critical Threat)");
                }
            }

            if (isDisguisedExe)
            {
                anomalyScore += 40;
                reasons.Add("비실행형 확장자(.dat/.jpg/.txt 등) 내부에 은닉된 PE 실행 바이너리(MZ/PE 헤더) 포착");
            }

            if (entropy > 7.2)
            {
                anomalyScore += 25;
                reasons.Add($"고밀도 암호화 또는 패킹 의심 (Shannon Entropy: {entropy:F2} > 7.20)");
            }

            if (!isSigned && !isPathMasqueraded)
            {
                // 일반 바이너리 무서명 시 경미 가산
                anomalyScore += 10;
                reasons.Add($"디지털 서명 미보유 ({sigStatus})");
            }

            anomalyScore = Math.Clamp(anomalyScore, 0, 100);
            string diagnosticReason = reasons.Count > 0 ? string.Join("; ", reasons) : "정상 정규 파일 (특이 이상 징후 없음)";

            var entry = new SimulatedFileEntry(
                Exists: true,
                FileSizeBytes: fileSizeBytes,
                Sha256: sha256,
                Entropy: entropy,
                IsSigned: isSigned,
                SignerSubject: signerSubject,
                SignatureStatus: sigStatus,
                IsPathMasqueraded: isPathMasqueraded,
                IsDisguisedExecutable: isDisguisedExe,
                AnomalyScore: anomalyScore,
                DiagnosticReason: diagnosticReason
            );

            return Task.FromResult(FormatResult(entry, normalized, isSimulated: false));
        }
        catch (Exception ex)
        {
            return Task.FromResult(new ToolResult(false, $"[FileInspectionTool 치명적 예외] 파일 검증 중 오류 발생: {ex.Message}"));
        }
    }

    #endregion

    #region 보조 헬퍼 메서드

    private static string ExtractFilePath(Dictionary<string, object> parameters)
    {
        string[] candidateKeys = { "filePath", "file_path", "path", "targetPath", "target_path" };
        foreach (var key in candidateKeys)
        {
            if (parameters.TryGetValue(key, out var val) && val != null)
            {
                if (val is JsonElement je && je.ValueKind == JsonValueKind.String)
                {
                    return je.GetString() ?? string.Empty;
                }
                return val.ToString() ?? string.Empty;
            }
        }

        // 키를 대소문자 무시하고 순회
        foreach (var kvp in parameters)
        {
            if (string.Equals(kvp.Key, "filePath", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(kvp.Key, "path", StringComparison.OrdinalIgnoreCase))
            {
                if (kvp.Value is JsonElement je && je.ValueKind == JsonValueKind.String)
                {
                    return je.GetString() ?? string.Empty;
                }
                return kvp.Value?.ToString() ?? string.Empty;
            }
        }

        return string.Empty;
    }

    private static string NormalizePath(string path)
    {
        try
        {
            // 따옴표 및 공백 트림
            string trimmed = path.Trim(' ', '\t', '"', '\'');
            if (string.IsNullOrWhiteSpace(trimmed)) return string.Empty;
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return path.Trim();
        }
    }

    private static string ComputeSha256(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(fs);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ExtractSignerSubject(string filePath)
    {
#pragma warning disable SYSLIB0057
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
            return cert.Subject;
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }
        catch
        {
            return string.Empty;
        }
#pragma warning restore SYSLIB0057
    }

    private static readonly HashSet<string> System32Binaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "runtimebroker.exe", "taskhostw.exe", "spoolsv.exe"
    };

    private static bool CheckPathMasqueraded(string normalizedPath, string fileName)
    {
        if (System32Binaries.Contains(fileName))
        {
            string dir = Path.GetDirectoryName(normalizedPath)?.TrimEnd('\\', '/') ?? string.Empty;
            string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System).TrimEnd('\\', '/');
            string sysWow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86).TrimEnd('\\', '/');

            // System32 또는 SysWOW64 정규 디렉터리에 위치하지 않으면 위장으로 적발
            if (!string.Equals(dir, sys32, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(dir, sysWow64, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        else if (string.Equals(fileName, "explorer.exe", StringComparison.OrdinalIgnoreCase))
        {
            string dir = Path.GetDirectoryName(normalizedPath)?.TrimEnd('\\', '/') ?? string.Empty;
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\', '/');
            if (!string.Equals(dir, winDir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static (double Entropy, bool IsDisguised) InspectBytes(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length == 0) return (0.0, false); // 0바이트 파일 Division by Zero 방어

            int bytesToRead = (int)Math.Min(fs.Length, 1024 * 1024);
            byte[] buffer = new byte[bytesToRead];
            int bytesRead = fs.Read(buffer, 0, bytesToRead);
            if (bytesRead == 0) return (0.0, false);

            int[] counts = new int[256];
            for (int i = 0; i < bytesRead; i++) counts[buffer[i]]++;
            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = (double)counts[i] / bytesRead;
                    entropy -= p * Math.Log2(p);
                }
            }

            bool isDisguised = false;
            if (bytesRead >= 64 && buffer[0] == 0x4D && buffer[1] == 0x5A) // 'M', 'Z'
            {
                int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                if (e_lfanew > 0 && e_lfanew + 4 <= bytesRead)
                {
                    if (buffer[e_lfanew] == 0x50 && buffer[e_lfanew + 1] == 0x45 &&
                        buffer[e_lfanew + 2] == 0x00 && buffer[e_lfanew + 3] == 0x00) // "PE\0\0"
                    {
                        string ext = Path.GetExtension(filePath).ToLowerInvariant();
                        if (ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".cpl")
                        {
                            isDisguised = true;
                        }
                    }
                }
            }

            return (Math.Round(entropy, 4), isDisguised);
        }
        catch
        {
            return (0.0, false);
        }
    }

    private static ToolResult FormatResult(SimulatedFileEntry entry, string normalizedPath, bool isSimulated)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[FileInspectionTool 포렌식 검증 결과{(isSimulated ? " (Clean-Room Simulation)" : "")}]");
        sb.AppendLine($"• 대상 경로: {normalizedPath}");
        sb.AppendLine($"• 파일 존재: {(entry.Exists ? "O (Exists)" : "X (NotFound)")} (크기: {entry.FileSizeBytes:N0} 바이트)");
        if (!string.IsNullOrEmpty(entry.Sha256)) sb.AppendLine($"• SHA-256: {entry.Sha256}");
        sb.AppendLine($"• 디지털 서명(Authenticode): {(entry.IsSigned ? "VALID SIGNED" : "UNSIGNED / INVALID")} ({entry.SignatureStatus})");
        if (!string.IsNullOrEmpty(entry.SignerSubject)) sb.AppendLine($"• 서명 주체: {entry.SignerSubject}");
        sb.AppendLine($"• 시스템 경로 위장(Masquerading T1036.005): {(entry.IsPathMasqueraded ? "CRITICAL DETECTED" : "Normal")}");
        sb.AppendLine($"• 확장자 위장(Disguised PE Executable): {(entry.IsDisguisedExecutable ? "DETECTED (MZ/PE in Non-Exe)" : "Normal")}");
        sb.AppendLine($"• Shannon 엔트로피: {entry.Entropy:F4} {(entry.Entropy > 7.2 ? "(HIGH: Packed/Encrypted)" : "(Normal)")}");
        sb.AppendLine($"• 복합 이상 징후 위험도: {entry.AnomalyScore}/100");
        sb.AppendLine($"• 정밀 진단 소견: {entry.DiagnosticReason}");

        var data = new Dictionary<string, object>
        {
            ["Exists"] = entry.Exists,
            ["NormalizedPath"] = normalizedPath,
            ["FileSizeBytes"] = entry.FileSizeBytes,
            ["Sha256"] = entry.Sha256,
            ["Entropy"] = entry.Entropy,
            ["IsSigned"] = entry.IsSigned,
            ["SignerSubject"] = entry.SignerSubject,
            ["SignatureStatus"] = entry.SignatureStatus,
            ["IsPathMasqueraded"] = entry.IsPathMasqueraded,
            ["IsDisguisedExecutable"] = entry.IsDisguisedExecutable,
            ["AnomalyScore"] = entry.AnomalyScore,
            ["DiagnosticReason"] = entry.DiagnosticReason
        };

        return new ToolResult(Success: true, Output: sb.ToString().TrimEnd(), Data: data);
    }

    #endregion
}
