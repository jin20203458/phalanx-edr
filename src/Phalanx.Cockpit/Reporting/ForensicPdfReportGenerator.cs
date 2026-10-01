namespace Phalanx.Cockpit.Reporting;

using System;
using System.IO;
using QuestPDF.Fluent;
using QuestPDF.Infrastructure;
using Phalanx.Cockpit.ViewModels;

/// <summary>
/// QuestPDF 기반의 포렌식 리포트 생성기 구현체
/// UI 스레드 및 파일 다이얼로그와 완전히 분리되어 순수 인메모리 바이트 생성과 안전한 디스크 파일 출력을 담당합니다.
/// </summary>
public class ForensicPdfReportGenerator : IForensicReportGenerator
{
    private static readonly object LicenseLock = new();
    private static bool _isLicenseConfigured;

    static ForensicPdfReportGenerator()
    {
        EnsureLicenseConfigured();
    }

    /// <summary>
    /// 단위 테스트나 헤드리스 환경 등 Main() 진입점을 거치지 않는 환경에서도
    /// QuestPDF LicenseException이 발생하지 않도록 스레드 안전하게 라이선스를 구성합니다.
    /// </summary>
    public static void EnsureLicenseConfigured()
    {
        if (_isLicenseConfigured) return;
        lock (LicenseLock)
        {
            if (!_isLicenseConfigured)
            {
                QuestPDF.Settings.License = LicenseType.Community;
                QuestPDF.Settings.UseSystemFonts = true;
                QuestPDF.Settings.ThrowOnMissingFontFamilies = false;
                _isLicenseConfigured = true;
            }
        }
    }

    /// <inheritdoc />
    public byte[] GenerateReportBytes(IncidentItemViewModel incident)
    {
        ArgumentNullException.ThrowIfNull(incident);
        EnsureLicenseConfigured();

        var document = new ForensicPdfReportDocument(incident);
        return document.GeneratePdf();
    }

    /// <inheritdoc />
    public string ExportReportToFile(IncidentItemViewModel incident, string outputDirectory)
    {
        ArgumentNullException.ThrowIfNull(incident);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);

        if (!Directory.Exists(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        string safeIncidentId = string.IsNullOrWhiteSpace(incident.IncidentId)
            ? $"INC-{DateTime.UtcNow:yyyyMMdd-HHmmss}"
            : string.Join("_", incident.IncidentId.Split(Path.GetInvalidFileNameChars()));

        string fileName = $"Phalanx_Forensic_Report_{safeIncidentId}_{incident.Timestamp:yyyyMMdd_HHmmss}.pdf";
        string fullPath = Path.Combine(outputDirectory, fileName);

        byte[] pdfBytes = GenerateReportBytes(incident);
        File.WriteAllBytes(fullPath, pdfBytes);

        return fullPath;
    }
}
