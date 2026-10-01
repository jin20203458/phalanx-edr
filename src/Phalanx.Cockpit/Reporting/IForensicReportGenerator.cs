namespace Phalanx.Cockpit.Reporting;

using Phalanx.Cockpit.ViewModels;

/// <summary>
/// EDR 침해사고 수사 결과 및 ReAct 추론 흔적을 기반으로 하는 포렌식 리포트 생성기 인터페이스
/// </summary>
public interface IForensicReportGenerator
{
    /// <summary>
    /// 인시던트 뷰모델을 순수 인메모리 A4 PDF 바이트 배열로 렌더링합니다.
    /// UI 스레드나 디스크 I/O 없이 고속으로 동작하며 단위 테스트에서 직접 검증 가능합니다.
    /// </summary>
    byte[] GenerateReportBytes(IncidentItemViewModel incident);

    /// <summary>
    /// 인시던트 보고서를 지정된 출력 디렉터리에 PDF 파일로 저장하고 절대 경로를 반환합니다.
    /// </summary>
    string ExportReportToFile(IncidentItemViewModel incident, string outputDirectory);

    /// <summary>
    /// 인시던트 보고서를 지정된 절대 파일 경로에 PDF 파일로 저장하고 절대 경로를 반환합니다.
    /// 대상 상위 디렉터리가 없을 경우 자동으로 생성합니다.
    /// </summary>
    string ExportReportToFilePath(IncidentItemViewModel incident, string targetFilePath);
}
