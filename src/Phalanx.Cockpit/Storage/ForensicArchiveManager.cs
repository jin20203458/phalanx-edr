using System.IO;
using LiteDB;

namespace Phalanx.Cockpit.Storage;

/// <summary>
/// LiteDB 5.0 기반 침해사고 포렌식 아카이브 영속화 관리자.
/// 스레드 락 없이 안전한 임베디드 데이터베이스 작업을 수행합니다.
/// </summary>
public class ForensicArchiveManager : IDisposable
{
    private readonly LiteDatabase _db;
    private readonly ILiteCollection<IncidentRecord> _incidents;
    private readonly ILiteCollection<ReActTraceRecord> _traces;

    public ForensicArchiveManager(string dbPath = "phalanx_forensics.db")
    {
        // ConnectionString with Shared mode for thread-safe access
        var connectionString = new ConnectionString(dbPath)
        {
            Connection = ConnectionType.Shared
        };
        _db = new LiteDatabase(connectionString);

        _incidents = _db.GetCollection<IncidentRecord>("incidents");
        _traces = _db.GetCollection<ReActTraceRecord>("react_traces");

        _incidents.EnsureIndex(x => x.IncidentId, unique: true);
        _incidents.EnsureIndex(x => x.Timestamp);
        _traces.EnsureIndex(x => x.IncidentId);

        MigrateLegacyEngines();
    }

    /// <summary>
    /// 단위 테스트용 메모리 기반 인스턴스 팩토리
    /// </summary>
    public static ForensicArchiveManager CreateInMemory()
    {
        var memStream = new MemoryStream();
        return new ForensicArchiveManager(memStream);
    }

    /// <summary>
    /// 단위 테스트용 스트림 기반 인스턴스 팩토리 (사전 주입된 데이터의 마이그레이션 검증 전용)
    /// </summary>
    public static ForensicArchiveManager CreateFromStreamForTesting(MemoryStream stream)
    {
        return new ForensicArchiveManager(stream);
    }

    private ForensicArchiveManager(MemoryStream stream)
    {
        _db = new LiteDatabase(stream);
        _incidents = _db.GetCollection<IncidentRecord>("incidents");
        _traces = _db.GetCollection<ReActTraceRecord>("react_traces");

        _incidents.EnsureIndex(x => x.IncidentId, unique: true);
        _incidents.EnsureIndex(x => x.Timestamp);
        _traces.EnsureIndex(x => x.IncidentId);

        MigrateLegacyEngines();
    }

    public void SaveIncident(IncidentRecord incident, IEnumerable<ReActTraceRecord>? traces = null)
    {
        _db.BeginTrans();
        try
        {
            _incidents.Upsert(incident);

            if (traces != null)
            {
                _traces.InsertBulk(traces);
            }

            _db.Commit();
        }
        catch
        {
            _db.Rollback();
            throw;
        }
    }

    public IncidentRecord? GetIncident(string incidentId)
    {
        return _incidents.FindOne(x => x.IncidentId == incidentId);
    }

    public List<IncidentRecord> GetAllIncidents()
    {
        return _incidents.Query().OrderByDescending(x => x.Timestamp).ToList();
    }

    public List<ReActTraceRecord> GetTracesForIncident(string incidentId)
    {
        return _traces.Query().Where(x => x.IncidentId == incidentId).OrderBy(x => x.StepNumber).ToList();
    }

    /// <summary>
    /// 보관된 모든 침해사고 레코드 및 ReAct 추론 흔적을 원자적으로 삭제합니다.
    /// </summary>
    public int ClearAllIncidents()
    {
        _db.BeginTrans();
        try
        {
            int deleted = _incidents.DeleteAll();
            _traces.DeleteAll();
            _db.Commit();
            return deleted;
        }
        catch
        {
            _db.Rollback();
            throw;
        }
    }

    /// <summary>
    /// 과거 Phase 2/3 레코드 중 GEMINI_CLOUD, null 또는 빈 문자열로 저장된 레거시 엔진명을 CLOUD_LLM으로 영구 갱신합니다.
    /// </summary>
    private void MigrateLegacyEngines()
    {
        try
        {
            var allIncidents = _incidents.FindAll().ToList();
            var legacyRecords = allIncidents
                .Where(x => string.IsNullOrWhiteSpace(x.InvestigationEngine) || x.InvestigationEngine == "GEMINI_CLOUD")
                .ToList();

            if (legacyRecords.Count > 0)
            {
                foreach (var rec in legacyRecords)
                {
                    rec.InvestigationEngine = "CLOUD_LLM";
                    _incidents.Update(rec);
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine($"[ForensicArchiveManager] 레거시 엔진 마이그레이션 실패: {ex.Message}");
        }
    }

    public void Dispose()
    {
        _db.Dispose();
    }
}
