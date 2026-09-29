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
        _traces.EnsureIndex(x => x.IncidentId);
    }

    /// <summary>
    /// 단위 테스트용 메모리 기반 인스턴스 팩토리
    /// </summary>
    public static ForensicArchiveManager CreateInMemory()
    {
        var memStream = new MemoryStream();
        return new ForensicArchiveManager(memStream);
    }

    private ForensicArchiveManager(MemoryStream stream)
    {
        _db = new LiteDatabase(stream);
        _incidents = _db.GetCollection<IncidentRecord>("incidents");
        _traces = _db.GetCollection<ReActTraceRecord>("react_traces");

        _incidents.EnsureIndex(x => x.IncidentId, unique: true);
        _traces.EnsureIndex(x => x.IncidentId);
    }

    public void SaveIncident(IncidentRecord incident, IEnumerable<ReActTraceRecord>? traces = null)
    {
        _incidents.Upsert(incident);

        if (traces != null)
        {
            _traces.InsertBulk(traces);
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

    public void Dispose()
    {
        _db.Dispose();
    }
}
