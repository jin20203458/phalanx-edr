using System.IO;
using Phalanx.Cockpit.Storage;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class ForensicArchiveManagerMigrationTests
{
    [Fact]
    public void ForensicArchiveManager_MigratesLegacyGeminiCloudAndNullRecords_ToCloudLlm()
    {
        using var memStream = new MemoryStream();

        // 1. 레거시 레코드 강제 주입 (원시 LiteDatabase 사용)
        using (var rawDb = new LiteDB.LiteDatabase(memStream))
        {
            var col = rawDb.GetCollection<IncidentRecord>("incidents");
            col.Insert(new IncidentRecord
            {
                IncidentId = "INC-LEGACY-001",
                InvestigationEngine = "GEMINI_CLOUD",
                SummaryTitle = "Legacy Gemini Incident"
            });
            col.Insert(new IncidentRecord
            {
                IncidentId = "INC-LEGACY-002",
                InvestigationEngine = null!,
                SummaryTitle = "Legacy Null Incident"
            });
            col.Insert(new IncidentRecord
            {
                IncidentId = "INC-MODERN-003",
                InvestigationEngine = "OFFLINE_LOCAL",
                SummaryTitle = "Modern Incident"
            });
        }

        // 2. 스트림 포인터 리셋 (중요: 재오픈을 위해 0으로 되감기)
        memStream.Position = 0;

        // 3. ForensicArchiveManager 시작 (마이그레이션 자동 트리거)
        using (var manager = ForensicArchiveManager.CreateFromStreamForTesting(memStream))
        {
            var legacyGemini = manager.GetIncident("INC-LEGACY-001");
            var legacyNull = manager.GetIncident("INC-LEGACY-002");
            var modern = manager.GetIncident("INC-MODERN-003");

            Assert.NotNull(legacyGemini);
            Assert.Equal("CLOUD_LLM", legacyGemini.InvestigationEngine);

            Assert.NotNull(legacyNull);
            Assert.Equal("CLOUD_LLM", legacyNull.InvestigationEngine);

            Assert.NotNull(modern);
            Assert.Equal("OFFLINE_LOCAL", modern.InvestigationEngine);
        }
    }
}
