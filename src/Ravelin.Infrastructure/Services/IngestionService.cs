using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Ravelin.Domain.Services;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Orchestrates ingestion of one scan: loads the project's findings and SLA policies, runs
/// the pure <see cref="ScanReconciler"/>, persists changes, and records the scan.
/// </summary>
public class IngestionService(RavelinDbContext db)
{
    public async Task<(Scan Scan, ReconciliationResult Result, int OpenTotal)> IngestAsync(
        Guid projectId,
        string tool,
        string? toolVersion,
        IReadOnlyCollection<IncomingFinding> incoming,
        CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;

        var slaDays = await db.SlaPolicies
            .ToDictionaryAsync(p => p.Severity, p => p.RemediationDays, ct);

        var existing = await db.Findings
            .Where(f => f.ProjectId == projectId)
            .ToListAsync(ct);

        // Tracked entities are mutated in place by the reconciler; only new ones need adding.
        var result = ScanReconciler.Reconcile(projectId, existing, incoming, slaDays, now);
        db.Findings.AddRange(result.Created);

        var scan = new Scan
        {
            ProjectId = projectId,
            Tool = tool,
            ToolVersion = toolVersion,
            Source = ScanSource.PipelinePush,
            IngestedAt = now,
            ReportedFindingCount = incoming.Count,
        };
        db.Scans.Add(scan);

        await db.SaveChangesAsync(ct);

        var openTotal = await db.Findings
            .CountAsync(f => f.ProjectId == projectId && f.Status == FindingStatus.Open, ct);

        return (scan, result, openTotal);
    }
}
