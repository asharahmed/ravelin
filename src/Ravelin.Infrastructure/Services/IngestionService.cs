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
public class IngestionService(RavelinDbContext db, TimeProvider clock)
{
    // Two concurrent scans of the same project each load `existing` before the other commits, so
    // both can queue an INSERT for the same brand-new finding (dedup unique-index violation) or
    // update the same tracked row (rowversion conflict). Rather than fail the pipeline with a 500,
    // reload and re-reconcile against the now-committed state. One retry is enough for two racers;
    // the small extra covers a burst.
    private const int MaxConcurrencyRetries = 3;

    public async Task<(Scan Scan, ReconciliationResult Result, int OpenTotal)> IngestAsync(
        Guid projectId,
        string tool,
        string? toolVersion,
        IReadOnlyCollection<IncomingFinding> incoming,
        CancellationToken ct = default)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await IngestOnceAsync(projectId, tool, toolVersion, incoming, ct);
            }
            catch (DbUpdateException) when (attempt < MaxConcurrencyRetries)
            {
                // Discard the failed change-tracker state and start the read-modify-write over so
                // the reload in IngestOnceAsync sees the row the racing scan just committed. Covers
                // both the dedup-index collision and the rowversion conflict (DbUpdateConcurrencyException
                // is a subclass of DbUpdateException).
                db.ChangeTracker.Clear();
            }
        }
    }

    private async Task<(Scan Scan, ReconciliationResult Result, int OpenTotal)> IngestOnceAsync(
        Guid projectId,
        string tool,
        string? toolVersion,
        IReadOnlyCollection<IncomingFinding> incoming,
        CancellationToken ct)
    {
        var now = clock.GetUtcNow();

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
