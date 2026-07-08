using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Writes an append-only <see cref="PostureSnapshot"/> once per UTC day, capturing the
/// organisation's compliance posture so historical numbers stay fixed even as live deadlines pass.
/// Idempotent (one row per day, enforced by a unique index) and safe across replicas — a losing
/// concurrent write simply no-ops. Creates its own scope so it can run from a timer or a request.
/// </summary>
public sealed class PostureSnapshotService(
    IServiceScopeFactory scopeFactory, TimeProvider clock, ILogger<PostureSnapshotService> logger)
{
    /// <summary>Ensures today's snapshot exists. Returns true if one was written now.</summary>
    public async Task<bool> EnsureSnapshotAsync(CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();

        var now = clock.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        if (await db.PostureSnapshots.AnyAsync(s => s.SnapshotDate == today, ct))
        {
            return false; // already captured today — the day's record is immutable
        }

        var activeIds = await db.Projects.Where(p => !p.IsArchived).Select(p => p.Id).ToListAsync(ct);
        var open = await db.Findings
            .Where(f => f.Status == FindingStatus.Open && activeIds.Contains(f.ProjectId))
            .Select(f => new { f.Severity, f.SlaDueAt, f.IsKnownExploited })
            .ToListAsync(ct);

        SlaState StateOf(DateTimeOffset? dueAt) =>
            SlaEvaluator.Evaluate(FindingStatus.Open, dueAt, now, SlaEvaluator.DefaultDueSoonWindow).State;

        var total = open.Count;
        var breached = open.Count(f => StateOf(f.SlaDueAt) == SlaState.Breached);
        var dueSoon = open.Count(f => StateOf(f.SlaDueAt) == SlaState.DueSoon);

        db.PostureSnapshots.Add(new PostureSnapshot
        {
            SnapshotDate = today,
            TakenAt = now,
            ProjectCount = activeIds.Count,
            TotalOpen = total,
            Breached = breached,
            DueSoon = dueSoon,
            OnTrack = total - breached - dueSoon,
            CompliancePercent = total == 0 ? 100 : Math.Round((double)(total - breached) / total * 100, 1),
            ActivelyExploited = open.Count(f => f.IsKnownExploited),
            Critical = open.Count(f => f.Severity == Severity.Critical),
            High = open.Count(f => f.Severity == Severity.High),
            Medium = open.Count(f => f.Severity == Severity.Medium),
            Low = open.Count(f => f.Severity == Severity.Low),
            Unknown = open.Count(f => f.Severity == Severity.Unknown),
        });

        try
        {
            await db.SaveChangesAsync(ct);
            logger.LogInformation("Posture snapshot written for {Date}: {Compliance}% ({Open} open)",
                today, total == 0 ? 100 : Math.Round((double)(total - breached) / total * 100, 1), total);
            return true;
        }
        catch (DbUpdateException)
        {
            // Another replica wrote today's snapshot first (unique index) — that's fine.
            return false;
        }
    }
}
