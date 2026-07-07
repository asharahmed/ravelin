using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

namespace Ravelin.Infrastructure.Services;

public readonly record struct ReEvaluateResult(int Scanned, int NewBreached, int NewDueSoon, int Notified);

/// <summary>
/// Re-evaluates every open finding's SLA standing and records a <see cref="FindingAlert"/> the
/// first time a finding crosses into DueSoon or Breached (idempotent — never duplicates an
/// existing (finding, state) alert). New alerts are dispatched to each project's webhook.
/// Creates its own scope so it can run from a background timer or an HTTP request.
/// </summary>
public sealed class SlaReEvaluator(
    IServiceScopeFactory scopeFactory, NotificationService notifications,
    IFindingEnricher enricher, ILogger<SlaReEvaluator> logger)
{
    public async Task<ReEvaluateResult> ReEvaluateAsync(CancellationToken ct = default)
    {
        // Refresh exploitation intelligence first so newly-KEV findings have their tightened
        // deadline in place before breach detection runs. Best-effort (inert when disabled); a
        // failure here must never stop SLA re-evaluation.
        try
        {
            await enricher.EnrichAsync(ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Enrichment step failed; continuing with SLA re-evaluation.");
        }

        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<AuditService>();
        var now = DateTimeOffset.UtcNow;

        var findings = await db.Findings
            .Where(f => f.Status == FindingStatus.Open && !f.Project.IsArchived)
            .Select(f => new
            {
                f.Id, f.ProjectId, f.Severity, f.SlaDueAt, f.VulnerabilityId,
                ProjectName = f.Project.Name, f.Project.WebhookUrl,
            })
            .ToListAsync(ct);

        // Existing (finding, state) pairs → idempotency.
        var existing = (await db.FindingAlerts
                .Select(a => new { a.FindingId, a.State })
                .ToListAsync(ct))
            .Select(e => (e.FindingId, e.State))
            .ToHashSet();

        var newAlerts = new List<FindingAlert>();
        var notifyLines = new List<(Guid projectId, string webhook, string projectName, NotificationService.AlertLine line)>();
        int newBreached = 0, newDueSoon = 0;

        foreach (var f in findings)
        {
            var eval = SlaEvaluator.Evaluate(FindingStatus.Open, f.SlaDueAt, now, SlaEvaluator.DefaultDueSoonWindow);
            if (eval.State is not (SlaState.DueSoon or SlaState.Breached)) continue;
            if (existing.Contains((f.Id, eval.State))) continue;

            newAlerts.Add(new FindingAlert
            {
                FindingId = f.Id, ProjectId = f.ProjectId, Severity = f.Severity, State = eval.State, RaisedAt = now,
            });
            if (eval.State == SlaState.Breached) newBreached++; else newDueSoon++;

            if (!string.IsNullOrWhiteSpace(f.WebhookUrl))
            {
                var daysOverdue = eval.State == SlaState.Breached && eval.DaysRemaining is int dr ? Math.Abs(dr) : (int?)null;
                notifyLines.Add((f.ProjectId, f.WebhookUrl!, f.ProjectName,
                    new NotificationService.AlertLine(f.VulnerabilityId, f.Severity.ToString(), eval.State.ToString(), daysOverdue)));
            }
        }

        if (newAlerts.Count > 0)
        {
            db.FindingAlerts.AddRange(newAlerts);
            await db.SaveChangesAsync(ct);
        }

        var notified = 0;
        foreach (var grp in notifyLines.GroupBy(x => x.projectId))
        {
            var first = grp.First();
            var (ok, _, _) = await notifications.SendAsync(first.webhook, first.projectName, grp.Select(x => x.line).ToList(), ct);
            if (!ok) continue;
            notified++;
            foreach (var a in newAlerts.Where(a => a.ProjectId == grp.Key)) a.NotifiedAt = now;
        }
        if (notified > 0) await db.SaveChangesAsync(ct);

        if (newAlerts.Count > 0)
        {
            logger.LogInformation("SLA re-eval: {Breached} breached, {DueSoon} due-soon, {Notified} notified",
                newBreached, newDueSoon, notified);
            await audit.RecordAsync("system", "alert.reeval", null,
                $"{newBreached} breached, {newDueSoon} due-soon, {notified} notified");
        }

        return new ReEvaluateResult(findings.Count, newBreached, newDueSoon, notified);
    }
}
