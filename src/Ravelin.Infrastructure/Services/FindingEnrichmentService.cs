using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Enriches open findings with CISA KEV and FIRST EPSS intelligence and re-baselines their
/// risk-adjusted SLA deadline, so an actively-exploited vulnerability gets a tighter deadline than
/// its CVSS severity alone would give. Creates its own scope so it can run from a background timer
/// or an HTTP request. Best-effort: a feed outage leaves existing enrichment untouched and never
/// throws.
/// </summary>
public sealed class FindingEnrichmentService(
    IServiceScopeFactory scopeFactory,
    IVulnerabilityIntelligence intelligence,
    IOptions<VulnIntelOptions> options,
    ILogger<FindingEnrichmentService> logger) : IFindingEnricher
{
    public async Task<EnrichmentResult> EnrichAsync(CancellationToken ct = default)
    {
        var opts = options.Value;
        var risk = opts.ToRiskPolicy();

        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();

        var findings = await db.Findings
            .Where(f => f.Status == FindingStatus.Open)
            .ToListAsync(ct);
        if (findings.Count == 0)
        {
            return default;
        }

        // Map each open finding to its CVE (KEV/EPSS are CVE-keyed; GHSA-only findings are skipped).
        var cveOf = new Dictionary<Guid, string>();
        foreach (var f in findings)
        {
            if (CveIdentifier.TryExtract(f.VulnerabilityId, out var cve))
            {
                cveOf[f.Id] = cve;
            }
        }
        if (cveOf.Count == 0)
        {
            return new EnrichmentResult(findings.Count, 0, 0, 0);
        }

        var distinctCves = cveOf.Values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        // Null = feed unavailable this pass → leave that dimension of existing data as-is.
        var kev = await intelligence.GetKnownExploitedAsync(ct);
        var epss = await intelligence.GetEpssScoresAsync(distinctCves, ct);
        if (kev is null && epss is null)
        {
            return new EnrichmentResult(findings.Count, findings.Count(f => f.IsKnownExploited), 0, 0);
        }

        var slaDays = await db.SlaPolicies.ToDictionaryAsync(p => p.Severity, p => p.RemediationDays, ct);
        var now = DateTimeOffset.UtcNow;
        int updated = 0, escalated = 0;

        foreach (var f in findings)
        {
            if (!cveOf.TryGetValue(f.Id, out var cve))
            {
                continue;
            }

            var changed = false;

            if (kev is not null)
            {
                var isKev = kev.TryGetValue(cve, out var addedDate);
                if (f.IsKnownExploited != isKev)
                {
                    f.IsKnownExploited = isKev;
                    f.KevDateAdded = isKev ? addedDate : null;
                    changed = true;
                }
            }

            if (epss is not null && epss.TryGetValue(cve, out var score))
            {
                if (f.EpssScore != score.Score || f.EpssPercentile != score.Percentile)
                {
                    f.EpssScore = score.Score;
                    f.EpssPercentile = score.Percentile;
                    changed = true;
                }
            }

            if (!changed)
            {
                continue;
            }

            f.EnrichedAt = now;

            // Re-baseline the deadline from first-detection with the refreshed risk signals.
            var newDue = SlaEvaluator.ComputeDueDate(
                f.FirstDetectedAt, f.Severity, slaDays, risk, f.IsKnownExploited, f.EpssScore);
            var severityOnly = SlaEvaluator.ComputeDueDate(f.FirstDetectedAt, f.Severity, slaDays);
            if (newDue is DateTimeOffset nd && (severityOnly is null || nd < severityOnly))
            {
                escalated++;
            }
            f.SlaDueAt = newDue;
            updated++;
        }

        if (updated > 0)
        {
            await db.SaveChangesAsync(ct);
            var knownExploited = findings.Count(f => f.IsKnownExploited);
            logger.LogInformation(
                "Enrichment: {Scanned} open, {Kev} actively exploited, {Escalated} SLA-escalated, {Updated} updated",
                findings.Count, knownExploited, escalated, updated);

            var audit = scope.ServiceProvider.GetRequiredService<AuditService>();
            await audit.RecordAsync("system", "finding.enrich", null,
                $"{knownExploited} KEV, {escalated} escalated, {updated} updated");
        }

        return new EnrichmentResult(findings.Count, findings.Count(f => f.IsKnownExploited), escalated, updated);
    }
}
