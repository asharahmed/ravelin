namespace Ravelin.Domain.Services;

using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;

/// <summary>Outcome of reconciling one scan against a project's existing findings.</summary>
public sealed class ReconciliationResult
{
    public List<Finding> Created { get; } = [];
    public List<Finding> Reopened { get; } = [];
    public List<Finding> Resolved { get; } = [];

    /// <summary>Findings still present and already open/triaged (touched, not state-changed).</summary>
    public List<Finding> Seen { get; } = [];
}

/// <summary>
/// Pure reconciliation logic: given a project's current findings and the findings reported
/// by a new scan, decide what is new, what re-appeared, what should auto-resolve, and update
/// last-seen / descriptive fields. No database or I/O — fully unit-testable.
///
/// Rules:
///  - New identity            -> create Open finding, FirstDetected=now, SLA due from policy.
///  - Existing Open identity   -> refresh fields + LastSeen; keep SLA due (from FirstDetected).
///  - Existing Resolved identity reappears -> reopen (clear ResolvedAt, recompute SLA due).
///  - Existing FalsePositive / AcceptedRisk reappears -> respect triage; only touch LastSeen.
///  - Existing Open identity absent from this scan -> auto-resolve (ResolvedAt=now).
///    (Triaged findings are never auto-resolved.)
/// </summary>
public static class ScanReconciler
{
    public static ReconciliationResult Reconcile(
        Guid projectId,
        IReadOnlyCollection<Finding> existingFindings,
        IReadOnlyCollection<IncomingFinding> incoming,
        IReadOnlyDictionary<Severity, int> slaDays,
        DateTimeOffset now)
    {
        var result = new ReconciliationResult();
        // Identity keys are compared case-insensitively: NuGet package ids are officially
        // case-insensitive and Azure SQL's default collation is too, so "Newtonsoft.Json" and
        // "newtonsoft.json" are the SAME finding. Matching them here (rather than inserting a
        // second row) avoids a duplicate INSERT that would violate the dedup unique index.
        var existingByKey = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in existingFindings)
        {
            existingByKey[IdentityKey(f)] = f;
        }
        var incomingKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var inc in incoming)
        {
            // Collapse duplicate identities within a single payload.
            if (!incomingKeys.Add(inc.IdentityKey))
            {
                continue;
            }

            if (existingByKey.TryGetValue(inc.IdentityKey, out var finding))
            {
                finding.LastSeenAt = now;
                finding.Severity = inc.Severity;
                finding.Title = inc.Title;
                finding.Description = inc.Description;
                finding.CvssScore = inc.CvssScore;
                finding.FixedVersion = inc.FixedVersion;

                switch (finding.Status)
                {
                    case FindingStatus.Resolved:
                        finding.Status = FindingStatus.Open;
                        finding.ResolvedAt = null;
                        finding.SlaDueAt = ComputeDue(finding.FirstDetectedAt, inc.Severity, slaDays);
                        result.Reopened.Add(finding);
                        break;

                    case FindingStatus.Open:
                        finding.SlaDueAt = ComputeDue(finding.FirstDetectedAt, inc.Severity, slaDays);
                        result.Seen.Add(finding);
                        break;

                    default: // FalsePositive / AcceptedRisk — respect the triage decision.
                        result.Seen.Add(finding);
                        break;
                }
            }
            else
            {
                result.Created.Add(new Finding
                {
                    ProjectId = projectId,
                    VulnerabilityId = inc.VulnerabilityId,
                    PackageName = inc.PackageName,
                    PackageVersion = inc.PackageVersion,
                    Title = inc.Title,
                    Description = inc.Description,
                    Severity = inc.Severity,
                    CvssScore = inc.CvssScore,
                    FixedVersion = inc.FixedVersion,
                    Status = FindingStatus.Open,
                    FirstDetectedAt = now,
                    LastSeenAt = now,
                    SlaDueAt = ComputeDue(now, inc.Severity, slaDays),
                });
            }
        }

        // Auto-resolve open findings that were not reported by this scan — but NOT when the scan
        // reported nothing at all. An empty report is far more likely a broken/errored scanner
        // step (which still emits structurally-valid empty JSON) than a genuine "everything is
        // fixed" event; silently resolving every open finding on it would report false 100%
        // compliance — the worst failure mode for an accountability tool. An empty scan is
        // therefore treated as "no new information": nothing is auto-resolved. Findings that are
        // genuinely remediated drop out of a subsequent NON-empty scan and resolve normally.
        if (incomingKeys.Count > 0)
        {
            foreach (var finding in existingFindings)
            {
                if (finding.Status == FindingStatus.Open && !incomingKeys.Contains(IdentityKey(finding)))
                {
                    finding.Status = FindingStatus.Resolved;
                    finding.ResolvedAt = now;
                    result.Resolved.Add(finding);
                }
            }
        }

        return result;
    }

    private static string IdentityKey(Finding f) =>
        $"{f.VulnerabilityId}|{f.PackageName}|{f.PackageVersion}";

    private static DateTimeOffset? ComputeDue(
        DateTimeOffset from, Severity severity, IReadOnlyDictionary<Severity, int> slaDays) =>
        SlaEvaluator.ComputeDueDate(from, severity, slaDays);
}
