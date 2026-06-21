namespace Ravelin.Domain.Services;

using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;

/// <summary>Outcome of a triage attempt — success, or a human-readable reason it was rejected.</summary>
public readonly record struct TriageOutcome(bool Success, string? Error)
{
    public static TriageOutcome Ok() => new(true, null);
    public static TriageOutcome Fail(string error) => new(false, error);
}

/// <summary>
/// Pure triage transitions a human (Analyst/Admin) may apply to a finding, with the audit
/// rules enforced: a justification note is required when suppressing a finding
/// (false-positive / accepted-risk). Mutates the finding in place on success. No I/O.
/// </summary>
public static class FindingTriage
{
    /// <summary>Statuses a human may set via triage. (Auto-resolution to <see cref="FindingStatus.Resolved"/>
    /// also happens during scan reconciliation; here it allows a manual fix.)</summary>
    public static readonly IReadOnlySet<FindingStatus> AllowedTargets = new HashSet<FindingStatus>
    {
        FindingStatus.Open,           // reopen
        FindingStatus.Resolved,       // manually mark fixed
        FindingStatus.FalsePositive,  // suppress (note required)
        FindingStatus.AcceptedRisk,   // accept (note required)
    };

    public static TriageOutcome Apply(
        Finding finding, FindingStatus target, string? note, DateTimeOffset now)
    {
        if (!AllowedTargets.Contains(target))
        {
            return TriageOutcome.Fail($"'{target}' is not a valid triage status.");
        }

        var requiresNote = target is FindingStatus.FalsePositive or FindingStatus.AcceptedRisk;
        if (requiresNote && string.IsNullOrWhiteSpace(note))
        {
            return TriageOutcome.Fail(
                "A justification note is required to mark a finding false-positive or accepted-risk.");
        }

        finding.Status = target;
        if (!string.IsNullOrWhiteSpace(note))
        {
            finding.TriageNote = note.Trim();
        }

        // ResolvedAt tracks when a finding was actually fixed; reopening clears it. Suppressed
        // findings (FP / accepted-risk) are excluded from metrics regardless, so leave it as-is.
        finding.ResolvedAt = target switch
        {
            FindingStatus.Resolved => now,
            FindingStatus.Open => null,
            _ => finding.ResolvedAt,
        };

        return TriageOutcome.Ok();
    }
}
