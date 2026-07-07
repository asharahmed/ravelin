namespace Ravelin.Domain.Services;

using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;

/// <summary>SLA standing of a finding at a point in time.</summary>
public enum SlaState
{
    /// <summary>Not subject to SLA: resolved or triaged (false-positive / accepted-risk),
    /// or no due date assigned.</summary>
    NotApplicable = 0,

    /// <summary>Open and comfortably within its remediation window.</summary>
    OnTrack = 1,

    /// <summary>Open and approaching its deadline (within the due-soon window).</summary>
    DueSoon = 2,

    /// <summary>Open and past its remediation deadline.</summary>
    Breached = 3,
}

/// <summary>Result of evaluating a finding's SLA. <see cref="DaysRemaining"/> is whole days
/// until the deadline (negative when overdue); null when SLA does not apply.</summary>
public readonly record struct SlaEvaluation(SlaState State, int? DaysRemaining)
{
    public bool IsBreached => State == SlaState.Breached;
}

/// <summary>
/// Pure SLA math: turns a finding's stored deadline (<see cref="Finding.SlaDueAt"/>) into a
/// time-relative state. The deadline itself is a snapshot computed at detection
/// (<see cref="ComputeDueDate"/>); breach/due-soon are evaluated on read because they depend
/// on the current time. No database or I/O — fully unit-testable.
/// </summary>
public static class SlaEvaluator
{
    /// <summary>How close to the deadline an open finding is flagged <see cref="SlaState.DueSoon"/>.</summary>
    public static readonly TimeSpan DefaultDueSoonWindow = TimeSpan.FromDays(7);

    public static SlaEvaluation Evaluate(Finding finding, DateTimeOffset now) =>
        Evaluate(finding.Status, finding.SlaDueAt, now, DefaultDueSoonWindow);

    public static SlaEvaluation Evaluate(
        FindingStatus status, DateTimeOffset? dueAt, DateTimeOffset now, TimeSpan dueSoonWindow)
    {
        // Only open findings with a deadline are tracked; resolved/triaged are excluded
        // from SLA metrics by design (see FindingStatus docs).
        if (status != FindingStatus.Open || dueAt is null)
        {
            return new SlaEvaluation(SlaState.NotApplicable, null);
        }

        var remaining = dueAt.Value - now;
        var days = (int)Math.Floor(remaining.TotalDays);

        if (remaining <= TimeSpan.Zero)
        {
            return new SlaEvaluation(SlaState.Breached, days); // <= 0: deadline reached/passed
        }

        return remaining <= dueSoonWindow
            ? new SlaEvaluation(SlaState.DueSoon, days)
            : new SlaEvaluation(SlaState.OnTrack, days);
    }

    /// <summary>Remediation deadline for a finding first seen at <paramref name="from"/> with the
    /// given severity, per the org SLA policy. Null when no policy covers that severity.</summary>
    public static DateTimeOffset? ComputeDueDate(
        DateTimeOffset from, Severity severity, IReadOnlyDictionary<Severity, int> slaDays) =>
        slaDays.TryGetValue(severity, out var days) ? from.AddDays(days) : null;

    /// <summary>
    /// Remediation deadline adjusted for real-world exploitation risk. Starts from the severity
    /// SLA, then lets the KEV and/or high-EPSS overrides pull the deadline in (never out). An
    /// exploited finding with an unmapped severity (no baseline) still gets the risk deadline, so
    /// "actively exploited" is never left untracked.
    /// </summary>
    public static DateTimeOffset? ComputeDueDate(
        DateTimeOffset from, Severity severity, IReadOnlyDictionary<Severity, int> slaDays,
        RiskSlaPolicy risk, bool isKnownExploited, double? epss)
    {
        var baseline = ComputeDueDate(from, severity, slaDays);

        int? riskDays = null;
        if (isKnownExploited && risk.KevRemediationDays is int kev)
        {
            riskDays = kev;
        }
        if (epss is double e && e >= risk.EpssEscalationThreshold && risk.HighEpssRemediationDays is int hi)
        {
            riskDays = riskDays is int current ? Math.Min(current, hi) : hi;
        }

        if (riskDays is not int days)
        {
            return baseline;
        }

        var riskDue = from.AddDays(days);
        return baseline is DateTimeOffset b && b < riskDue ? b : riskDue;
    }
}
