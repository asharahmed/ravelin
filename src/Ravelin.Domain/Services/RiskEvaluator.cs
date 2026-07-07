namespace Ravelin.Domain.Services;

using Ravelin.Domain.Enums;

/// <summary>
/// Risk-adjusted SLA policy: how much a real-world-exploitation signal tightens a finding's
/// remediation deadline, on top of the severity-based SLA. Both overrides "tighten only" — they
/// can pull a deadline in, never push it out.
/// </summary>
/// <param name="KevRemediationDays">Deadline (days from detection) for a finding in the CISA
/// Known Exploited Vulnerabilities catalog. Null disables the KEV override.</param>
/// <param name="HighEpssRemediationDays">Deadline for a finding whose EPSS score meets
/// <paramref name="EpssEscalationThreshold"/>. Null disables the EPSS override.</param>
/// <param name="EpssEscalationThreshold">EPSS probability (0–1) at or above which the high-EPSS
/// override applies.</param>
public readonly record struct RiskSlaPolicy(
    int? KevRemediationDays,
    int? HighEpssRemediationDays,
    double EpssEscalationThreshold)
{
    /// <summary>No risk adjustment — severity policy alone governs the deadline.</summary>
    public static readonly RiskSlaPolicy None = new(null, null, 1.0);
}

/// <summary>
/// Pure prioritization logic. Severity (CVSS-derived) is a weak triage signal on its own; real
/// programs prioritize by exploitation in the wild. This ranks and labels a finding by combining
/// severity with two exploitation signals — CISA KEV (known actively exploited) and EPSS
/// (predicted exploitation probability). No I/O; fully unit-testable. The enrichment of findings
/// with those signals is done elsewhere (infrastructure); this only interprets them.
/// </summary>
public static class RiskEvaluator
{
    /// <summary>Default EPSS probability at/above which a finding is treated as high-likelihood.</summary>
    public const double DefaultEpssEscalationThreshold = 0.5;

    /// <summary>
    /// A single urgency score, higher = more urgent, for sorting findings by real risk. KEV
    /// dominates every non-KEV finding; within a tier, higher severity wins, then higher EPSS.
    /// </summary>
    public static double Rank(Severity severity, bool isKnownExploited, double? epss) =>
        (isKnownExploited ? 1_000d : 0d)
        + (int)severity * 100d
        + Math.Clamp(epss ?? 0d, 0d, 1d) * 10d;

    /// <summary>Short label for the strongest active-exploitation signal on a finding, or null
    /// when neither applies. Drives the UI risk badge.</summary>
    public static string? Label(bool isKnownExploited, double? epss, double epssThreshold)
    {
        if (isKnownExploited) return "Actively exploited";
        if (epss is double e && e >= epssThreshold) return "Likely exploited";
        return null;
    }
}
