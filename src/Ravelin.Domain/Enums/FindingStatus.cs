namespace Ravelin.Domain.Enums;

/// <summary>
/// Lifecycle/triage state of a finding. Only <see cref="Open"/> findings count toward
/// SLA breaches; <see cref="FalsePositive"/> and <see cref="AcceptedRisk"/> are excluded
/// from compliance metrics (see Stage 5 SLA engine).
/// </summary>
public enum FindingStatus
{
    /// <summary>Active and unresolved — subject to SLA tracking.</summary>
    Open = 0,

    /// <summary>No longer present in the latest scan (auto-resolved) or manually fixed.</summary>
    Resolved = 1,

    /// <summary>Triaged as not a real issue — excluded from metrics.</summary>
    FalsePositive = 2,

    /// <summary>Acknowledged and accepted (often time-boxed) — excluded from breach counts.</summary>
    AcceptedRisk = 3,
}
