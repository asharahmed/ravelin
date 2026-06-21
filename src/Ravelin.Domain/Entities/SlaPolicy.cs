namespace Ravelin.Domain.Entities;

using Ravelin.Domain.Enums;

/// <summary>
/// Organization-level remediation SLA for a given severity: how many days an open finding
/// of that severity may remain unresolved before it breaches. One row per severity (v1 is
/// single-org; per-project overrides are a possible later enhancement).
/// </summary>
public class SlaPolicy
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Severity this policy applies to. Unique.</summary>
    public required Severity Severity { get; set; }

    /// <summary>Allowed days to remediate before an open finding breaches its SLA.</summary>
    public required int RemediationDays { get; set; }

    /// <summary>Industry-standard starting defaults (admin-configurable in Stage 5).</summary>
    public static IReadOnlyList<SlaPolicy> Defaults { get; } = new[]
    {
        new SlaPolicy { Severity = Severity.Critical, RemediationDays = 7 },
        new SlaPolicy { Severity = Severity.High, RemediationDays = 30 },
        new SlaPolicy { Severity = Severity.Medium, RemediationDays = 90 },
        new SlaPolicy { Severity = Severity.Low, RemediationDays = 180 },
    };
}
