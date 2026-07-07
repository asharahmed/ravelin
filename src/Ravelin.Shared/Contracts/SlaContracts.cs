namespace Ravelin.Shared.Contracts;

/// <summary>Triage action on a finding (Analyst/Admin). <see cref="Status"/> is one of
/// Open / Resolved / FalsePositive / AcceptedRisk; <see cref="Note"/> is required when
/// suppressing (FalsePositive / AcceptedRisk).</summary>
public record TriageFindingRequest
{
    public required string Status { get; init; }
    public string? Note { get; init; }
}

/// <summary>One severity's remediation SLA (days), as read or set by an admin.</summary>
public record SlaPolicyDto
{
    public required string Severity { get; init; }
    public required int RemediationDays { get; init; }
}

/// <summary>Replace the remediation-day SLA for one or more severities (admin).</summary>
public record UpdateSlaPoliciesRequest
{
    public required IReadOnlyList<SlaPolicyDto> Policies { get; init; }
}

/// <summary>The risk-adjusted SLA policy: how KEV / high-EPSS exploitation signals tighten a
/// finding's remediation deadline beyond its severity SLA.</summary>
public record RiskPolicyDto
{
    /// <summary>Whether KEV/EPSS enrichment is active on this instance.</summary>
    public required bool Enabled { get; init; }

    /// <summary>Deadline (days) applied to a CISA-KEV (actively-exploited) finding.</summary>
    public required int KevRemediationDays { get; init; }

    /// <summary>Deadline (days) applied to a finding whose EPSS meets the escalation threshold.</summary>
    public required int HighEpssRemediationDays { get; init; }

    /// <summary>EPSS probability (0–1) at/above which the high-EPSS deadline applies.</summary>
    public required double EpssEscalationThreshold { get; init; }
}

/// <summary>Result of an enrichment pass (refresh KEV/EPSS + re-baseline risk SLA).</summary>
public record EnrichmentSummaryDto
{
    public required int Scanned { get; init; }
    public required int KnownExploited { get; init; }
    public required int Escalated { get; init; }
    public required int Updated { get; init; }
}

/// <summary>Per-project SLA posture snapshot (open findings only; suppressed/resolved excluded).</summary>
public record SlaSummaryDto
{
    public required string ProjectKey { get; init; }
    public required int Open { get; init; }
    public required int OnTrack { get; init; }
    public required int DueSoon { get; init; }
    public required int Breached { get; init; }

    /// <summary>Share of open findings currently within SLA (0–100); 100 when there are none.</summary>
    public required double CompliancePercent { get; init; }
}
