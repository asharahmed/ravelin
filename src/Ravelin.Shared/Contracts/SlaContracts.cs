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
