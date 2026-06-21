namespace Ravelin.Domain.Entities;

using Ravelin.Domain.Enums;

/// <summary>
/// A normalized dependency vulnerability for a project. A finding's identity for
/// deduplication across scans is (<see cref="ProjectId"/>, <see cref="VulnerabilityId"/>,
/// <see cref="PackageName"/>, <see cref="PackageVersion"/>) — enforced by a unique index.
/// SLA fields are populated/evaluated by the Stage 5 SLA engine.
/// </summary>
public class Finding
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required Guid ProjectId { get; set; }

    // --- Dedup identity ---
    /// <summary>Advisory identifier, e.g. "CVE-2023-1234" or a GHSA id.</summary>
    public required string VulnerabilityId { get; set; }

    /// <summary>Affected package/component name.</summary>
    public required string PackageName { get; set; }

    /// <summary>Installed (affected) version of the package.</summary>
    public required string PackageVersion { get; set; }

    // --- Descriptive ---
    public required string Title { get; set; }
    public string? Description { get; set; }
    public Severity Severity { get; set; } = Severity.Unknown;
    public double? CvssScore { get; set; }

    /// <summary>Version that remediates the vulnerability, if known.</summary>
    public string? FixedVersion { get; set; }

    // --- Lifecycle / triage ---
    public FindingStatus Status { get; set; } = FindingStatus.Open;
    public DateTimeOffset FirstDetectedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ResolvedAt { get; set; }

    /// <summary>
    /// SLA remediation deadline, derived from severity policy at detection time.
    /// Null until the SLA engine assigns it (Stage 5).
    /// </summary>
    public DateTimeOffset? SlaDueAt { get; set; }

    /// <summary>Free-text triage note (e.g. justification for accepted-risk/false-positive).</summary>
    public string? TriageNote { get; set; }

    // Navigation
    public Project? Project { get; set; }
}
