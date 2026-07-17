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

    /// <summary>Expiry for an <see cref="FindingStatus.AcceptedRisk"/> decision. When set and past,
    /// the finding is automatically reopened by the re-evaluator so accepted risks don't linger
    /// forever. Null means the acceptance does not expire.</summary>
    public DateTimeOffset? AcceptedRiskUntil { get; set; }

    // --- Exploitation intelligence (enrichment; keyed by CVE) ---
    /// <summary>True when this finding's CVE is in the CISA Known Exploited Vulnerabilities
    /// catalog — the strongest "fix this now" signal. Drives risk-adjusted SLA and prioritization.</summary>
    public bool IsKnownExploited { get; set; }

    /// <summary>When the CVE was added to the CISA KEV catalog, if known.</summary>
    public DateTimeOffset? KevDateAdded { get; set; }

    /// <summary>EPSS score (0–1): predicted probability the CVE is exploited in the next 30 days.</summary>
    public double? EpssScore { get; set; }

    /// <summary>EPSS percentile (0–1): where this CVE ranks against all scored CVEs.</summary>
    public double? EpssPercentile { get; set; }

    /// <summary>When exploitation intelligence was last refreshed for this finding.</summary>
    public DateTimeOffset? EnrichedAt { get; set; }

    /// <summary>
    /// SQL <c>rowversion</c> concurrency token. Guards against silent last-writer-wins when an
    /// ingestion pass and a manual triage mutate the same finding concurrently (e.g. an analyst's
    /// AcceptedRisk being clobbered back to Open). EF throws <see cref="Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException"/>
    /// on a conflicting update; callers reload and reconcile.
    /// </summary>
    public byte[]? RowVersion { get; set; }

    // Navigation
    public Project? Project { get; set; }
}
