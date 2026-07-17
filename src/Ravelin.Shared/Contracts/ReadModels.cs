namespace Ravelin.Shared.Contracts;

public record ProjectDto
{
    public required Guid Id { get; init; }
    public required string Key { get; init; }
    public required string Name { get; init; }
    public string? RepositoryUrl { get; init; }
    public required int OpenFindings { get; init; }
    public bool IsArchived { get; init; }
    public bool IsPublic { get; init; }
    public string? WebhookUrl { get; init; }
}

public record FindingDto
{
    public required Guid Id { get; init; }
    public required string VulnerabilityId { get; init; }
    public required string PackageName { get; init; }
    public required string PackageVersion { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public required string Severity { get; init; }
    public required string Status { get; init; }
    public double? CvssScore { get; init; }
    public string? FixedVersion { get; init; }
    public required DateTimeOffset FirstDetectedAt { get; init; }
    public DateTimeOffset? ResolvedAt { get; init; }
    public DateTimeOffset? SlaDueAt { get; init; }
    public required bool SlaBreached { get; init; }

    /// <summary>SLA standing: NotApplicable / OnTrack / DueSoon / Breached.</summary>
    public required string SlaState { get; init; }

    /// <summary>Whole days until the SLA deadline; negative when overdue, null when N/A.</summary>
    public int? DaysToSla { get; init; }

    // --- Exploitation intelligence ---
    /// <summary>True when the CVE is in the CISA Known Exploited Vulnerabilities catalog.</summary>
    public bool IsKnownExploited { get; init; }

    /// <summary>When the CVE was added to CISA KEV, if known.</summary>
    public DateTimeOffset? KevDateAdded { get; init; }

    /// <summary>EPSS score (0–1): predicted 30-day exploitation probability.</summary>
    public double? EpssScore { get; init; }

    /// <summary>EPSS percentile (0–1) versus all scored CVEs.</summary>
    public double? EpssPercentile { get; init; }

    /// <summary>Short risk badge ("Actively exploited" / "Likely exploited"), or null.</summary>
    public string? RiskLabel { get; init; }
}
