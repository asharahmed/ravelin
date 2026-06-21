namespace Ravelin.Domain.Entities;

/// <summary>
/// An API key that authorizes a pipeline to push scans for a specific project (least
/// privilege — scoped to one project, ingestion only). The raw key is shown to the user
/// exactly once at creation; only its hash is stored. <see cref="KeyPrefix"/> is a short,
/// non-secret fragment kept for identification in listings.
/// </summary>
public class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required Guid ProjectId { get; set; }

    /// <summary>Human label for the key (e.g. "payments-api Azure pipeline").</summary>
    public required string Name { get; set; }

    /// <summary>SHA-256 hex digest of the raw key. The raw key is never stored.</summary>
    public required string KeyHash { get; set; }

    /// <summary>Non-secret leading fragment (e.g. "rvln_ab12") for identifying the key.</summary>
    public required string KeyPrefix { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public bool IsActive => RevokedAt is null;

    // Navigation
    public Project? Project { get; set; }
}
