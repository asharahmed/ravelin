namespace Ravelin.Domain.Entities;

/// <summary>
/// A codebase/repository whose pipeline pushes vulnerability scans. Findings are grouped
/// under a project. <see cref="Key"/> is the stable identifier a pipeline uses when it
/// pushes results (it does not change if the display <see cref="Name"/> changes).
/// </summary>
public class Project
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Stable, URL-safe identifier used by pipelines (e.g. "payments-api"). Unique.</summary>
    public required string Key { get; set; }

    /// <summary>Human-friendly display name.</summary>
    public required string Name { get; set; }

    /// <summary>Optional source repository URL.</summary>
    public string? RepositoryUrl { get; set; }

    /// <summary>Optional outbound webhook (generic JSON, or Slack if it's a Slack incoming URL)
    /// that receives new breach / due-soon alerts for this project.</summary>
    public string? WebhookUrl { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Archived projects are hidden from the default dashboard/lists but keep their
    /// data and stop accruing new alerts. Reversible.</summary>
    public bool IsArchived { get; set; }

    public DateTimeOffset? ArchivedAt { get; set; }

    // Navigation
    public ICollection<Scan> Scans { get; set; } = new List<Scan>();
    public ICollection<Finding> Findings { get; set; } = new List<Finding>();
}
