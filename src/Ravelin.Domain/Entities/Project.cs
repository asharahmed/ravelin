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

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Navigation
    public ICollection<Scan> Scans { get; set; } = new List<Scan>();
    public ICollection<Finding> Findings { get; set; } = new List<Finding>();
}
