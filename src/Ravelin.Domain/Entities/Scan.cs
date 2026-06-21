namespace Ravelin.Domain.Entities;

using Ravelin.Domain.Enums;

/// <summary>
/// A single ingestion event: one set of scan results pushed for a project at a point in
/// time. Scans are the basis for reconciliation (dedup + auto-resolve) — comparing the
/// latest scan's findings against what is currently open for the project.
/// </summary>
public class Scan
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required Guid ProjectId { get; set; }

    /// <summary>Scanner that produced the results (e.g. "Trivy", "Dependabot").</summary>
    public required string Tool { get; set; }

    public string? ToolVersion { get; set; }

    public ScanSource Source { get; set; } = ScanSource.PipelinePush;

    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Number of findings reported in this scan (denormalized for quick display).</summary>
    public int ReportedFindingCount { get; set; }

    // Navigation
    public Project? Project { get; set; }
}
