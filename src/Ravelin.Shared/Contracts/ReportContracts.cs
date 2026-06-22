namespace Ravelin.Shared.Contracts;

/// <summary>A breached (overdue) open finding, with the detail an auditor needs in a report.</summary>
public record ReportFindingDto
{
    public required string ProjectKey { get; init; }
    public required string ProjectName { get; init; }
    public required string VulnerabilityId { get; init; }
    public required string PackageName { get; init; }
    public required string PackageVersion { get; init; }
    public required string Severity { get; init; }
    public required int DaysOverdue { get; init; }
    public DateTimeOffset? SlaDueAt { get; init; }
}
