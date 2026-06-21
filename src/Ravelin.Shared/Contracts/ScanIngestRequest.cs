namespace Ravelin.Shared.Contracts;

/// <summary>
/// Payload a pipeline POSTs to ingest one scan's results for a project. Tool-agnostic
/// normalized shape; severity is a string ("Critical"/"High"/"Medium"/"Low"/"Unknown",
/// case-insensitive) so the contract is language-neutral.
/// </summary>
public record ScanIngestRequest
{
    public required string Tool { get; init; }
    public string? ToolVersion { get; init; }
    public required IReadOnlyList<IngestFinding> Findings { get; init; }
}

public record IngestFinding
{
    public required string VulnerabilityId { get; init; }
    public required string PackageName { get; init; }
    public required string PackageVersion { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public string? Severity { get; init; }
    public double? CvssScore { get; init; }
    public string? FixedVersion { get; init; }
}

/// <summary>Summary of what a scan ingestion changed.</summary>
public record ScanIngestResponse
{
    public required Guid ScanId { get; init; }
    public required int Created { get; init; }
    public required int Reopened { get; init; }
    public required int Resolved { get; init; }
    public required int Seen { get; init; }
    public required int OpenTotal { get; init; }
}
