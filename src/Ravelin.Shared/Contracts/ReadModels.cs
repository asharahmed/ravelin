namespace Ravelin.Shared.Contracts;

public record ProjectDto
{
    public required Guid Id { get; init; }
    public required string Key { get; init; }
    public required string Name { get; init; }
    public string? RepositoryUrl { get; init; }
    public required int OpenFindings { get; init; }
}

public record FindingDto
{
    public required Guid Id { get; init; }
    public required string VulnerabilityId { get; init; }
    public required string PackageName { get; init; }
    public required string PackageVersion { get; init; }
    public required string Title { get; init; }
    public required string Severity { get; init; }
    public required string Status { get; init; }
    public double? CvssScore { get; init; }
    public string? FixedVersion { get; init; }
    public required DateTimeOffset FirstDetectedAt { get; init; }
    public DateTimeOffset? ResolvedAt { get; init; }
    public DateTimeOffset? SlaDueAt { get; init; }
    public required bool SlaBreached { get; init; }
}
