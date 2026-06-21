namespace Ravelin.Domain.Ingestion;

using Ravelin.Domain.Enums;

/// <summary>
/// A single normalized vulnerability as reported by a scan — the tool-agnostic shape the
/// reconciler works with. Adapters (Trivy, Dependabot, …) convert tool output into this.
/// Carries only what a scan knows; identity/lifecycle live on <see cref="Entities.Finding"/>.
/// </summary>
public record IncomingFinding
{
    public required string VulnerabilityId { get; init; }
    public required string PackageName { get; init; }
    public required string PackageVersion { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public Severity Severity { get; init; } = Severity.Unknown;
    public double? CvssScore { get; init; }
    public string? FixedVersion { get; init; }

    /// <summary>Dedup identity within a project — matches <see cref="Entities.Finding"/>'s.</summary>
    public string IdentityKey => $"{VulnerabilityId}|{PackageName}|{PackageVersion}";
}
