namespace Ravelin.Shared.Contracts;

/// <summary>Create a project (admin / bootstrap).</summary>
public record CreateProjectRequest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public string? RepositoryUrl { get; init; }
}

/// <summary>Issue an API key for a project (admin / bootstrap).</summary>
public record CreateApiKeyRequest
{
    public required string Name { get; init; }
}

/// <summary>
/// Returned once when a key is created — <see cref="Key"/> is the only time the raw key is
/// ever shown. Store it now; only its hash is persisted.
/// </summary>
public record CreateApiKeyResponse
{
    public required Guid Id { get; init; }
    public required string Name { get; init; }
    public required string Key { get; init; }
    public required string Prefix { get; init; }
}
