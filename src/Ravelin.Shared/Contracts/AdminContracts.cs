namespace Ravelin.Shared.Contracts;

/// <summary>Create a project (admin / bootstrap).</summary>
public record CreateProjectRequest
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public string? RepositoryUrl { get; init; }

    /// <summary>When true, any authenticated user can read the project (used for demo projects).
    /// Defaults to false — real projects require explicit membership.</summary>
    public bool IsPublic { get; init; }
}

/// <summary>Set whether any authenticated user can read a project.</summary>
public record SetProjectVisibilityRequest
{
    public required bool IsPublic { get; init; }
}

/// <summary>Grant a user membership of a project (admin), by email.</summary>
public record GrantMembershipRequest
{
    public required string Email { get; init; }
}

/// <summary>A member of a project.</summary>
public record ProjectMemberDto
{
    public required string UserId { get; init; }
    public required string Email { get; init; }
    public required string Role { get; init; }
    public required DateTimeOffset GrantedAt { get; init; }
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

/// <summary>An API key in a listing — never includes the secret, only its prefix and lifecycle.</summary>
public record ApiKeyDto
{
    public required Guid Id { get; init; }
    public required string Name { get; init; }
    public required string Prefix { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? LastUsedAt { get; init; }
    public DateTimeOffset? RevokedAt { get; init; }
    public required bool IsActive { get; init; }
}

/// <summary>A human user account and its single role (Admin / Analyst / Viewer).</summary>
public record UserDto
{
    public required string Id { get; init; }
    public required string Email { get; init; }
    public required string Role { get; init; }
}

/// <summary>Set a user's role (admin). Replaces any existing role.</summary>
public record SetUserRoleRequest
{
    public required string Role { get; init; }
}

/// <summary>One entry in the audit trail.</summary>
public record AuditEventDto
{
    public required DateTimeOffset At { get; init; }
    public required string Actor { get; init; }
    public required string Action { get; init; }
    public string? Target { get; init; }
    public string? Detail { get; init; }
}
