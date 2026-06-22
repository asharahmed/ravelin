namespace Ravelin.Shared.Contracts;

public record LoginRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
}

/// <summary>Self-service registration. The server always assigns the read-only Viewer
/// role; analyst/admin access is granted out-of-band by an administrator.</summary>
public record RegisterRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
}

public record LoginResponse
{
    public required string Token { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required string Email { get; init; }
    public required IReadOnlyList<string> Roles { get; init; }
}
