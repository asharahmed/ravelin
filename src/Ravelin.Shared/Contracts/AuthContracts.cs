namespace Ravelin.Shared.Contracts;

public record LoginRequest
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
