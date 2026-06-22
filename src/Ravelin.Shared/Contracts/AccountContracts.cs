namespace Ravelin.Shared.Contracts;

/// <summary>The signed-in user's own profile.</summary>
public record AccountDto
{
    public required string Email { get; init; }
    public required IReadOnlyList<string> Roles { get; init; }
}

public record ChangePasswordRequest
{
    public required string CurrentPassword { get; init; }
    public required string NewPassword { get; init; }
}

/// <summary>Returned once when an admin resets a user's password. There is no email, so the
/// admin hands the temporary password to the user out-of-band; the user signs in and changes it.</summary>
public record AdminResetPasswordResponse
{
    public required string Email { get; init; }
    public required string TemporaryPassword { get; init; }
}
