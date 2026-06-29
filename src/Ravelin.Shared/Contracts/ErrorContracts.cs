namespace Ravelin.Shared.Contracts;

/// <summary>A captured application error (deduplicated unhandled exception), as surfaced to
/// admins. Free-text fields are already secret-scrubbed at capture time.</summary>
public sealed record AppErrorDto
{
    public Guid Id { get; init; }
    public string Fingerprint { get; init; } = "";
    public string ExceptionType { get; init; } = "";
    public string? Message { get; init; }
    public string? RequestMethod { get; init; }
    public string? RequestPath { get; init; }
    public string Status { get; init; } = "";
    public int Occurrences { get; init; }
    public DateTimeOffset FirstSeenAt { get; init; }
    public DateTimeOffset LastSeenAt { get; init; }

    /// <summary>Linked tracked-issue identity (e.g. Linear "RAV-123"), if synced.</summary>
    public string? IssueIdentifier { get; init; }
    public string? IssueUrl { get; init; }
}
