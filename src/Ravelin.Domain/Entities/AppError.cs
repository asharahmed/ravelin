namespace Ravelin.Domain.Entities;

using Ravelin.Domain.Enums;

/// <summary>
/// A deduplicated, captured application error — an unhandled exception caught at the request
/// boundary — grouped by <see cref="Fingerprint"/> so the same fault recorded a thousand times
/// is one row with an occurrence count. This is the unit a tracked issue (and eventually an
/// auto-fix attempt) is created from. All captured free text is scrubbed of secret-shaped
/// values before it is stored (capturing a bug must never leak a credential).
/// </summary>
public class AppError
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Stable identity = hash(exception type + normalized top stack frames). Unique, so
    /// the same fault always maps to this one row regardless of how often it fires.</summary>
    public required string Fingerprint { get; set; }

    public required string ExceptionType { get; set; }

    /// <summary>Exception message, scrubbed of secret-shaped values.</summary>
    public string? Message { get; set; }

    /// <summary>Normalized top stack frames (no file paths or line numbers) — the repro context
    /// an issue/agent works from. Scrubbed.</summary>
    public string? StackExcerpt { get; set; }

    /// <summary>Where it surfaced. Path only — never the query string, body, or headers.</summary>
    public string? RequestMethod { get; set; }
    public string? RequestPath { get; set; }

    /// <summary>Correlation id of the most recent occurrence, to cross-reference request logs.</summary>
    public string? LastCorrelationId { get; set; }

    public AppErrorStatus Status { get; set; } = AppErrorStatus.Open;

    /// <summary>How many times this fault has been captured.</summary>
    public int Occurrences { get; set; } = 1;

    public DateTimeOffset FirstSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeenAt { get; set; } = DateTimeOffset.UtcNow;

    // --- Issue-tracker link (the seam for capture -> Linear; set once synced) ---
    /// <summary>Identifier of the tracked issue (e.g. Linear "RAV-123"), once synced.</summary>
    public string? IssueIdentifier { get; set; }
    public string? IssueUrl { get; set; }
    public DateTimeOffset? IssueSyncedAt { get; set; }
}
