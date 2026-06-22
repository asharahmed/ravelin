namespace Ravelin.Domain.Entities;

/// <summary>
/// An immutable audit-trail record: who did what, when. Written for security-relevant actions
/// (auth, RBAC changes, API-key lifecycle, SLA-policy edits, triage) so a boutique can answer
/// "who changed this?" during a client engagement or audit.
/// </summary>
public class AuditEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTimeOffset At { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Who performed the action — a user email, or "system".</summary>
    public required string Actor { get; set; }

    /// <summary>Dotted action key, e.g. "project.create", "apikey.revoke", "user.role".</summary>
    public required string Action { get; set; }

    /// <summary>The affected resource (project key, user email, finding id, …), if any.</summary>
    public string? Target { get; set; }

    /// <summary>Human-readable detail, e.g. "Viewer -> Admin" or "status: FalsePositive".</summary>
    public string? Detail { get; set; }
}
