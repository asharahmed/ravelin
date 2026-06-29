namespace Ravelin.Domain.Enums;

/// <summary>Lifecycle of a captured application error (an unhandled exception), distinct from a
/// security <see cref="Entities.Finding"/>. A recurrence reopens a resolved error.</summary>
public enum AppErrorStatus
{
    Open = 0,
    Resolved = 1,
    Muted = 2,
}
