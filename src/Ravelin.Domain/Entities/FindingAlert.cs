namespace Ravelin.Domain.Entities;

using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

/// <summary>
/// A recorded SLA event for a finding — it entered <see cref="SlaState.DueSoon"/> or
/// <see cref="SlaState.Breached"/>. There is at most one row per (finding, state), so
/// re-evaluation is idempotent; the set of rows for a finding is its aging timeline.
/// Analysts acknowledge alerts; the dispatch timestamp records the outbound notification.
/// </summary>
public class FindingAlert
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required Guid FindingId { get; set; }

    /// <summary>Denormalised for fast per-project filtering and the timeline (no FK/cascade).</summary>
    public required Guid ProjectId { get; set; }

    /// <summary>Severity snapshot when the alert was raised.</summary>
    public required Severity Severity { get; set; }

    /// <summary>The state that triggered this alert: DueSoon or Breached.</summary>
    public required SlaState State { get; set; }

    public DateTimeOffset RaisedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? AcknowledgedAt { get; set; }
    public string? AcknowledgedBy { get; set; }

    /// <summary>When the outbound webhook/Slack notification was dispatched (null if none/failed).</summary>
    public DateTimeOffset? NotifiedAt { get; set; }
}
