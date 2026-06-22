namespace Ravelin.Shared.Contracts;

/// <summary>A raised SLA alert (due-soon or breached) for a finding.</summary>
public record AlertDto
{
    public required Guid Id { get; init; }
    public required string ProjectKey { get; init; }
    public required string ProjectName { get; init; }
    public required string VulnerabilityId { get; init; }
    public required string PackageName { get; init; }
    public required string Severity { get; init; }

    /// <summary>DueSoon or Breached.</summary>
    public required string State { get; init; }

    public required DateTimeOffset RaisedAt { get; init; }
    public DateTimeOffset? AcknowledgedAt { get; init; }
    public string? AcknowledgedBy { get; init; }

    /// <summary>Whole days past the deadline now (positive when overdue), null when not breached.</summary>
    public int? DaysOverdue { get; init; }
}

/// <summary>Result of a re-evaluation pass.</summary>
public record ReEvaluateSummaryDto
{
    public required int Scanned { get; init; }
    public required int NewBreached { get; init; }
    public required int NewDueSoon { get; init; }
    public required int Notified { get; init; }
}

public record SetWebhookRequest
{
    public string? Url { get; init; }
}

public record TestWebhookResponse
{
    public required bool Success { get; init; }
    public int? StatusCode { get; init; }
    public string? Error { get; init; }
}
