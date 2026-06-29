using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Outbound seam to an issue tracker (e.g. Linear). A newly-captured <see cref="AppError"/> can
/// be turned into a tracked issue here. The default implementation is a no-op; a real,
/// config-gated implementation is added in the capture→Linear delivery stage, so wiring it up
/// requires no change to the capture path.
/// </summary>
public interface IIssueTracker
{
    /// <summary>Creates/links a tracked issue for a newly-captured error. Returns the issue
    /// identity, or null if issue tracking is not configured.</summary>
    Task<TrackedIssue?> TryCreateIssueAsync(AppError error, CancellationToken ct = default);
}

/// <summary>The external issue created for an error (e.g. Linear "RAV-123" + its URL).</summary>
public sealed record TrackedIssue(string Identifier, string Url);

/// <summary>Default no-op tracker: captures stay local until a real tracker is configured.</summary>
public sealed class NullIssueTracker : IIssueTracker
{
    public Task<TrackedIssue?> TryCreateIssueAsync(AppError error, CancellationToken ct = default)
        => Task.FromResult<TrackedIssue?>(null);
}
