using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ravelin.Domain.Diagnostics;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Records captured application errors in their own DB scope, deduplicated by fingerprint: the
/// first occurrence inserts a row (and offers it to the issue tracker), later identical faults
/// just bump Occurrences/LastSeenAt. Best-effort and isolated — like the audit log, a capture
/// failure must never disturb the request that was already failing.
/// </summary>
public sealed class AppErrorService(
    IServiceScopeFactory scopeFactory, IIssueTracker issueTracker, ILogger<AppErrorService> logger)
{
    public async Task RecordAsync(CapturedError error, CancellationToken ct = default)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();

            var fingerprint = ErrorFingerprint.Compute(error.ExceptionType, error.StackTrace);
            var now = DateTimeOffset.UtcNow;

            var existing = await db.AppErrors.FirstOrDefaultAsync(e => e.Fingerprint == fingerprint, ct);
            if (existing is not null)
            {
                existing.Occurrences += 1;
                existing.LastSeenAt = now;
                existing.LastCorrelationId = Clip(error.CorrelationId, 64);
                if (existing.Status == AppErrorStatus.Resolved)
                {
                    existing.Status = AppErrorStatus.Open; // a recurrence reopens it
                }
                await db.SaveChangesAsync(ct);
                return;
            }

            var appError = new AppError
            {
                Fingerprint = fingerprint,
                ExceptionType = Clip(error.ExceptionType, 256) ?? "UnknownException",
                Message = Clip(SecretScrubber.Scrub(error.Message), 2000),
                StackExcerpt = Clip(SecretScrubber.Scrub(ErrorFingerprint.NormalizeFrames(error.StackTrace)), 4000),
                RequestMethod = Clip(error.RequestMethod, 16),
                RequestPath = Clip(error.RequestPath, 512),
                LastCorrelationId = Clip(error.CorrelationId, 64),
                FirstSeenAt = now,
                LastSeenAt = now,
            };
            db.AppErrors.Add(appError);
            await db.SaveChangesAsync(ct);

            await TrySyncIssueAsync(db, appError, ct);
        }
        catch (Exception ex)
        {
            // Includes the rare unique-index race on first sight of a fault: drop, don't disturb.
            logger.LogWarning(ex, "Error capture failed; continuing.");
        }
    }

    private async Task TrySyncIssueAsync(RavelinDbContext db, AppError appError, CancellationToken ct)
    {
        try
        {
            var issue = await issueTracker.TryCreateIssueAsync(appError, ct);
            if (issue is null)
            {
                return; // no tracker configured (the default)
            }
            appError.IssueIdentifier = Clip(issue.Identifier, 64);
            appError.IssueUrl = Clip(issue.Url, 512);
            appError.IssueSyncedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Issue sync failed; the error is still recorded locally.");
        }
    }

    private static string? Clip(string? s, int max) =>
        string.IsNullOrWhiteSpace(s) ? null : (s.Length <= max ? s : s[..max]);
}

/// <summary>Raw (un-scrubbed) capture context handed to <see cref="AppErrorService"/>; the
/// service scrubs and clips before anything is stored.</summary>
public sealed record CapturedError
{
    public required string ExceptionType { get; init; }
    public string? Message { get; init; }
    public string? StackTrace { get; init; }
    public string? RequestMethod { get; init; }
    public string? RequestPath { get; init; }
    public string? CorrelationId { get; init; }
}
