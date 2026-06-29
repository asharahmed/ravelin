using System.Net;
using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;

namespace Ravelin.IntegrationTests;

/// <summary>
/// End-to-end proof of the error-capture pipeline: an unhandled exception thrown deep in the
/// real request pipeline is recorded as an AppError in real SQL — secret-scrubbed, with the
/// request path but not the query string — and a recurrence dedups to one row with a bumped
/// occurrence count. Exercises the middleware, the AppErrorService, and the new migration.
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class ErrorCaptureTests(RavelinFixture fixture) : IAsyncLifetime
{
    private const string ThrowRoute = "/api/_test/throw";

    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task UnhandledException_IsCaptured_Scrubbed_AndDeduped()
    {
        using var client = fixture.CreateClient();
        const string secret = "rvln_supersecretvalue1234567890";

        var first = await client.GetAsync($"{ThrowRoute}?token={secret}");
        Assert.True((int)first.StatusCode >= 500); // unhandled -> server-error response, unchanged

        var error = await PollForErrorAsync();
        Assert.NotNull(error);
        Assert.Equal("System.InvalidOperationException", error!.ExceptionType);
        Assert.Equal(ThrowRoute, error.RequestPath); // path only — no query string captured
        Assert.Equal("GET", error.RequestMethod);
        Assert.Equal(1, error.Occurrences);

        // Security: the secret carried in the exception message must be redacted before storage.
        Assert.NotNull(error.Message);
        Assert.DoesNotContain(secret, error.Message!);
        Assert.Contains("[redacted]", error.Message!);

        // Same fault again -> still one row (SingleOrDefault would throw on a duplicate), count++.
        await client.GetAsync($"{ThrowRoute}?token={secret}");
        var deduped = await PollForErrorAsync(minOccurrences: 2);
        Assert.NotNull(deduped);
        Assert.Equal(2, deduped!.Occurrences);
    }

    // Capture runs in its own DB scope; poll briefly for the committed row to avoid flakiness.
    private async Task<AppError?> PollForErrorAsync(int minOccurrences = 1)
    {
        AppError? found = null;
        for (var attempt = 0; attempt < 25; attempt++)
        {
            await fixture.WithDbAsync(async db =>
                found = await db.AppErrors.AsNoTracking()
                    .SingleOrDefaultAsync(e => e.RequestPath == ThrowRoute));
            if (found is not null && found.Occurrences >= minOccurrences)
            {
                return found;
            }
            await Task.Delay(80);
        }
        return found;
    }
}
