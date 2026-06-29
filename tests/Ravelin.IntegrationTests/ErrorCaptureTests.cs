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

        await TriggerThrowAsync(client, $"{ThrowRoute}?token={secret}");

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
        await TriggerThrowAsync(client, $"{ThrowRoute}?token={secret}");
        var deduped = await PollForErrorAsync(minOccurrences: 2);
        Assert.NotNull(deduped);
        Assert.Equal(2, deduped!.Occurrences);
    }

    // Hits the deliberately-throwing endpoint. A real server (Kestrel) returns 500; the in-memory
    // TestServer instead surfaces the unhandled exception to the caller. Either way the request
    // failed unhandled — and the capture middleware, below the exception handler, recorded it
    // before the rethrow. What this test asserts is that recording, not the response shape.
    private static async Task TriggerThrowAsync(HttpClient client, string url)
    {
        try
        {
            var response = await client.GetAsync(url);
            Assert.True((int)response.StatusCode >= 500);
        }
        catch (InvalidOperationException)
        {
            // Expected under TestServer: the deliberate test exception is rethrown to the caller.
        }
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
