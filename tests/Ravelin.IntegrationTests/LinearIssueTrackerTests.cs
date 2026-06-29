using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Ravelin.Domain.Entities;
using Ravelin.Infrastructure.Services;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Unit tests for <see cref="LinearIssueTracker"/> with a stubbed HTTP handler — no network, no
/// database, so no collection fixture (and no SQL container) is involved. Verifies the request
/// it sends to Linear and how it interprets the response, plus the best-effort fallbacks.
/// </summary>
public sealed class LinearIssueTrackerTests
{
    [Fact]
    public async Task Files_issue_sends_raw_api_key_and_returns_identifier_and_url()
    {
        string? sentAuth = null;
        string? sentBody = null;
        var handler = new StubHandler(async req =>
        {
            sentAuth = req.Headers.TryGetValues("Authorization", out var v) ? string.Concat(v) : null;
            sentBody = req.Content is null ? null : await req.Content.ReadAsStringAsync();
            return Json("""
                {"data":{"issueCreate":{"success":true,
                  "issue":{"identifier":"RAV-42","url":"https://linear.app/acme/issue/RAV-42"}}}}
                """);
        });

        var tracker = NewTracker(handler, apiKey: "lin_api_test_key", teamId: "team-uuid-123");

        var issue = await tracker.TryCreateIssueAsync(NewError());

        Assert.NotNull(issue);
        Assert.Equal("RAV-42", issue!.Identifier);
        Assert.Equal("https://linear.app/acme/issue/RAV-42", issue.Url);
        Assert.Equal("lin_api_test_key", sentAuth);    // raw key, NOT "Bearer ..."
        Assert.Contains("issueCreate", sentBody);
        Assert.Contains("team-uuid-123", sentBody);     // team id forwarded
    }

    [Fact]
    public async Task Returns_null_when_not_configured_and_never_calls_out()
    {
        var handler = new StubHandler(_ => throw new InvalidOperationException("should not be called"));
        var tracker = NewTracker(handler, apiKey: "", teamId: "");

        Assert.Null(await tracker.TryCreateIssueAsync(NewError()));
    }

    [Fact]
    public async Task Returns_null_on_http_error()
    {
        var handler = new StubHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)));
        var tracker = NewTracker(handler, apiKey: "lin_api_test_key", teamId: "team-uuid-123");

        Assert.Null(await tracker.TryCreateIssueAsync(NewError()));
    }

    [Fact]
    public async Task Returns_null_when_mutation_reports_failure()
    {
        var handler = new StubHandler(_ =>
            Task.FromResult(Json("""{"data":{"issueCreate":{"success":false,"issue":null}}}""")));
        var tracker = NewTracker(handler, apiKey: "lin_api_test_key", teamId: "team-uuid-123");

        Assert.Null(await tracker.TryCreateIssueAsync(NewError()));
    }

    private static LinearIssueTracker NewTracker(HttpMessageHandler handler, string apiKey, string teamId) =>
        new(new SingleClientFactory(handler),
            Options.Create(new LinearOptions { ApiKey = apiKey, TeamId = teamId }),
            NullLogger<LinearIssueTracker>.Instance);

    private static AppError NewError() => new()
    {
        Fingerprint = "ABC123",
        ExceptionType = "System.InvalidOperationException",
        Message = "boom",
        RequestMethod = "GET",
        RequestPath = "/api/x",
        StackExcerpt = "at Ravelin.X.Y()",
    };

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => respond(request);
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
