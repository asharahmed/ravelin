using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Services;

/// <summary>Configuration for the Linear issue tracker (section "Linear").</summary>
public sealed class LinearOptions
{
    public const string SectionName = "Linear";

    /// <summary>Linear personal API key — sent verbatim in the Authorization header.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Target team id (UUID) that captured-error issues are filed under.</summary>
    public string TeamId { get; set; } = string.Empty;

    public bool IsConfigured => !string.IsNullOrWhiteSpace(ApiKey) && !string.IsNullOrWhiteSpace(TeamId);
}

/// <summary>
/// Files a captured <see cref="AppError"/> as a Linear issue via the GraphQL API. Config-gated:
/// only registered (replacing <see cref="NullIssueTracker"/>) when Linear:ApiKey and
/// Linear:TeamId are set. Best-effort — any failure returns null and the error stays recorded
/// locally; capture must never depend on an external service being reachable. The fields it
/// sends (message, stack excerpt) were already secret-scrubbed at capture time.
/// </summary>
public sealed class LinearIssueTracker(
    IHttpClientFactory httpFactory, IOptions<LinearOptions> options, ILogger<LinearIssueTracker> logger)
    : IIssueTracker
{
    private const string Endpoint = "https://api.linear.app/graphql";

    private const string Mutation =
        "mutation CreateIssue($input: IssueCreateInput!) { " +
        "issueCreate(input: $input) { success issue { identifier url } } }";

    private readonly LinearOptions _options = options.Value;

    public async Task<TrackedIssue?> TryCreateIssueAsync(AppError error, CancellationToken ct = default)
    {
        if (!_options.IsConfigured)
        {
            return null;
        }

        var payload = new
        {
            query = Mutation,
            variables = new
            {
                input = new
                {
                    title = BuildTitle(error),
                    description = BuildDescription(error),
                    teamId = _options.TeamId,
                },
            },
        };

        try
        {
            var client = httpFactory.CreateClient("linear");
            using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint)
            {
                Content = JsonContent.Create(payload),
            };
            // Linear personal API keys go in Authorization verbatim — NOT as a Bearer token.
            request.Headers.TryAddWithoutValidation("Authorization", _options.ApiKey);

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Linear issueCreate failed: HTTP {Status}", (int)response.StatusCode);
                return null;
            }

            var body = await response.Content.ReadFromJsonAsync<LinearResponse>(ct);
            var result = body?.Data?.IssueCreate;
            if (result is not { Success: true, Issue: { } issue })
            {
                logger.LogWarning("Linear issueCreate returned no issue (success={Success}).", result?.Success);
                return null;
            }
            return new TrackedIssue(issue.Identifier, issue.Url);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Linear issueCreate threw; the error remains recorded locally.");
            return null;
        }
    }

    private static string BuildTitle(AppError e)
    {
        var where = string.IsNullOrEmpty(e.RequestPath) ? "" : $" at {e.RequestMethod} {e.RequestPath}";
        var title = $"[error] {e.ExceptionType}{where}";
        return title.Length <= 250 ? title : title[..250];
    }

    private static string BuildDescription(AppError e) =>
        $"""
        **{e.ExceptionType}**

        {e.Message}

        | | |
        |---|---|
        | Where | `{e.RequestMethod} {e.RequestPath}` |
        | Occurrences | {e.Occurrences} |
        | First seen | {e.FirstSeenAt:u} |
        | Last seen | {e.LastSeenAt:u} |
        | Fingerprint | `{e.Fingerprint}` |
        | Correlation | `{e.LastCorrelationId}` |

        ```
        {e.StackExcerpt}
        ```

        _Filed automatically by Ravelin error capture._
        """;

    // Response shape (only the fields we use). Web JSON defaults are camelCase + case-insensitive.
    private sealed record LinearResponse([property: JsonPropertyName("data")] LinearData? Data);

    private sealed record LinearData(
        [property: JsonPropertyName("issueCreate")] IssueCreatePayload? IssueCreate);

    private sealed record IssueCreatePayload(
        [property: JsonPropertyName("success")] bool Success,
        [property: JsonPropertyName("issue")] IssueNode? Issue);

    private sealed record IssueNode(
        [property: JsonPropertyName("identifier")] string Identifier,
        [property: JsonPropertyName("url")] string Url);
}
