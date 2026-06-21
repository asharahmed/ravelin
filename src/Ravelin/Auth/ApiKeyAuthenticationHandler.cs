using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Ravelin.Infrastructure.Services;

namespace Ravelin.Auth;

public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions;

/// <summary>
/// Authenticates pipeline requests by a project-scoped API key supplied as
/// "X-Api-Key: &lt;key&gt;" or "Authorization: Bearer &lt;key&gt;". On success the principal
/// carries the key's project id, so the ingestion endpoint can only ever write to that
/// project (least privilege — the route never chooses the project).
/// </summary>
public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiKeyService apiKeys)
    : AuthenticationHandler<ApiKeyAuthenticationOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";
    public const string HeaderName = "X-Api-Key";
    public const string ProjectIdClaim = "ravelin:project_id";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var raw = Request.Headers[HeaderName].FirstOrDefault();
        if (string.IsNullOrEmpty(raw))
        {
            var auth = Request.Headers.Authorization.FirstOrDefault();
            if (auth?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
            {
                raw = auth["Bearer ".Length..].Trim();
            }
        }

        if (string.IsNullOrEmpty(raw))
        {
            return AuthenticateResult.NoResult();
        }

        var key = await apiKeys.ValidateAsync(raw);
        if (key is null)
        {
            return AuthenticateResult.Fail("Invalid or revoked API key.");
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(ProjectIdClaim, key.ProjectId.ToString()),
                new Claim(ClaimTypes.Name, key.Project?.Key ?? key.ProjectId.ToString()),
            ],
            SchemeName);

        return AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }
}
