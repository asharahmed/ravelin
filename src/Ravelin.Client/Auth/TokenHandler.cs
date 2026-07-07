using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Components;

namespace Ravelin.Client.Auth;

/// <summary>
/// Attaches the stored JWT as a Bearer header to outgoing API requests, and centralizes the
/// response to an expired/revoked token: a 401 on an authenticated call clears the token, flips
/// auth state to anonymous, and redirects to /login (preserving the current page as returnUrl),
/// instead of letting every page surface a raw "401 (Unauthorized)" exception string.
/// </summary>
public sealed class TokenHandler(
    TokenStore tokens,
    NavigationManager nav,
    JwtAuthenticationStateProvider stateProvider) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await tokens.GetAsync();
        var hadToken = !string.IsNullOrWhiteSpace(token);
        if (hadToken)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // Only treat a 401 as "session ended" when we actually sent a token and the call was NOT
        // an auth endpoint (login/register return 401 for bad credentials — those handle their own
        // messaging). Skip if we're already on /login to avoid a redirect loop.
        if (response.StatusCode == HttpStatusCode.Unauthorized
            && hadToken
            && request.RequestUri is { } uri
            && !uri.AbsolutePath.Contains("/api/auth/", StringComparison.OrdinalIgnoreCase))
        {
            var here = nav.ToBaseRelativePath(nav.Uri);
            if (!here.StartsWith("login", StringComparison.OrdinalIgnoreCase))
            {
                await tokens.ClearAsync();
                stateProvider.NotifyAuthChanged();

                var query = string.IsNullOrEmpty(here)
                    ? string.Empty
                    : $"?returnUrl={Uri.EscapeDataString(here)}";
                nav.NavigateTo($"login{query}");
            }
        }

        return response;
    }
}
