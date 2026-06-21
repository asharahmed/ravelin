using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace Ravelin.Client.Auth;

/// <summary>Supplies Blazor's authentication state from the JWT held in localStorage.</summary>
public sealed class JwtAuthenticationStateProvider(TokenStore tokens) : AuthenticationStateProvider
{
    // Must match the claim types the server puts in the token (JwtTokenService uses "role";
    // the email is the standard "email" claim) so IsInRole / <AuthorizeView Roles="..."> and
    // @context.User.Identity?.Name resolve correctly.
    private const string RoleClaim = "role";
    private const string EmailClaim = "email";

    private static readonly AuthenticationState Anonymous =
        new(new ClaimsPrincipal(new ClaimsIdentity()));

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await tokens.GetAsync();
        if (string.IsNullOrWhiteSpace(token))
        {
            return Anonymous;
        }

        var claims = JwtParser.ParseClaims(token);
        var expiry = JwtParser.GetExpiry(claims);
        if (expiry is not null && expiry <= DateTimeOffset.UtcNow)
        {
            // Expired token — drop it so the user is treated as signed out.
            await tokens.ClearAsync();
            return Anonymous;
        }

        var identity = new ClaimsIdentity(claims, authenticationType: "jwt",
            nameType: EmailClaim, roleType: RoleClaim);
        return new AuthenticationState(new ClaimsPrincipal(identity));
    }

    /// <summary>Re-read the stored token and broadcast the new auth state to the UI.</summary>
    public void NotifyAuthChanged() =>
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
}
