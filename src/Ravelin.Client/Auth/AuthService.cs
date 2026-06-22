using System.Net;
using System.Net.Http.Json;
using Ravelin.Shared.Contracts;

namespace Ravelin.Client.Auth;

/// <summary>Coordinates login/logout: calls the API, persists the JWT, and refreshes auth state.</summary>
public sealed class AuthService(
    HttpClient http, TokenStore tokens, JwtAuthenticationStateProvider stateProvider)
{
    /// <summary>Attempts a login. Returns <c>null</c> on success, or a user-facing error message.</summary>
    public async Task<string?> LoginAsync(LoginRequest request)
    {
        HttpResponseMessage response;
        try
        {
            response = await http.PostAsJsonAsync("api/auth/login", request);
        }
        catch (Exception ex)
        {
            return $"Could not reach the server: {ex.Message}";
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Invalid email or password.";
        }
        if (!response.IsSuccessStatusCode)
        {
            return $"Login failed ({(int)response.StatusCode}).";
        }

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();
        if (login is null || string.IsNullOrWhiteSpace(login.Token))
        {
            return "Login failed: the server returned an empty response.";
        }

        await tokens.SetAsync(login.Token);
        stateProvider.NotifyAuthChanged();
        return null;
    }

    /// <summary>Registers a new (read-only Viewer) account and signs in. Returns <c>null</c>
    /// on success, or a user-facing error message.</summary>
    public async Task<string?> RegisterAsync(RegisterRequest request)
    {
        HttpResponseMessage response;
        try
        {
            response = await http.PostAsJsonAsync("api/auth/register", request);
        }
        catch (Exception ex)
        {
            return $"Could not reach the server: {ex.Message}";
        }

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            return await ApiErrors.ReadMessageAsync(response, "Could not create the account.");
        }
        if (!response.IsSuccessStatusCode)
        {
            return $"Sign up failed ({(int)response.StatusCode}).";
        }

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();
        if (login is null || string.IsNullOrWhiteSpace(login.Token))
        {
            return "Sign up failed: the server returned an empty response.";
        }

        await tokens.SetAsync(login.Token);
        stateProvider.NotifyAuthChanged();
        return null;
    }

    public async Task LogoutAsync()
    {
        await tokens.ClearAsync();
        stateProvider.NotifyAuthChanged();
    }
}
