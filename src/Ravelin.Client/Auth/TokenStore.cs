using Microsoft.JSInterop;

namespace Ravelin.Client.Auth;

/// <summary>Persists the human-auth JWT in browser localStorage via a tiny JS interop call.
/// localStorage is acceptable here: the token is short-lived (60 min) and the API validates
/// every call server-side. (A future hardening could move to an in-memory + refresh model.)</summary>
public sealed class TokenStore(IJSRuntime js)
{
    private const string Key = "ravelin.jwt";

    public ValueTask<string?> GetAsync() =>
        js.InvokeAsync<string?>("localStorage.getItem", Key);

    public ValueTask SetAsync(string token) =>
        js.InvokeVoidAsync("localStorage.setItem", Key, token);

    public ValueTask ClearAsync() =>
        js.InvokeVoidAsync("localStorage.removeItem", Key);
}
