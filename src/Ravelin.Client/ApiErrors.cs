using System.Text.Json;

namespace Ravelin.Client;

/// <summary>
/// Extracts a user-facing message from a failed HTTP response, tolerant of both RFC 9457
/// ProblemDetails (<c>application/problem+json</c> with a <c>detail</c>/<c>title</c>) and the
/// older plain-string error bodies. Dependency-free so it works in the WASM client.
/// </summary>
public static class ApiErrors
{
    public static async Task<string> ReadMessageAsync(HttpResponseMessage response, string fallback)
    {
        try
        {
            var raw = (await response.Content.ReadAsStringAsync()).Trim();
            if (string.IsNullOrWhiteSpace(raw)) return fallback;

            // ProblemDetails (or any JSON object) — prefer detail, then title.
            if (raw.StartsWith('{'))
            {
                try
                {
                    using var doc = JsonDocument.Parse(raw);
                    var root = doc.RootElement;
                    foreach (var prop in new[] { "detail", "title" })
                    {
                        if (root.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String)
                        {
                            var s = v.GetString();
                            if (!string.IsNullOrWhiteSpace(s)) return s!;
                        }
                    }
                }
                catch (JsonException) { /* fall through to the raw body */ }
            }

            return raw.Trim('"');
        }
        catch
        {
            return fallback;
        }
    }
}
