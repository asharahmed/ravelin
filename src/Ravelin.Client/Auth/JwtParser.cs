using System.Security.Claims;
using System.Text.Json;

namespace Ravelin.Client.Auth;

/// <summary>Decodes a JWT payload into claims WITHOUT validating the signature. The client
/// only needs the claims to render auth-aware UI; authenticity is enforced server-side on
/// every API call (the signing key never leaves the server).</summary>
public static class JwtParser
{
    public static IReadOnlyList<Claim> ParseClaims(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            return [];
        }

        var claims = new List<Claim>();
        using var doc = JsonDocument.Parse(DecodeBase64Url(parts[1]));

        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in prop.Value.EnumerateArray())
                {
                    claims.Add(new Claim(prop.Name, item.ToString()));
                }
            }
            else
            {
                claims.Add(new Claim(prop.Name, prop.Value.ToString()));
            }
        }

        return claims;
    }

    /// <summary>Reads the standard "exp" claim (Unix seconds) as an absolute time, if present.</summary>
    public static DateTimeOffset? GetExpiry(IEnumerable<Claim> claims)
    {
        var exp = claims.FirstOrDefault(c => c.Type == "exp")?.Value;
        return long.TryParse(exp, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            _ => string.Empty,
        };
        return Convert.FromBase64String(s);
    }
}
