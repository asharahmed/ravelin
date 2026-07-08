using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Ravelin.Auth;

public class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; set; } = "ravelin";
    public string Audience { get; set; } = "ravelin";
    public string SigningKey { get; set; } = string.Empty;
    public int ExpiryMinutes { get; set; } = 60;
}

/// <summary>Issues signed JWTs (HMAC-SHA256) carrying the user's id, email, and roles.</summary>
public class JwtTokenService(IOptions<JwtOptions> options)
{
    public const string RoleClaim = "role";

    /// <summary>Identity security-stamp claim. Validated per request (see Program.cs) so a role
    /// change, password reset, or disable revokes existing tokens immediately.</summary>
    public const string StampClaim = "sstamp";

    private readonly JwtOptions _options = options.Value;

    public (string Token, DateTimeOffset ExpiresAt) CreateToken(
        string userId, string email, IEnumerable<string> roles, string? securityStamp = null)
    {
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(_options.ExpiryMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Email, email),
        };
        claims.AddRange(roles.Select(r => new Claim(RoleClaim, r)));
        if (!string.IsNullOrEmpty(securityStamp))
        {
            claims.Add(new Claim(StampClaim, securityStamp));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            Subject = new ClaimsIdentity(claims),
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        };

        var token = new JsonWebTokenHandler().CreateToken(descriptor);
        return (token, expiresAt);
    }
}
