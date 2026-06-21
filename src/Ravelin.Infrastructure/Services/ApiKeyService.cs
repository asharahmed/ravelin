using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Issues and validates project-scoped API keys. Keys are 256 bits of CSPRNG entropy, so a
/// fast hash (SHA-256) is appropriate for storage — unlike low-entropy passwords. The raw
/// key is returned only at creation; only the hash is persisted.
/// </summary>
public class ApiKeyService(RavelinDbContext db)
{
    private const string Prefix = "rvln_";

    public async Task<(ApiKey Entity, string RawKey)> CreateAsync(
        Guid projectId, string name, CancellationToken ct = default)
    {
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var rawKey = Prefix + secret;

        var entity = new ApiKey
        {
            ProjectId = projectId,
            Name = name,
            KeyHash = Hash(rawKey),
            KeyPrefix = rawKey[..9], // e.g. "rvln_ab12" — non-secret identifier
        };

        db.ApiKeys.Add(entity);
        await db.SaveChangesAsync(ct);
        return (entity, rawKey);
    }

    /// <summary>Returns the matching active key (with its project) or null. Updates LastUsedAt.</summary>
    public async Task<ApiKey?> ValidateAsync(string? rawKey, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawKey))
        {
            return null;
        }

        var hash = Hash(rawKey);
        var key = await db.ApiKeys
            .Include(k => k.Project)
            .FirstOrDefaultAsync(k => k.KeyHash == hash && k.RevokedAt == null, ct);

        if (key is null)
        {
            return null;
        }

        key.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return key;
    }

    public static string Hash(string rawKey) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawKey)));
}
