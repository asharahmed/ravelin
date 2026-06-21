using System.Security.Cryptography;
using System.Text;

namespace Ravelin.Endpoints;

/// <summary>
/// Temporary admin gate for Stage 3: requires a matching "X-Bootstrap-Token" header (value
/// from configuration "Ravelin:BootstrapToken"). Lets us create projects/keys and read data
/// before user auth exists. Replaced by ASP.NET Core Identity + RBAC in Stage 4.
/// Comparison is constant-time to avoid leaking the token via timing.
/// </summary>
public class BootstrapTokenFilter(IConfiguration config) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var expected = config["Ravelin:BootstrapToken"];
        var provided = context.HttpContext.Request.Headers["X-Bootstrap-Token"].FirstOrDefault();

        if (string.IsNullOrEmpty(expected) || !FixedTimeEquals(expected, provided))
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }

    private static bool FixedTimeEquals(string a, string? b)
    {
        if (b is null)
        {
            return false;
        }

        // Hash both to equal-length digests so the comparison length can't leak the secret length.
        var ha = SHA256.HashData(Encoding.UTF8.GetBytes(a));
        var hb = SHA256.HashData(Encoding.UTF8.GetBytes(b));
        return CryptographicOperations.FixedTimeEquals(ha, hb);
    }
}
