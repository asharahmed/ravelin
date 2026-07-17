using System.Net;
using Ravelin.Shared;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Token revocation (0.8.2): a JWT carries the user's Identity security stamp, validated on every
/// request. Rotating the stamp (role change / password reset / disable) revokes already-issued
/// tokens immediately, rather than leaving them valid until expiry.
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class TokenRevocationTests(RavelinFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Existing_token_is_rejected_after_security_stamp_rotates()
    {
        using var client = await fixture.CreateClientForRoleAsync(RavelinRoles.Analyst);

        // The freshly-issued token works.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/projects")).StatusCode);

        // A role change / password reset / disable rotates the stamp...
        await fixture.RotateSecurityStampAsync("analyst@ravelin.test");

        // ...and the same token is now rejected on the next request (not honoured until expiry).
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/projects")).StatusCode);
    }
}
