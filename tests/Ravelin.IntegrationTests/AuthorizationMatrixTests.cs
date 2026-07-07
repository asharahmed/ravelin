using System.Net;
using System.Net.Http.Json;
using Ravelin.Shared;
using Ravelin.Shared.Contracts;

namespace Ravelin.IntegrationTests;

/// <summary>
/// The RBAC matrix, exercised end-to-end through the real JwtBearer + authorization pipeline into
/// the genuine endpoints. For a security tool this is the highest-value regression gate: it proves
/// deny-by-default holds, that role boundaries are enforced server-side (not just cosmetically in
/// the client), and it guards the MapInboundClaims=false / RoleClaimType wiring that RequireRole
/// depends on. Unauthenticated → 401; authenticated-but-wrong-role → 403; authorized → past the
/// gate (2xx, or a 404 for a deliberately-absent resource, never a 403).
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class AuthorizationMatrixTests(RavelinFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    // --- POST /api/admin/projects : Admin only ---------------------------------------------

    [Fact]
    public async Task CreateProject_AsAdmin_Succeeds()
    {
        using var client = await fixture.CreateClientForRoleAsync(RavelinRoles.Admin);

        var response = await client.PostAsJsonAsync("/api/admin/projects",
            new CreateProjectRequest { Key = "authz-admin", Name = "Authz Admin" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Theory]
    [InlineData(RavelinRoles.Analyst)]
    [InlineData(RavelinRoles.Viewer)]
    public async Task CreateProject_AsNonAdmin_IsForbidden(string role)
    {
        using var client = await fixture.CreateClientForRoleAsync(role);

        var response = await client.PostAsJsonAsync("/api/admin/projects",
            new CreateProjectRequest { Key = "authz-deny", Name = "Denied" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task CreateProject_NoToken_IsUnauthorized()
    {
        using var client = fixture.CreateClient();

        var response = await client.PostAsJsonAsync("/api/admin/projects",
            new CreateProjectRequest { Key = "authz-anon", Name = "Anon" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- Triage : Admin or Analyst; Viewer read-only ---------------------------------------
    // Authorization runs before the handler, so a Viewer is forbidden even for a finding that
    // does not exist, while an authorized role reaches the handler and gets 404 — which proves
    // it passed the role gate rather than being blocked by it.

    [Fact]
    public async Task Triage_AsViewer_IsForbidden()
    {
        using var client = await fixture.CreateClientForRoleAsync(RavelinRoles.Viewer);

        var response = await Triage(client);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData(RavelinRoles.Admin)]
    [InlineData(RavelinRoles.Analyst)]
    public async Task Triage_AsAnalystOrAdmin_PassesTheRoleGate(string role)
    {
        using var client = await fixture.CreateClientForRoleAsync(role);

        var response = await Triage(client);

        // Not 403: authorized, but the finding does not exist.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Triage_NoToken_IsUnauthorized()
    {
        using var client = fixture.CreateClient();

        var response = await Triage(client);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- PUT /api/sla-policies : Admin only ------------------------------------------------

    [Fact]
    public async Task UpdateSlaPolicies_AsAnalyst_IsForbidden()
    {
        using var client = await fixture.CreateClientForRoleAsync(RavelinRoles.Analyst);

        var response = await client.PutAsJsonAsync("/api/sla-policies", new UpdateSlaPoliciesRequest
        {
            Policies = [new SlaPolicyDto { Severity = "High", RemediationDays = 20 }],
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task UpdateSlaPolicies_AsAdmin_Succeeds()
    {
        using var client = await fixture.CreateClientForRoleAsync(RavelinRoles.Admin);

        var response = await client.PutAsJsonAsync("/api/sla-policies", new UpdateSlaPoliciesRequest
        {
            Policies = [new SlaPolicyDto { Severity = "High", RemediationDays = 20 }],
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // --- Reads : any authenticated user; anonymous denied ----------------------------------

    [Fact]
    public async Task Reads_RequireAuthentication_ButAllowAnyRole()
    {
        using var anon = fixture.CreateClient();
        var anonResponse = await anon.GetAsync("/api/projects");
        Assert.Equal(HttpStatusCode.Unauthorized, anonResponse.StatusCode);

        using var viewer = await fixture.CreateClientForRoleAsync(RavelinRoles.Viewer);
        var viewerResponse = await viewer.GetAsync("/api/projects");
        Assert.Equal(HttpStatusCode.OK, viewerResponse.StatusCode);
    }

    private static Task<HttpResponseMessage> Triage(HttpClient client) =>
        client.PostAsJsonAsync(
            $"/api/projects/no-such-project/findings/{Guid.NewGuid()}/triage",
            new TriageFindingRequest { Status = "AcceptedRisk", Note = "n/a" });
}
