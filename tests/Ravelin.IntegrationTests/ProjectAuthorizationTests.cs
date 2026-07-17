using System.Net;
using System.Net.Http.Json;
using Ravelin.Shared;
using Ravelin.Shared.Contracts;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Per-project authorization (0.8.1): reads are scoped to the projects a user may see — public
/// projects, projects they're a member of, or all projects for Admins. Guards the "any Viewer
/// sees every project's data" hole end-to-end through the real pipeline + SQL.
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class ProjectAuthorizationTests(RavelinFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Viewer_sees_public_and_member_projects_only()
    {
        await fixture.SeedProjectAsync("authz-public", isPublic: true);
        await fixture.SeedProjectAsync("authz-member", isPublic: false);
        await fixture.SeedProjectAsync("authz-hidden", isPublic: false);

        using var viewer = await fixture.CreateClientForRoleAsync(RavelinRoles.Viewer);
        await fixture.GrantMembershipAsync("viewer@ravelin.test", "authz-member");

        var projects = await viewer.GetFromJsonAsync<List<ProjectDto>>("/api/projects");
        var keys = projects!.Select(p => p.Key).ToHashSet();

        Assert.Contains("authz-public", keys);   // public → visible to all
        Assert.Contains("authz-member", keys);    // member → visible
        Assert.DoesNotContain("authz-hidden", keys); // private, no membership → hidden
    }

    [Fact]
    public async Task Viewer_cannot_read_findings_of_unauthorized_project()
    {
        await fixture.SeedProjectAsync("authz-secret", isPublic: false);

        using var viewer = await fixture.CreateClientForRoleAsync(RavelinRoles.Viewer);
        var viewerResp = await viewer.GetAsync("/api/projects/authz-secret/findings");
        // 404, not 403 — existence must not be disclosed to an unauthorized user.
        Assert.Equal(HttpStatusCode.NotFound, viewerResp.StatusCode);

        using var admin = await fixture.CreateClientForRoleAsync(RavelinRoles.Admin);
        var adminResp = await admin.GetAsync("/api/projects/authz-secret/findings");
        Assert.Equal(HttpStatusCode.OK, adminResp.StatusCode); // Admin sees all
    }

    [Fact]
    public async Task Admin_sees_all_projects_regardless_of_visibility()
    {
        await fixture.SeedProjectAsync("authz-a", isPublic: false);
        await fixture.SeedProjectAsync("authz-b", isPublic: false);

        using var admin = await fixture.CreateClientForRoleAsync(RavelinRoles.Admin);
        var projects = await admin.GetFromJsonAsync<List<ProjectDto>>("/api/projects");
        var keys = projects!.Select(p => p.Key).ToHashSet();

        Assert.Contains("authz-a", keys);
        Assert.Contains("authz-b", keys);
    }

    [Fact]
    public async Task Self_service_registration_is_disabled_by_default()
    {
        using var client = fixture.CreateClient();
        var resp = await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest { Email = "newbie@example.com", Password = "Sup3r-Secret-Pw-1!" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_membership_grant_then_revoke_changes_visibility()
    {
        await fixture.SeedProjectAsync("authz-grant", isPublic: false);
        using var admin = await fixture.CreateClientForRoleAsync(RavelinRoles.Admin);
        using var viewer = await fixture.CreateClientForRoleAsync(RavelinRoles.Viewer);

        // Before grant: hidden.
        Assert.Equal(HttpStatusCode.NotFound,
            (await viewer.GetAsync("/api/projects/authz-grant/findings")).StatusCode);

        // Grant via the admin API.
        var grant = await admin.PostAsJsonAsync("/api/admin/projects/authz-grant/members",
            new GrantMembershipRequest { Email = "viewer@ravelin.test" });
        Assert.Equal(HttpStatusCode.NoContent, grant.StatusCode);

        // After grant: visible (the token is unchanged; visibility is evaluated against the DB).
        Assert.Equal(HttpStatusCode.OK,
            (await viewer.GetAsync("/api/projects/authz-grant/findings")).StatusCode);

        // Revoke: hidden again.
        var members = await admin.GetFromJsonAsync<List<ProjectMemberDto>>("/api/admin/projects/authz-grant/members");
        var userId = members!.Single().UserId;
        var revoke = await admin.DeleteAsync($"/api/admin/projects/authz-grant/members/{userId}");
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await viewer.GetAsync("/api/projects/authz-grant/findings")).StatusCode);
    }
}
