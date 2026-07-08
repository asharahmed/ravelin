using System.Data.Common;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Ravelin.Auth;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Infrastructure;
using Ravelin.Infrastructure.Services;
using Respawn;
using Testcontainers.MsSql;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Shared across the whole integration-test collection: one SQL Server container and one booted
/// app, reused for speed. <see cref="ResetAsync"/> (Respawn) wipes per-test domain data between
/// tests so each starts from a clean slate, while preserving rows that are seeded exactly once
/// at startup (the SLA policies and Identity roles).
/// </summary>
public sealed class RavelinFixture : IAsyncLifetime
{
    private readonly MsSqlContainer _sql = new MsSqlBuilder().Build();
    private RavelinAppFactory _factory = null!;
    private Respawner _respawner = null!;
    private DbConnection _respawnConnection = null!;

    public RavelinAppFactory Factory => _factory;

    public HttpClient CreateClient() => _factory.CreateClient();

    public async Task InitializeAsync()
    {
        await _sql.StartAsync();

        _factory = new RavelinAppFactory(_sql.GetConnectionString());

        // Touch the service provider to force host startup, which applies EF migrations against
        // the fresh container (schema + seeded SLA policies) before we snapshot for Respawn.
        using (var scope = _factory.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<RavelinDbContext>().Database.MigrateAsync();
        }

        _respawnConnection = new SqlConnection(_sql.GetConnectionString());
        await _respawnConnection.OpenAsync();
        _respawner = await Respawner.CreateAsync(_respawnConnection, new RespawnerOptions
        {
            DbAdapter = DbAdapter.SqlServer,
            SchemasToInclude = ["dbo"],
            // Preserve rows seeded once at startup; everything else is per-test data to wipe.
            TablesToIgnore =
            [
                "__EFMigrationsHistory",
                "SlaPolicies",
                "AspNetRoles", "AspNetRoleClaims",
                "AspNetUsers", "AspNetUserRoles", "AspNetUserClaims",
                "AspNetUserLogins", "AspNetUserTokens",
            ],
        });
    }

    /// <summary>Wipes per-test domain data (Findings, Scans, Projects, ApiKeys, audit, alerts).</summary>
    public Task ResetAsync() => _respawner.ResetAsync(_respawnConnection);

    /// <summary>Creates a project and a live API key for it, returning the raw key (shown once).
    /// Lets a test authenticate to the ingestion endpoints exactly as a pipeline would.</summary>
    public async Task<(Project Project, string RawApiKey)> SeedProjectWithKeyAsync(string key)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();

        var project = new Project { Key = key, Name = key };
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        var apiKeys = scope.ServiceProvider.GetRequiredService<ApiKeyService>();
        var (_, rawKey) = await apiKeys.CreateAsync(project.Id, $"{key}-ci");
        return (project, rawKey);
    }

    /// <summary>Runs an assertion against a fresh DbContext scope (read DB state after a request).</summary>
    public async Task WithDbAsync(Func<RavelinDbContext, Task> action)
    {
        using var scope = _factory.Services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<RavelinDbContext>());
    }

    /// <summary>Creates a project (with one open finding) at the given visibility, for authz tests.</summary>
    public async Task<Guid> SeedProjectAsync(string key, bool isPublic)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();

        var project = new Project { Key = key, Name = key, IsPublic = isPublic };
        db.Projects.Add(project);
        db.Findings.Add(new Finding
        {
            ProjectId = project.Id,
            VulnerabilityId = "CVE-2024-0001",
            PackageName = "seed-pkg",
            PackageVersion = "1.0.0",
            Title = "seed finding",
            Severity = Severity.High,
            Status = FindingStatus.Open,
            FirstDetectedAt = DateTimeOffset.UtcNow,
            LastSeenAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        return project.Id;
    }

    /// <summary>Grants a seeded user (by email) membership of a project (by key).</summary>
    public async Task GrantMembershipAsync(string email, string projectKey)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

        var user = await users.FindByEmailAsync(email)
            ?? throw new InvalidOperationException($"No seeded user {email}");
        var project = await db.Projects.FirstAsync(p => p.Key == projectKey);
        db.ProjectMemberships.Add(new ProjectMembership { UserId = user.Id, ProjectId = project.Id });
        await db.SaveChangesAsync();
    }

    /// <summary>Idempotently ensures a user exists with exactly the given role. Roles/users live
    /// in AspNet* tables, which Respawn preserves across resets, so this is safe to call every
    /// test. Returns an <see cref="HttpClient"/> pre-authenticated as that user via a real JWT.</summary>
    public async Task<HttpClient> CreateClientForRoleAsync(string role)
    {
        var email = $"{role.ToLowerInvariant()}@ravelin.test";
        const string password = "Integration-Test-Pw-1!";

        string token;
        using (var scope = _factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            if (!await roles.RoleExistsAsync(role))
            {
                await roles.CreateAsync(new IdentityRole(role));
            }

            var user = await users.FindByEmailAsync(email);
            if (user is null)
            {
                user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
                var created = await users.CreateAsync(user, password);
                if (!created.Succeeded)
                {
                    throw new InvalidOperationException(
                        "Failed to seed test user: " + string.Join("; ", created.Errors.Select(e => e.Description)));
                }
            }

            var current = await users.GetRolesAsync(user);
            if (current.Count > 0) await users.RemoveFromRolesAsync(user, current);
            await users.AddToRoleAsync(user, role);

            // Mint the JWT directly (bypasses the login endpoint's per-IP "auth" rate limit, which
            // would otherwise 429 a test that authenticates many times from loopback).
            var jwt = scope.ServiceProvider.GetRequiredService<JwtTokenService>();
            var userRoles = await users.GetRolesAsync(user);
            (token, _) = jwt.CreateToken(user.Id, user.Email!, userRoles);
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public async Task DisposeAsync()
    {
        if (_respawnConnection is not null)
        {
            await _respawnConnection.DisposeAsync();
        }
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }
        await _sql.DisposeAsync();
    }
}

/// <summary>Binds the fixture to the integration-test collection. Tests in one collection run
/// sequentially, which suits a single shared database reset by Respawn between tests.</summary>
[CollectionDefinition(Name)]
public sealed class RavelinCollection : ICollectionFixture<RavelinFixture>
{
    public const string Name = "ravelin-integration";
}
