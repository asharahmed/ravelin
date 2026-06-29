using System.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Ravelin.Domain.Entities;
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
