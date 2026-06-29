using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Ravelin.Infrastructure;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Boots the real Ravelin host through <see cref="WebApplicationFactory{TEntryPoint}"/>, but
/// repoints <see cref="RavelinDbContext"/> from Azure SQL to a throwaway Testcontainers SQL
/// Server. Everything else — authentication, routing, model validation, rate limiting, the
/// ingestion/reconciliation pipeline — is the genuine production code path. No mocks of the
/// system under test: that is the whole point, so a test can't pass against fake behaviour.
/// </summary>
public sealed class RavelinAppFactory(string connectionString) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // A neutral environment: not Development (so it skips Blazor WASM debugging) and not the
        // Production secrets/Key Vault wiring. Just enough to boot the host in a test process.
        builder.UseEnvironment("Testing");

        builder.ConfigureTestServices(services =>
        {
            // Replace the app's Azure SQL DbContext with one pointed at the container.
            // ConfigureTestServices runs after the app's own registrations, so this wins — and
            // it is in place before Program.cs runs Database.MigrateAsync() at startup, so the
            // schema (and HasData-seeded SLA policies) are created in the container automatically.
            services.RemoveAll<DbContextOptions<RavelinDbContext>>();
            services.RemoveAll<RavelinDbContext>();
            services.AddDbContext<RavelinDbContext>(options => options.UseSqlServer(connectionString));
        });
    }
}
