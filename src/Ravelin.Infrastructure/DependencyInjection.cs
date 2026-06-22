using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Ravelin.Infrastructure.Services;

namespace Ravelin.Infrastructure;

public static class DependencyInjection
{
    /// <summary>Registers the EF Core context (Azure SQL) and Ravelin application services.</summary>
    public static IServiceCollection AddRavelinInfrastructure(
        this IServiceCollection services, string? connectionString)
    {
        services.AddDbContext<RavelinDbContext>(options =>
            options.UseSqlServer(connectionString ?? "Server=(unconfigured)", sql =>
                // Azure SQL serverless auto-pauses when idle; the first query after a resume
                // (and other transient faults) must be retried rather than failing the request.
                sql.EnableRetryOnFailure(
                    maxRetryCount: 5,
                    maxRetryDelay: TimeSpan.FromSeconds(10),
                    errorNumbersToAdd: null)));

        services.AddScoped<ApiKeyService>();
        services.AddScoped<IngestionService>();
        services.AddSingleton<AuditService>();
        services.AddSingleton<NotificationService>();
        services.AddSingleton<SlaReEvaluator>();

        return services;
    }
}
