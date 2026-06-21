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
            options.UseSqlServer(connectionString ?? "Server=(unconfigured)"));

        services.AddScoped<ApiKeyService>();
        services.AddScoped<IngestionService>();

        return services;
    }
}
