using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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

        // Injectable clock — services use TimeProvider instead of DateTimeOffset.UtcNow so
        // time-dependent behavior (SLA transitions, snapshots) can be driven by a fake clock.
        services.TryAddSingleton(TimeProvider.System);

        services.AddScoped<ApiKeyService>();
        services.AddScoped<IngestionService>();
        services.AddSingleton<AuditService>();
        services.AddSingleton<NotificationService>();
        services.AddSingleton<SlaReEvaluator>();

        // Exploitation-intelligence enrichment is inert until AddVulnerabilityIntelligence enables
        // it (config-gated). The re-evaluator/admin endpoint always resolve IFindingEnricher.
        services.AddSingleton<IFindingEnricher, NullFindingEnricher>();

        // Error capture: dedup + persist unhandled exceptions. The issue tracker is a no-op until
        // a real (config-gated) one is registered in the capture→Linear delivery stage.
        services.AddSingleton<IIssueTracker, NullIssueTracker>();
        services.AddSingleton<AppErrorService>();

        return services;
    }

    /// <summary>
    /// Wires Linear as the issue tracker for captured errors — but only when Linear:ApiKey and
    /// Linear:TeamId are configured. Otherwise it does nothing and the no-op NullIssueTracker
    /// stays, so the capture path is fully functional with no Linear secret present (the same
    /// "config-gated, inert by default" shape as the dogfood ingest key).
    /// </summary>
    public static IServiceCollection AddLinearIssueTracker(
        this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection(LinearOptions.SectionName);
        var options = section.Get<LinearOptions>() ?? new LinearOptions();
        if (!options.IsConfigured)
        {
            return services;
        }

        services.Configure<LinearOptions>(section);
        services.AddHttpClient("linear", c => c.Timeout = TimeSpan.FromSeconds(10));
        services.Replace(ServiceDescriptor.Singleton<IIssueTracker, LinearIssueTracker>());
        return services;
    }

    /// <summary>
    /// Wires CISA-KEV + FIRST-EPSS enrichment and the risk-adjusted SLA it drives — but only when
    /// VulnIntel:Enabled is true. Otherwise the inert NullFindingEnricher stays, so local/dev/test
    /// runs make no external calls (the same "config-gated, inert by default" shape as Linear).
    /// </summary>
    public static IServiceCollection AddVulnerabilityIntelligence(
        this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection(VulnIntelOptions.SectionName);
        services.Configure<VulnIntelOptions>(section);

        var options = section.Get<VulnIntelOptions>() ?? new VulnIntelOptions();
        if (!options.Enabled)
        {
            return services;
        }

        services.AddHttpClient("vulnintel", c => c.Timeout = TimeSpan.FromSeconds(20));
        services.AddSingleton<IVulnerabilityIntelligence, VulnerabilityIntelligenceClient>();
        services.Replace(ServiceDescriptor.Singleton<IFindingEnricher, FindingEnrichmentService>());
        return services;
    }
}
