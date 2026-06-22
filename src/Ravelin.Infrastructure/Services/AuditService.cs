using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Records audit-trail events in their own DB scope, isolated from the request's unit of work.
/// Failures NEVER propagate: if the write fails (e.g. the table isn't present yet) the user
/// action is unaffected — the failure is logged and dropped. The audit log is best-effort.
/// </summary>
public sealed class AuditService(IServiceScopeFactory scopeFactory, ILogger<AuditService> logger)
{
    public async Task RecordAsync(string actor, string action, string? target = null, string? detail = null)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();
            db.AuditEvents.Add(new AuditEvent
            {
                Actor = Clip(actor, 256) ?? "system",
                Action = Clip(action, 64) ?? "unknown",
                Target = Clip(target, 256),
                Detail = Clip(detail, 1024),
            });
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Audit write failed for action {Action}; continuing.", action);
        }
    }

    private static string? Clip(string? s, int max) =>
        string.IsNullOrWhiteSpace(s) ? null : (s.Length <= max ? s : s[..max]);
}
