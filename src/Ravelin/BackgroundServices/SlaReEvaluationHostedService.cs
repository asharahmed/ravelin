using Ravelin.Infrastructure.Services;

namespace Ravelin.BackgroundServices;

/// <summary>
/// Runs the SLA re-evaluation hourly so breaches surface — and notify — without anyone loading a
/// page. NOTE: an in-process timer only runs while the app is running, so the Container App must
/// keep at least one replica (min_replicas >= 1 in Terraform). Admins can also trigger a pass
/// on demand via POST /api/admin/alerts/reevaluate.
/// </summary>
public sealed class SlaReEvaluationHostedService(
    SlaReEvaluator reEvaluator, ILogger<SlaReEvaluationHostedService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // A short delay so the first pass doesn't pile onto cold-start.
            await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);

            using var timer = new PeriodicTimer(Interval);
            do
            {
                try
                {
                    var result = await reEvaluator.ReEvaluateAsync(stoppingToken);
                    logger.LogInformation(
                        "Hourly SLA re-eval: scanned {Scanned}, +{Breached} breached, +{DueSoon} due-soon, {Notified} notified",
                        result.Scanned, result.NewBreached, result.NewDueSoon, result.Notified);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    logger.LogError(ex, "SLA re-evaluation pass failed; will retry next interval.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
            // Application is shutting down — nothing to do.
        }
    }
}
