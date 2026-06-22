using System.Diagnostics;

namespace Ravelin.Middleware;

/// <summary>
/// Tags each request with a correlation id (honouring an inbound <c>X-Correlation-ID</c> or
/// generating one), pushes it into the logging scope, echoes it on the response, and logs a
/// single structured line per request (method, path, status, elapsed). Lightweight — no
/// external dependency; logs flow to the Container App's Log Analytics workspace.
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    private const string HeaderName = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers.TryGetValue(HeaderName, out var inbound)
            && !string.IsNullOrWhiteSpace(inbound)
            ? inbound.ToString()
            : Guid.NewGuid().ToString("N")[..12];

        context.Response.Headers[HeaderName] = correlationId;

        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationId,
        });

        var sw = Stopwatch.StartNew();
        try
        {
            await next(context);
        }
        finally
        {
            sw.Stop();
            // Skip noisy static-asset/framework requests; log API + page navigations.
            var path = context.Request.Path.Value ?? "";
            if (!path.StartsWith("/_framework", StringComparison.Ordinal)
                && !path.Contains('.', StringComparison.Ordinal))
            {
                logger.LogInformation("{Method} {Path} -> {Status} in {Elapsed}ms",
                    context.Request.Method, path, context.Response.StatusCode, sw.ElapsedMilliseconds);
            }
        }
    }
}
