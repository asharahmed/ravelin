using Ravelin.Infrastructure.Services;

namespace Ravelin.Middleware;

/// <summary>
/// Captures unhandled exceptions at the request boundary into the AppError store (deduplicated,
/// secret-scrubbed), then rethrows so the normal error response is completely unchanged.
/// <para>
/// It sits BELOW the exception handler in the pipeline, so it sees the exception before the
/// handler turns it into a response. Capture is best-effort: <see cref="AppErrorService"/>
/// swallows its own failures, and this middleware always rethrows the original exception, so
/// recording a fault can never mask or alter the failure the user was already getting.
/// </para>
/// </summary>
public sealed class ErrorCaptureMiddleware(RequestDelegate next, AppErrorService errors)
{
    private const string CorrelationHeader = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            await errors.RecordAsync(new CapturedError
            {
                ExceptionType = ex.GetType().FullName ?? ex.GetType().Name,
                Message = ex.Message,
                StackTrace = ex.StackTrace,
                RequestMethod = context.Request.Method,
                RequestPath = context.Request.Path.Value, // path only — never the query string
                CorrelationId = context.Response.Headers.TryGetValue(CorrelationHeader, out var c)
                    ? c.ToString()
                    : null,
            });
            throw; // preserve the original response/behaviour
        }
    }
}
