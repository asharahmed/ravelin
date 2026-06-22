using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Posts new SLA alerts to a project's outbound webhook — a generic JSON payload, or a
/// Slack-compatible message when the URL is a Slack incoming webhook. Failures are logged and
/// swallowed (a flaky webhook must never break ingestion or the re-evaluation pass).
/// Admin-supplied URLs are validated (https-only, internal ranges blocked) as SSRF defence.
/// </summary>
public sealed class NotificationService(IHttpClientFactory httpFactory, ILogger<NotificationService> logger)
{
    public readonly record struct AlertLine(string VulnerabilityId, string Severity, string State, int? DaysOverdue);

    public async Task<(bool ok, int? status, string? error)> SendAsync(
        string url, string projectName, IReadOnlyList<AlertLine> alerts, CancellationToken ct = default)
    {
        if (!IsSafeUrl(url, out var urlError))
        {
            return (false, null, urlError);
        }

        var client = httpFactory.CreateClient("webhooks");
        object payload = IsSlack(url) ? BuildSlack(projectName, alerts) : BuildGeneric(projectName, alerts);

        try
        {
            var resp = await client.PostAsJsonAsync(url, payload, ct);
            var status = (int)resp.StatusCode;
            return resp.IsSuccessStatusCode ? (true, status, null) : (false, status, $"HTTP {status}");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Webhook POST to {Host} failed", HostOf(url));
            return (false, null, ex.Message);
        }
    }

    private static bool IsSlack(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) &&
        u.Host.Equals("hooks.slack.com", StringComparison.OrdinalIgnoreCase);

    private static object BuildGeneric(string projectName, IReadOnlyList<AlertLine> alerts) => new
    {
        source = "ravelin",
        project = projectName,
        alerts = alerts.Select(a => new
        {
            vulnerabilityId = a.VulnerabilityId,
            severity = a.Severity,
            state = a.State,
            daysOverdue = a.DaysOverdue,
        }),
    };

    private static object BuildSlack(string projectName, IReadOnlyList<AlertLine> alerts)
    {
        var lines = alerts.Select(a =>
            $"• *{a.State}* — {a.VulnerabilityId} ({a.Severity})"
            + (a.DaysOverdue is int d ? $", {d}d overdue" : ""));
        var text = $":rotating_light: *Ravelin* — {alerts.Count} new SLA alert"
                   + (alerts.Count == 1 ? "" : "s") + $" for *{projectName}*\n" + string.Join("\n", lines);
        return new { text };
    }

    /// <summary>Public validation used by the admin webhook-config endpoint.</summary>
    public static bool IsValidWebhookUrl(string url, out string? error) => IsSafeUrl(url, out error);

    /// <summary>https only, and no obvious internal targets (loopback, RFC1918, link-local,
    /// cloud metadata). Admins are trusted in single-tenant, but this is cheap defence-in-depth.</summary>
    private static bool IsSafeUrl(string url, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            error = "Enter a valid absolute URL."; return false;
        }
        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            error = "Webhook URL must use https."; return false;
        }

        var host = uri.Host;
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("metadata", StringComparison.OrdinalIgnoreCase) ||
            host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase))
        {
            error = "Webhook URL must not target an internal host."; return false;
        }
        if (IPAddress.TryParse(host, out var ip) && (IPAddress.IsLoopback(ip) || IsPrivate(ip)))
        {
            error = "Webhook URL must not target an internal address."; return false;
        }
        return true;
    }

    private static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
        var b = ip.GetAddressBytes();
        return b[0] == 10                                   // 10.0.0.0/8
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)    // 172.16.0.0/12
            || (b[0] == 192 && b[1] == 168)                 // 192.168.0.0/16
            || (b[0] == 169 && b[1] == 254);                // 169.254.0.0/16 (link-local / metadata)
    }

    private static string HostOf(string url) => Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : "?";
}
