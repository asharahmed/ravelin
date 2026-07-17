using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;
using Ravelin.Infrastructure;

namespace Ravelin.Auth;

/// <summary>
/// Seeds realistic, back-dated demo data so the public dashboard shows a genuine posture
/// (breaches, due-soon, resolved-over-time trend) rather than an empty 100%. Gated by
/// <c>Seed:DemoData=true</c> and idempotent: a demo project is created only if its key is
/// absent, so restarts never duplicate. Findings are back-dated relative to "now" at seed
/// time, with SLA deadlines computed from the active policy.
/// </summary>
public static class DemoDataSeeder
{
    private sealed record FindingSpec(
        string Vuln, string Package, string Version, string Title, Severity Severity,
        int DetectedDaysAgo, FindingStatus Status = FindingStatus.Open,
        int? ResolvedDaysAgo = null, string? FixedVersion = null, double? Cvss = null,
        string? TriageNote = null);

    private sealed record ProjectSpec(string Key, string Name, string Repo, FindingSpec[] Findings);

    public static async Task SeedAsync(IServiceProvider services, IConfiguration config)
    {
        if (!config.GetValue<bool>("Seed:DemoData"))
        {
            return;
        }

        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RavelinDbContext>();

        var slaDays = await db.SlaPolicies.AnyAsync()
            ? await db.SlaPolicies.ToDictionaryAsync(p => p.Severity, p => p.RemediationDays)
            : SlaPolicy.Defaults.ToDictionary(p => p.Severity, p => p.RemediationDays);

        var now = DateTimeOffset.UtcNow;

        foreach (var spec in Catalogue)
        {
            var existing = await db.Projects.FirstOrDefaultAsync(p => p.Key == spec.Key);
            if (existing is not null)
            {
                // Demo projects are public so any self-registered Viewer sees the showcase.
                // Flip already-seeded projects too (they predate per-project authorization).
                if (!existing.IsPublic)
                {
                    existing.IsPublic = true;
                    await db.SaveChangesAsync();
                }
                continue;
            }

            var project = new Project { Key = spec.Key, Name = spec.Name, RepositoryUrl = spec.Repo, IsPublic = true };
            db.Projects.Add(project);

            foreach (var f in spec.Findings)
            {
                var detected = now.AddDays(-f.DetectedDaysAgo);
                var resolvedAt = f.ResolvedDaysAgo is int r ? now.AddDays(-r) : (DateTimeOffset?)null;

                db.Findings.Add(new Finding
                {
                    ProjectId = project.Id,
                    VulnerabilityId = f.Vuln,
                    PackageName = f.Package,
                    PackageVersion = f.Version,
                    Title = f.Title,
                    Severity = f.Severity,
                    CvssScore = f.Cvss,
                    FixedVersion = f.FixedVersion,
                    Status = f.Status,
                    FirstDetectedAt = detected,
                    LastSeenAt = resolvedAt ?? now,
                    ResolvedAt = resolvedAt,
                    SlaDueAt = SlaEvaluator.ComputeDueDate(detected, f.Severity, slaDays),
                    TriageNote = f.TriageNote,
                });
            }

            db.Scans.Add(new Scan
            {
                ProjectId = project.Id,
                Tool = "Trivy",
                ToolVersion = "0.52.0",
                Source = ScanSource.PipelinePush,
                IngestedAt = now.AddHours(-3),
                ReportedFindingCount = spec.Findings.Count(f => f.Status == FindingStatus.Open),
            });
        }

        await db.SaveChangesAsync();
    }

    // Curated to exercise every SLA state, severity, and the 8-week trend.
    private static readonly ProjectSpec[] Catalogue =
    [
        new("checkout-api", "Checkout API", "https://github.com/acme/checkout-api",
        [
            new("CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1",
                "Log4Shell remote code execution via JNDI lookup", Severity.Critical,
                DetectedDaysAgo: 21, FixedVersion: "2.17.1", Cvss: 10.0),               // breached
            new("CVE-2022-22965", "org.springframework:spring-beans", "5.3.17",
                "Spring4Shell RCE via data binding", Severity.Critical,
                DetectedDaysAgo: 4, FixedVersion: "5.3.18", Cvss: 9.8),                 // due soon
            new("CVE-2023-20860", "org.springframework:spring-web", "5.3.25",
                "Security bypass with un-prefixed double wildcard pattern", Severity.High,
                DetectedDaysAgo: 12, FixedVersion: "5.3.26", Cvss: 7.5),                // on track
            new("CVE-2020-8908", "com.google.guava:guava", "29.0",
                "Local information disclosure via temporary directory", Severity.Low,
                DetectedDaysAgo: 40, FixedVersion: "32.0.0", Cvss: 3.3),               // on track
            new("CVE-2022-42003", "com.fasterxml.jackson.core:jackson-databind", "2.13.3",
                "Deep wrapper array nesting denial of service", Severity.High,
                DetectedDaysAgo: 33, Status: FindingStatus.Resolved, ResolvedDaysAgo: 2,
                FixedVersion: "2.13.4", Cvss: 7.5),                                     // resolved (trend)
        ]),

        new("payments-gateway", "Payments Gateway", "https://github.com/acme/payments-gateway",
        [
            new("CVE-2023-44487", "io.netty:netty-codec-http2", "4.1.96.Final",
                "HTTP/2 rapid reset denial of service", Severity.High,
                DetectedDaysAgo: 38, FixedVersion: "4.1.100.Final", Cvss: 7.5),         // breached
            new("CVE-2024-29025", "io.netty:netty-codec-http", "4.1.107.Final",
                "Allocation of resources without limits in multipart decoder", Severity.Medium,
                DetectedDaysAgo: 6, FixedVersion: "4.1.108.Final", Cvss: 5.3),          // on track
            new("CVE-2023-2976", "com.google.guava:guava", "30.1-jre",
                "Insecure temp file creation in FileBackedOutputStream", Severity.Medium,
                DetectedDaysAgo: 88, FixedVersion: "32.0.0-jre", Cvss: 5.5),            // due soon (90d SLA)
            new("CVE-2022-1471", "org.yaml:snakeyaml", "1.30",
                "Deserialization of untrusted data via SnakeYAML Constructor", Severity.Critical,
                DetectedDaysAgo: 51, Status: FindingStatus.Resolved, ResolvedDaysAgo: 9,
                FixedVersion: "2.0", Cvss: 9.8),                                        // resolved (trend)
        ]),

        new("web-storefront", "Web Storefront", "https://github.com/acme/web-storefront",
        [
            new("CVE-2021-23337", "lodash", "4.17.20",
                "Command injection via template", Severity.High,
                DetectedDaysAgo: 45, FixedVersion: "4.17.21", Cvss: 7.2),               // breached
            new("CVE-2024-4068", "braces", "3.0.2",
                "Uncontrolled resource consumption", Severity.Medium,
                DetectedDaysAgo: 15, FixedVersion: "3.0.3", Cvss: 5.3),                 // on track
            new("CVE-2022-25883", "semver", "7.3.5",
                "Regular expression denial of service", Severity.Medium,
                DetectedDaysAgo: 70, Status: FindingStatus.AcceptedRisk,
                FixedVersion: "7.5.2", Cvss: 5.3,
                TriageNote: "Server-side only; semver input is from trusted build metadata."),
            new("CVE-2020-28469", "glob-parent", "5.1.1",
                "Regular expression denial of service", Severity.Low,
                DetectedDaysAgo: 60, Status: FindingStatus.FalsePositive,
                FixedVersion: "5.1.2", Cvss: 5.3,
                TriageNote: "Transitive dev-only dependency; not shipped to production."),
            new("CVE-2023-26115", "word-wrap", "1.2.3",
                "Regular expression denial of service", Severity.Medium,
                DetectedDaysAgo: 30, Status: FindingStatus.Resolved, ResolvedDaysAgo: 16,
                FixedVersion: "1.2.4", Cvss: 5.3),                                       // resolved (trend)
        ]),

        new("internal-tools", "Internal Tools", "https://github.com/acme/internal-tools",
        [
            new("CVE-2024-21626", "runc", "1.1.11",
                "Container breakout via leaked file descriptor", Severity.High,
                DetectedDaysAgo: 9, FixedVersion: "1.1.12", Cvss: 8.6),                 // on track
            new("CVE-2023-39325", "golang.org/x/net", "0.10.0",
                "HTTP/2 rapid reset in net/http", Severity.Medium,
                DetectedDaysAgo: 22, FixedVersion: "0.17.0", Cvss: 5.3),                // on track
        ]),
    ];
}
