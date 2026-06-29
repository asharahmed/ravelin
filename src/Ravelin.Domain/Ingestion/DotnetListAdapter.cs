namespace Ravelin.Domain.Ingestion;

using System.Text.Json;

/// <summary>
/// Converts the JSON from <c>dotnet list package --vulnerable --include-transitive --format
/// json</c> into <see cref="IncomingFinding"/>s, so Ravelin's own pipeline can push the app's
/// NuGet dependency vulnerabilities straight to <c>/api/ingest/dotnet</c> — the "eats its own
/// dog food" loop where the tool tracks remediation SLAs against itself.
/// <para>
/// The report carries only a <c>severity</c> and an <c>advisoryurl</c> per vulnerability (no
/// CVSS, description, or fix version). The GHSA/CVE id at the end of the advisory URL is used
/// as the stable vulnerability identity. NuGet/GitHub use "Critical/High/Moderate/Low" — the
/// "Moderate" wording is handled by <see cref="SeverityMap"/>.
/// </para>
/// </summary>
public static class DotnetListAdapter
{
    /// <summary>Maps a <c>dotnet list package</c> report. Throws <see cref="FormatException"/> if
    /// it isn't one (no <c>projects</c> array), so a malformed payload can't be mistaken for a
    /// clean scan and silently auto-resolve everything. A report with no vulnerable packages
    /// (the <c>frameworks</c> key is omitted) correctly maps to zero findings.</summary>
    public static IReadOnlyList<IncomingFinding> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("projects", out var projects)
            || projects.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("Not a 'dotnet list package' JSON report (missing 'projects').");
        }

        var findings = new List<IncomingFinding>();
        // The same transitive vuln surfaces under several projects/frameworks across a solution;
        // collapse to one finding per (advisory, package, version) so dedup identity is stable.
        var seen = new HashSet<string>();

        foreach (var project in projects.EnumerateArray())
        {
            // A project with no vulnerabilities omits "frameworks" entirely — nothing to map.
            if (!project.TryGetProperty("frameworks", out var frameworks)
                || frameworks.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var framework in frameworks.EnumerateArray())
            {
                AddPackages(framework, "topLevelPackages", findings, seen);
                AddPackages(framework, "transitivePackages", findings, seen);
            }
        }

        return findings;
    }

    private static void AddPackages(
        JsonElement framework, string arrayName, List<IncomingFinding> findings, HashSet<string> seen)
    {
        if (!framework.TryGetProperty(arrayName, out var packages) || packages.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var pkg in packages.EnumerateArray())
        {
            if (!pkg.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            {
                continue; // a package with no advisories
            }

            var name = ScanJson.Str(pkg, "id");
            var version = ScanJson.Str(pkg, "resolvedVersion");
            if (name is null || version is null)
            {
                continue; // can't dedup without a stable identity
            }

            foreach (var v in vulns.EnumerateArray())
            {
                var advisoryUrl = ScanJson.Str(v, "advisoryurl");
                var id = AdvisoryId(advisoryUrl);
                if (id is null)
                {
                    continue; // no advisory id -> no stable identity
                }

                var finding = new IncomingFinding
                {
                    VulnerabilityId = id,
                    PackageName = name,
                    PackageVersion = version,
                    Title = $"{id} in {name} {version}",
                    Description = advisoryUrl,
                    Severity = SeverityMap.Parse(ScanJson.Str(v, "severity")),
                };

                if (seen.Add(finding.IdentityKey))
                {
                    findings.Add(finding);
                }
            }
        }
    }

    /// <summary>The advisory URL ends in the GHSA/CVE id (e.g. <c>.../advisories/GHSA-xxxx</c>);
    /// take that last path segment as the stable vulnerability identity, falling back to the
    /// whole URL when there's no usable segment.</summary>
    private static string? AdvisoryId(string? advisoryUrl)
    {
        if (string.IsNullOrWhiteSpace(advisoryUrl))
        {
            return null;
        }

        var trimmed = advisoryUrl.TrimEnd('/');
        var slash = trimmed.LastIndexOf('/');
        return slash >= 0 && slash < trimmed.Length - 1 ? trimmed[(slash + 1)..] : trimmed;
    }
}
