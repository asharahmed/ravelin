namespace Ravelin.Domain.Ingestion;

using System.Text.Json;

/// <summary>
/// Converts native Trivy JSON (<c>trivy ... --format json</c>) into Ravelin's
/// <see cref="IncomingFinding"/> shape, so a pipeline can pipe Trivy output straight to
/// <c>/api/ingest/trivy</c> without a transform step.
/// </summary>
public static class TrivyAdapter
{
    /// <summary>Maps a Trivy report. Throws <see cref="FormatException"/> if it isn't a Trivy
    /// report (no <c>Results</c>), so a malformed payload can't be mistaken for a clean scan
    /// and silently auto-resolve everything. A present-but-empty report maps to zero findings.</summary>
    public static IReadOnlyList<IncomingFinding> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("Results", out var results))
        {
            throw new FormatException("Not a Trivy JSON report (missing 'Results').");
        }

        var findings = new List<IncomingFinding>();
        if (results.ValueKind != JsonValueKind.Array)
        {
            return findings;
        }

        foreach (var result in results.EnumerateArray())
        {
            if (!result.TryGetProperty("Vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            {
                continue; // a Result with no vulnerabilities (e.g. a clean target)
            }

            foreach (var v in vulns.EnumerateArray())
            {
                var id = ScanJson.Str(v, "VulnerabilityID");
                var pkg = ScanJson.Str(v, "PkgName");
                var version = ScanJson.Str(v, "InstalledVersion");
                if (id is null || pkg is null || version is null)
                {
                    continue; // can't dedup without a stable identity
                }

                var description = ScanJson.Str(v, "Description");
                findings.Add(new IncomingFinding
                {
                    VulnerabilityId = id,
                    PackageName = pkg,
                    PackageVersion = version,
                    Title = ScanJson.FirstNonEmpty(ScanJson.Str(v, "Title"), ScanJson.Truncate(description, 140), id),
                    Description = description,
                    Severity = SeverityMap.Parse(ScanJson.Str(v, "Severity")),
                    CvssScore = Cvss(v),
                    FixedVersion = ScanJson.Str(v, "FixedVersion"),
                });
            }
        }

        return findings;
    }

    // Trivy nests CVSS by source ("nvd", "redhat", …). Prefer any V3 base score; fall back to V2.
    private static double? Cvss(JsonElement vuln)
    {
        if (!vuln.TryGetProperty("CVSS", out var cvss) || cvss.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        double? v2 = null;
        foreach (var source in cvss.EnumerateObject())
        {
            if (source.Value.ValueKind != JsonValueKind.Object) continue;
            if (source.Value.TryGetProperty("V3Score", out var s3) && s3.ValueKind == JsonValueKind.Number)
            {
                return s3.GetDouble();
            }
            if (v2 is null && source.Value.TryGetProperty("V2Score", out var s2) && s2.ValueKind == JsonValueKind.Number)
            {
                v2 = s2.GetDouble();
            }
        }
        return v2;
    }
}
