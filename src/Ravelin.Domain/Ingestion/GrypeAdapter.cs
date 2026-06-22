namespace Ravelin.Domain.Ingestion;

using System.Text.Json;

/// <summary>
/// Converts native Grype JSON (<c>grype ... -o json</c>) into Ravelin's
/// <see cref="IncomingFinding"/> shape, so a pipeline can pipe Grype output straight to
/// <c>/api/ingest/grype</c>.
/// </summary>
public static class GrypeAdapter
{
    /// <summary>Maps a Grype report. Throws <see cref="FormatException"/> if it isn't a Grype
    /// report (no <c>matches</c>). A present-but-empty report maps to zero findings.</summary>
    public static IReadOnlyList<IncomingFinding> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("matches", out var matches))
        {
            throw new FormatException("Not a Grype JSON report (missing 'matches').");
        }

        var findings = new List<IncomingFinding>();
        if (matches.ValueKind != JsonValueKind.Array)
        {
            return findings;
        }

        foreach (var match in matches.EnumerateArray())
        {
            if (!match.TryGetProperty("vulnerability", out var vuln) || vuln.ValueKind != JsonValueKind.Object ||
                !match.TryGetProperty("artifact", out var artifact) || artifact.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var id = ScanJson.Str(vuln, "id");
            var pkg = ScanJson.Str(artifact, "name");
            var version = ScanJson.Str(artifact, "version");
            if (id is null || pkg is null || version is null)
            {
                continue;
            }

            var description = ScanJson.Str(vuln, "description");
            findings.Add(new IncomingFinding
            {
                VulnerabilityId = id,
                PackageName = pkg,
                PackageVersion = version,
                Title = ScanJson.FirstNonEmpty(ScanJson.Truncate(description, 140), null, id),
                Description = description,
                Severity = SeverityMap.Parse(ScanJson.Str(vuln, "severity")),
                CvssScore = Cvss(vuln),
                FixedVersion = Fix(vuln),
            });
        }

        return findings;
    }

    // Grype lists CVSS entries (v2 + v3); take the highest base score.
    private static double? Cvss(JsonElement vuln)
    {
        if (!vuln.TryGetProperty("cvss", out var cvss) || cvss.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        double? best = null;
        foreach (var entry in cvss.EnumerateArray())
        {
            if (entry.TryGetProperty("metrics", out var metrics) &&
                metrics.TryGetProperty("baseScore", out var score) &&
                score.ValueKind == JsonValueKind.Number)
            {
                var value = score.GetDouble();
                if (best is null || value > best) best = value;
            }
        }
        return best;
    }

    private static string? Fix(JsonElement vuln)
    {
        if (vuln.TryGetProperty("fix", out var fix) && fix.ValueKind == JsonValueKind.Object &&
            fix.TryGetProperty("versions", out var versions) && versions.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in versions.EnumerateArray())
            {
                if (v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()))
                {
                    return v.GetString();
                }
            }
        }
        return null;
    }
}
