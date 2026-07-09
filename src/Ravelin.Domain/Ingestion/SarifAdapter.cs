namespace Ravelin.Domain.Ingestion;

using System.Globalization;
using System.Text.Json;
using Ravelin.Domain.Enums;

/// <summary>
/// Converts a SARIF 2.1.0 report (OASIS Static Analysis Results Interchange Format) into
/// <see cref="IncomingFinding"/>s. SARIF is the universal analysis format — CodeQL, Semgrep,
/// Trivy, Grype and many others emit it — so this one adapter lets Ravelin ingest almost any
/// scanner, and its own CI's SARIF.
/// <para>
/// SARIF describes code/config findings rather than package vulnerabilities, so the model is
/// mapped pragmatically: the finding identity is (ruleId, artifact file, line). Severity comes
/// from the CVSS-style <c>security-severity</c> property when present (as CodeQL emits), else the
/// SARIF result <c>level</c>. Throws <see cref="FormatException"/> when the payload isn't SARIF,
/// so a foreign document can't masquerade as a clean scan and auto-resolve everything.
/// </para>
/// </summary>
public static class SarifAdapter
{
    public static IReadOnlyList<IncomingFinding> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("runs", out var runs)
            || runs.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("Not a SARIF report (missing 'runs').");
        }

        var findings = new List<IncomingFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var run in runs.EnumerateArray())
        {
            var toolName = ToolName(run) ?? "sarif";
            var rules = IndexRules(run);

            if (!run.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var result in results.EnumerateArray())
            {
                var ruleId = RuleId(result);
                if (string.IsNullOrWhiteSpace(ruleId))
                {
                    continue; // no stable identity
                }

                var (uri, line) = FirstLocation(result);
                var component = uri ?? toolName;
                var version = line is int l ? $"L{l}" : "—";

                var message = MessageText(result) ?? ruleId;
                var cvss = SecuritySeverity(result, rules, ruleId);
                var severity = SeverityFrom(cvss, StrProp(result, "level"));

                var finding = new IncomingFinding
                {
                    VulnerabilityId = ruleId,
                    PackageName = component,
                    PackageVersion = version,
                    Title = Truncate($"{ruleId}: {message}", 490),
                    Description = message,
                    Severity = severity,
                    CvssScore = cvss,
                };

                if (seen.Add(finding.IdentityKey))
                {
                    findings.Add(finding);
                }
            }
        }

        return findings;
    }

    private static string? ToolName(JsonElement run) =>
        run.TryGetProperty("tool", out var tool) && tool.TryGetProperty("driver", out var driver)
            ? StrProp(driver, "name")
            : null;

    /// <summary>ruleId → rule element, for looking up rule-level metadata (security-severity).</summary>
    private static Dictionary<string, JsonElement> IndexRules(JsonElement run)
    {
        var map = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        if (run.TryGetProperty("tool", out var tool)
            && tool.TryGetProperty("driver", out var driver)
            && driver.TryGetProperty("rules", out var rules)
            && rules.ValueKind == JsonValueKind.Array)
        {
            foreach (var rule in rules.EnumerateArray())
            {
                var id = StrProp(rule, "id");
                if (id is not null)
                {
                    map[id] = rule;
                }
            }
        }
        return map;
    }

    private static string? RuleId(JsonElement result)
    {
        var id = StrProp(result, "ruleId");
        if (id is not null)
        {
            return id;
        }
        // Some tools nest it under "rule": { "id": "..." }.
        return result.TryGetProperty("rule", out var rule) ? StrProp(rule, "id") : null;
    }

    private static (string? Uri, int? Line) FirstLocation(JsonElement result)
    {
        if (!result.TryGetProperty("locations", out var locations)
            || locations.ValueKind != JsonValueKind.Array)
        {
            return (null, null);
        }

        foreach (var loc in locations.EnumerateArray())
        {
            if (!loc.TryGetProperty("physicalLocation", out var phys))
            {
                continue;
            }

            string? uri = phys.TryGetProperty("artifactLocation", out var art) ? StrProp(art, "uri") : null;
            int? line = phys.TryGetProperty("region", out var region)
                && region.TryGetProperty("startLine", out var sl) && sl.TryGetInt32(out var n)
                ? n
                : null;
            if (uri is not null || line is not null)
            {
                return (uri, line);
            }
        }
        return (null, null);
    }

    private static string? MessageText(JsonElement result) =>
        result.TryGetProperty("message", out var msg) ? StrProp(msg, "text") : null;

    /// <summary>CVSS-style score from the result's or rule's <c>security-severity</c> property
    /// (a 0–10 string, as CodeQL emits). Null when absent.</summary>
    private static double? SecuritySeverity(JsonElement result, Dictionary<string, JsonElement> rules, string ruleId)
    {
        var fromResult = SecuritySeverityOf(result);
        if (fromResult is not null)
        {
            return fromResult;
        }
        return rules.TryGetValue(ruleId, out var rule) ? SecuritySeverityOf(rule) : null;
    }

    private static double? SecuritySeverityOf(JsonElement element)
    {
        if (element.TryGetProperty("properties", out var props)
            && props.TryGetProperty("security-severity", out var sev))
        {
            var text = sev.ValueKind == JsonValueKind.String ? sev.GetString()
                : sev.ValueKind == JsonValueKind.Number ? sev.GetDouble().ToString(CultureInfo.InvariantCulture)
                : null;
            if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var score))
            {
                return score;
            }
        }
        return null;
    }

    /// <summary>CVSS band when a numeric score is present, else the SARIF level.</summary>
    private static Severity SeverityFrom(double? cvss, string? level)
    {
        if (cvss is double c)
        {
            return c >= 9.0 ? Severity.Critical
                : c >= 7.0 ? Severity.High
                : c >= 4.0 ? Severity.Medium
                : c > 0.0 ? Severity.Low
                : Severity.Unknown;
        }

        return level?.ToLowerInvariant() switch
        {
            "error" => Severity.High,
            "warning" => Severity.Medium,
            "note" => Severity.Low,
            _ => Severity.Unknown,
        };
    }

    private static string? StrProp(JsonElement element, string name) =>
        element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max];
}
