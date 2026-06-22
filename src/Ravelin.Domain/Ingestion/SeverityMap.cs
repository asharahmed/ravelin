namespace Ravelin.Domain.Ingestion;

using Ravelin.Domain.Enums;

/// <summary>
/// Maps the severity vocabularies of different scanners to Ravelin's <see cref="Severity"/>.
/// Trivy uses CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN; Grype adds "Negligible"; Red Hat advisories
/// use "Important"/"Moderate". Anything unrecognised is <see cref="Severity.Unknown"/>.
/// </summary>
public static class SeverityMap
{
    public static Severity Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" or "important" => Severity.High,
        "medium" or "moderate" => Severity.Medium,
        "low" or "minor" or "negligible" => Severity.Low,
        _ => Severity.Unknown,
    };
}
