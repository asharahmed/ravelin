namespace Ravelin.Domain.Services;

using System.Text.RegularExpressions;

/// <summary>Extracts a canonical CVE id from a finding's vulnerability identifier. KEV and EPSS
/// intelligence are keyed by CVE, but a finding's id may be a CVE, a GHSA id, or contain one, so
/// enrichment only applies to findings whose id yields a CVE.</summary>
public static partial class CveIdentifier
{
    [GeneratedRegex(@"CVE-\d{4}-\d{4,}", RegexOptions.IgnoreCase)]
    private static partial Regex CvePattern();

    /// <summary>True when a CVE id can be read from <paramref name="vulnerabilityId"/>, returning
    /// it upper-cased (the canonical form used by the KEV catalog and EPSS API).</summary>
    public static bool TryExtract(string? vulnerabilityId, out string cve)
    {
        cve = string.Empty;
        if (string.IsNullOrWhiteSpace(vulnerabilityId))
        {
            return false;
        }

        var match = CvePattern().Match(vulnerabilityId);
        if (!match.Success)
        {
            return false;
        }

        cve = match.Value.ToUpperInvariant();
        return true;
    }
}
