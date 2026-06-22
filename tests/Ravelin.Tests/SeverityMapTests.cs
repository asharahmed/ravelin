using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Xunit;

namespace Ravelin.Tests;

public class SeverityMapTests
{
    [Theory]
    // Trivy (uppercase) + canonical
    [InlineData("CRITICAL", Severity.Critical)]
    [InlineData("critical", Severity.Critical)]
    [InlineData("HIGH", Severity.High)]
    [InlineData("Medium", Severity.Medium)]
    [InlineData("LOW", Severity.Low)]
    // Grype adds "Negligible"
    [InlineData("Negligible", Severity.Low)]
    // Red Hat advisory vocabulary
    [InlineData("Important", Severity.High)]
    [InlineData("Moderate", Severity.Medium)]
    [InlineData("Minor", Severity.Low)]
    // Whitespace is tolerated
    [InlineData("  High  ", Severity.High)]
    // Unknown / unmapped / empty fall back
    [InlineData("UNKNOWN", Severity.Unknown)]
    [InlineData("none", Severity.Unknown)]
    [InlineData("", Severity.Unknown)]
    [InlineData(null, Severity.Unknown)]
    public void Parse_maps_scanner_vocabularies_to_severity(string? input, Severity expected)
    {
        Assert.Equal(expected, SeverityMap.Parse(input));
    }
}
