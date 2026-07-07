using Ravelin.Domain.Services;

namespace Ravelin.Tests;

public class CveIdentifierTests
{
    [Theory]
    [InlineData("CVE-2021-44228", "CVE-2021-44228")]
    [InlineData("cve-2021-44228", "CVE-2021-44228")]   // normalized to upper
    [InlineData("CVE-2024-0001", "CVE-2024-0001")]
    [InlineData("CVE-2023-1234567", "CVE-2023-1234567")] // >4-digit sequence
    public void Extracts_and_normalizes_a_cve_id(string input, string expected)
    {
        Assert.True(CveIdentifier.TryExtract(input, out var cve));
        Assert.Equal(expected, cve);
    }

    [Theory]
    [InlineData("GHSA-7jgj-8wvc-jh57")]   // GHSA has no CVE — enrichment skips it
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-an-id")]
    public void Returns_false_when_no_cve_present(string? input)
    {
        Assert.False(CveIdentifier.TryExtract(input, out var cve));
        Assert.Equal(string.Empty, cve);
    }
}
