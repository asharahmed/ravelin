using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Xunit;

namespace Ravelin.Tests;

public class TrivyAdapterTests
{
    private const string Report = """
    {
      "SchemaVersion": 2,
      "Results": [
        {
          "Target": "package-lock.json",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2021-23337",
              "PkgName": "lodash",
              "InstalledVersion": "4.17.20",
              "FixedVersion": "4.17.21",
              "Title": "lodash: command injection via template",
              "Description": "lodash prior to 4.17.21 is vulnerable to command injection.",
              "Severity": "HIGH",
              "CVSS": { "nvd": { "V3Score": 7.2 }, "redhat": { "V3Score": 6.3 } }
            },
            {
              "VulnerabilityID": "CVE-2020-8203",
              "PkgName": "lodash",
              "InstalledVersion": "4.17.20",
              "Description": "Prototype pollution in lodash.",
              "Severity": "critical",
              "CVSS": { "nvd": { "V2Score": 5.8 } }
            },
            {
              "VulnerabilityID": "CVE-MISSING-PKG",
              "InstalledVersion": "1.0.0",
              "Severity": "LOW"
            }
          ]
        },
        { "Target": "Dockerfile", "Class": "config" }
      ]
    }
    """;

    [Fact]
    public void Maps_vulnerabilities_and_skips_incomplete()
    {
        var findings = TrivyAdapter.Parse(Report);

        // Third vuln (no PkgName) skipped; second Result (no Vulnerabilities) skipped.
        Assert.Equal(2, findings.Count);

        var first = findings[0];
        Assert.Equal("CVE-2021-23337", first.VulnerabilityId);
        Assert.Equal("lodash", first.PackageName);
        Assert.Equal("4.17.20", first.PackageVersion);
        Assert.Equal("4.17.21", first.FixedVersion);
        Assert.Equal(Severity.High, first.Severity);
        Assert.Equal(7.2, first.CvssScore);   // prefers a V3 score
        Assert.Equal("lodash: command injection via template", first.Title);
    }

    [Fact]
    public void Falls_back_to_description_and_v2_score()
    {
        var second = TrivyAdapter.Parse(Report)[1];

        Assert.Equal(Severity.Critical, second.Severity);          // lowercase "critical"
        Assert.Equal(5.8, second.CvssScore);                       // V2 fallback when no V3
        Assert.StartsWith("Prototype pollution", second.Title);    // title falls back to description
    }

    [Fact]
    public void Throws_when_not_a_trivy_report()
    {
        Assert.Throws<FormatException>(() => TrivyAdapter.Parse("""{ "matches": [] }"""));
    }

    [Fact]
    public void Empty_report_maps_to_no_findings()
    {
        Assert.Empty(TrivyAdapter.Parse("""{ "Results": [] }"""));
    }
}
