using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Xunit;

namespace Ravelin.Tests;

public class GrypeAdapterTests
{
    private const string Report = """
    {
      "matches": [
        {
          "vulnerability": {
            "id": "CVE-2021-23337",
            "severity": "High",
            "description": "lodash command injection via template settings allows code execution.",
            "fix": { "versions": ["4.17.21"], "state": "fixed" },
            "cvss": [
              { "version": "2.0", "metrics": { "baseScore": 5.8 } },
              { "version": "3.1", "metrics": { "baseScore": 7.2 } }
            ]
          },
          "artifact": { "name": "lodash", "version": "4.17.20", "type": "npm" }
        },
        {
          "vulnerability": { "id": "GHSA-xxxx", "severity": "Negligible", "description": "Minor issue." },
          "artifact": { "name": "left-pad", "version": "1.0.0", "type": "npm" }
        },
        {
          "vulnerability": { "id": "CVE-NOART", "severity": "High" },
          "artifact": { "name": "x" }
        }
      ]
    }
    """;

    [Fact]
    public void Maps_matches_and_skips_incomplete()
    {
        var findings = GrypeAdapter.Parse(Report);

        // Third match has no artifact.version -> skipped.
        Assert.Equal(2, findings.Count);

        var first = findings[0];
        Assert.Equal("CVE-2021-23337", first.VulnerabilityId);
        Assert.Equal("lodash", first.PackageName);
        Assert.Equal("4.17.20", first.PackageVersion);
        Assert.Equal("4.17.21", first.FixedVersion);
        Assert.Equal(Severity.High, first.Severity);
        Assert.Equal(7.2, first.CvssScore);                     // highest base score across entries
        Assert.StartsWith("lodash command injection", first.Title);
    }

    [Fact]
    public void Negligible_maps_to_low_with_no_fix_or_score()
    {
        var second = GrypeAdapter.Parse(Report)[1];

        Assert.Equal(Severity.Low, second.Severity);
        Assert.Null(second.FixedVersion);
        Assert.Null(second.CvssScore);
    }

    [Fact]
    public void Throws_when_not_a_grype_report()
    {
        Assert.Throws<FormatException>(() => GrypeAdapter.Parse("""{ "Results": [] }"""));
    }
}
