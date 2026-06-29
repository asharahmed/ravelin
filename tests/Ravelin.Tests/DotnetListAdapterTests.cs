using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Xunit;

namespace Ravelin.Tests;

public class DotnetListAdapterTests
{
    // Real output captured from `dotnet list package --vulnerable --include-transitive --format
    // json` (SDK 10.0.301): a top-level vuln, a transitive vuln, and a "Moderate" severity.
    private const string Report = """
    {
      "version": 1,
      "parameters": "--vulnerable --include-transitive",
      "sources": [ "https://api.nuget.org/v3/index.json" ],
      "projects": [
        {
          "path": "/repo/src/Ravelin/Ravelin.csproj",
          "frameworks": [
            {
              "framework": "net10.0",
              "topLevelPackages": [
                {
                  "id": "Newtonsoft.Json",
                  "requestedVersion": "12.0.1",
                  "resolvedVersion": "12.0.1",
                  "vulnerabilities": [
                    { "severity": "High", "advisoryurl": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr" }
                  ]
                }
              ],
              "transitivePackages": [
                {
                  "id": "System.Net.Http",
                  "resolvedVersion": "4.3.0",
                  "vulnerabilities": [
                    { "severity": "Moderate", "advisoryurl": "https://github.com/advisories/GHSA-7jgj-8wvc-jh57" }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    [Fact]
    public void Parse_maps_top_level_and_transitive_vulnerabilities()
    {
        var findings = DotnetListAdapter.Parse(Report);

        Assert.Equal(2, findings.Count);

        var top = Assert.Single(findings, f => f.PackageName == "Newtonsoft.Json");
        Assert.Equal("GHSA-5crp-9r3c-p9vr", top.VulnerabilityId);
        Assert.Equal("12.0.1", top.PackageVersion);
        Assert.Equal(Severity.High, top.Severity);
        Assert.Equal("https://github.com/advisories/GHSA-5crp-9r3c-p9vr", top.Description);

        var transitive = Assert.Single(findings, f => f.PackageName == "System.Net.Http");
        Assert.Equal("GHSA-7jgj-8wvc-jh57", transitive.VulnerabilityId);
        Assert.Equal("4.3.0", transitive.PackageVersion);
    }

    [Fact]
    public void Parse_maps_moderate_to_medium()
    {
        var medium = Assert.Single(DotnetListAdapter.Parse(Report), f => f.PackageName == "System.Net.Http");
        Assert.Equal(Severity.Medium, medium.Severity);
    }

    [Fact]
    public void Parse_clean_report_without_frameworks_yields_no_findings()
    {
        // A clean scan omits "frameworks" entirely — this is the captured no-vulnerabilities shape.
        const string clean = """
        {
          "version": 1,
          "parameters": "--vulnerable --include-transitive",
          "projects": [ { "path": "/repo/src/Ravelin/Ravelin.csproj" } ]
        }
        """;

        Assert.Empty(DotnetListAdapter.Parse(clean));
    }

    [Fact]
    public void Parse_deduplicates_the_same_vuln_across_projects()
    {
        // The same transitive advisory surfaces under two projects of a solution scan.
        const string solution = """
        {
          "projects": [
            {
              "path": "/repo/src/A/A.csproj",
              "frameworks": [ { "framework": "net10.0", "transitivePackages": [
                { "id": "System.Net.Http", "resolvedVersion": "4.3.0", "vulnerabilities": [
                  { "severity": "Moderate", "advisoryurl": "https://github.com/advisories/GHSA-7jgj-8wvc-jh57" } ] } ] } ]
            },
            {
              "path": "/repo/src/B/B.csproj",
              "frameworks": [ { "framework": "net10.0", "transitivePackages": [
                { "id": "System.Net.Http", "resolvedVersion": "4.3.0", "vulnerabilities": [
                  { "severity": "Moderate", "advisoryurl": "https://github.com/advisories/GHSA-7jgj-8wvc-jh57" } ] } ] } ]
            }
          ]
        }
        """;

        Assert.Single(DotnetListAdapter.Parse(solution));
    }

    [Fact]
    public void Parse_skips_vulnerabilities_without_an_advisory_url()
    {
        const string noAdvisory = """
        {
          "projects": [ { "path": "/repo/x.csproj", "frameworks": [ { "framework": "net10.0",
            "topLevelPackages": [ { "id": "Foo", "resolvedVersion": "1.0.0",
              "vulnerabilities": [ { "severity": "High" } ] } ] } ] } ]
        }
        """;

        Assert.Empty(DotnetListAdapter.Parse(noAdvisory));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{ "version": 1 }""")]
    [InlineData("""{ "Results": [] }""")]
    public void Parse_throws_when_not_a_dotnet_list_report(string json)
    {
        // Guard: a foreign/malformed payload must not look like a clean scan (which would
        // auto-resolve every open finding).
        Assert.Throws<FormatException>(() => DotnetListAdapter.Parse(json));
    }
}
