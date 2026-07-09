using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;

namespace Ravelin.Tests;

public class SarifAdapterTests
{
    // CodeQL-style: severity comes from the CVSS-like security-severity property.
    private const string CodeQlSarif = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": { "driver": { "name": "CodeQL", "rules": [
            { "id": "cs/sql-injection", "properties": { "security-severity": "9.8" } }
          ] } },
          "results": [
            {
              "ruleId": "cs/sql-injection",
              "level": "error",
              "message": { "text": "This query depends on a user-provided value." },
              "locations": [
                { "physicalLocation": { "artifactLocation": { "uri": "src/Db.cs" }, "region": { "startLine": 42 } } }
              ]
            }
          ]
        }
      ]
    }
    """;

    // Semgrep-style: no security-severity, so severity falls back to the SARIF level.
    private const string LevelOnlySarif = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": { "driver": { "name": "Semgrep" } },
          "results": [
            {
              "ruleId": "javascript.lang.security.no-eval",
              "level": "warning",
              "message": { "text": "Avoid eval()." },
              "locations": [
                { "physicalLocation": { "artifactLocation": { "uri": "app.js" }, "region": { "startLine": 3 } } }
              ]
            }
          ]
        }
      ]
    }
    """;

    [Fact]
    public void Maps_a_codeql_result_with_security_severity()
    {
        var findings = SarifAdapter.Parse(CodeQlSarif);

        var f = Assert.Single(findings);
        Assert.Equal("cs/sql-injection", f.VulnerabilityId);
        Assert.Equal("src/Db.cs", f.PackageName);
        Assert.Equal("L42", f.PackageVersion);
        Assert.Equal(Severity.Critical, f.Severity);   // 9.8 → Critical
        Assert.Equal(9.8, f.CvssScore);
        Assert.StartsWith("cs/sql-injection:", f.Title);
    }

    [Fact]
    public void Falls_back_to_level_when_no_security_severity()
    {
        var findings = SarifAdapter.Parse(LevelOnlySarif);

        var f = Assert.Single(findings);
        Assert.Equal(Severity.Medium, f.Severity);     // "warning" → Medium
        Assert.Null(f.CvssScore);
        Assert.Equal("app.js", f.PackageName);
        Assert.Equal("L3", f.PackageVersion);
    }

    [Fact]
    public void Rule_level_security_severity_is_used_when_result_lacks_it()
    {
        // The result has no properties; the rule (indexed from driver.rules) carries the score.
        var findings = SarifAdapter.Parse(CodeQlSarif);
        Assert.Equal(9.8, Assert.Single(findings).CvssScore);
    }

    [Fact]
    public void Duplicate_rule_file_line_is_collapsed()
    {
        var findings = SarifAdapter.Parse(CodeQlSarif.Replace(
            "\"results\": [",
            """
            "results": [
              {
                "ruleId": "cs/sql-injection",
                "level": "error",
                "message": { "text": "dup" },
                "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "src/Db.cs" }, "region": { "startLine": 42 } } } ]
              },
            """));

        Assert.Single(findings); // same (rule, file, line) → one finding
    }

    [Fact]
    public void Empty_runs_map_to_no_findings()
    {
        Assert.Empty(SarifAdapter.Parse("""{ "version": "2.1.0", "runs": [] }"""));
    }

    [Fact]
    public void Non_sarif_payload_throws_FormatException()
    {
        // No 'runs' array — must not be mistaken for a clean scan.
        Assert.Throws<FormatException>(() => SarifAdapter.Parse("""{ "projects": [] }"""));
    }
}
