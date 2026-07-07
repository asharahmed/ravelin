using Ravelin.Infrastructure.Services;

namespace Ravelin.Tests;

public class VulnIntelParsingTests
{
    [Fact]
    public void ParseKev_reads_cve_ids_and_dates_case_insensitively()
    {
        const string json = """
        {
          "title": "CISA Catalog of Known Exploited Vulnerabilities",
          "count": 2,
          "vulnerabilities": [
            { "cveID": "CVE-2021-44228", "dateAdded": "2021-12-10" },
            { "cveID": "CVE-2023-1234", "dateAdded": "2023-05-01" }
          ]
        }
        """;

        var kev = VulnerabilityIntelligenceClient.ParseKev(json);

        Assert.Equal(2, kev.Count);
        Assert.True(kev.ContainsKey("cve-2021-44228"));   // case-insensitive lookup
        Assert.Equal(new DateTimeOffset(2021, 12, 10, 0, 0, 0, TimeSpan.Zero), kev["CVE-2021-44228"]);
    }

    [Fact]
    public void ParseKev_skips_entries_without_a_cve_id()
    {
        const string json = """{ "vulnerabilities": [ { "dateAdded": "2021-01-01" }, { "cveID": "CVE-2021-1" } ] }""";

        var kev = VulnerabilityIntelligenceClient.ParseKev(json);

        Assert.Single(kev);
        Assert.True(kev.ContainsKey("CVE-2021-1"));
    }

    [Fact]
    public void ParseEpss_reads_scores_as_invariant_doubles()
    {
        const string json = """
        {
          "status": "OK",
          "data": [
            { "cve": "CVE-2021-44228", "epss": "0.97514", "percentile": "0.99998" },
            { "cve": "CVE-2023-1234", "epss": "0.00042", "percentile": "0.10000" }
          ]
        }
        """;

        var epss = VulnerabilityIntelligenceClient.ParseEpss(json);

        Assert.Equal(2, epss.Count);
        Assert.Equal(0.97514, epss["CVE-2021-44228"].Score, precision: 5);
        Assert.Equal(0.99998, epss["CVE-2021-44228"].Percentile, precision: 5);
    }

    [Fact]
    public void ParseEpss_skips_rows_with_an_unparseable_score()
    {
        const string json = """{ "data": [ { "cve": "CVE-1", "epss": "n/a" }, { "cve": "CVE-2", "epss": "0.5", "percentile": "0.8" } ] }""";

        var epss = VulnerabilityIntelligenceClient.ParseEpss(json);

        Assert.Single(epss);
        Assert.True(epss.ContainsKey("CVE-2"));
    }
}
