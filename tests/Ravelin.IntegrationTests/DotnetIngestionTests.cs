using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Ravelin.Auth;
using Ravelin.Domain.Enums;
using Ravelin.Shared.Contracts;

namespace Ravelin.IntegrationTests;

/// <summary>
/// End-to-end integration tests for the dogfood ingestion endpoint. Each test drives a real
/// HTTP request through the genuine middleware pipeline (API-key auth → rate limit → endpoint
/// → adapter → reconciler → EF Core) into a real SQL Server, then asserts on persisted state.
/// Nothing about the system under test is mocked, so a hollow "test" can't pass.
///
/// The last test is the canonical example of the bug class the future auto-fix loop targets:
/// an untrusted payload must fail closed as a 400, never an unhandled 500 — and that guarantee
/// is provable here, against the real boundary, not a unit-level fake.
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class DotnetIngestionTests(RavelinFixture fixture) : IAsyncLifetime
{
    private const string Route = "/api/ingest/dotnet";

    // A minimal but real `dotnet list package --vulnerable --format json` document: one
    // transitive advisory. Maps to exactly one finding (GHSA id is the stable identity).
    private const string OneVulnReport = """
    {
      "version": 1,
      "parameters": "--vulnerable --include-transitive --format json",
      "projects": [
        {
          "path": "src/Ravelin/Ravelin.csproj",
          "frameworks": [
            {
              "framework": "net10.0",
              "topLevelPackages": [
                {
                  "id": "System.Net.Http",
                  "resolvedVersion": "4.3.0",
                  "vulnerabilities": [
                    {
                      "severity": "High",
                      "advisoryurl": "https://github.com/advisories/GHSA-7jgj-8wvc-jh57"
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    // A clean report: a project with no `frameworks` key means zero vulnerabilities.
    private const string CleanReport = """{ "version": 1, "projects": [ { "path": "x.csproj" } ] }""";

    // Not a dotnet-list report at all (no `projects` array). The adapter throws FormatException
    // by design, so a malformed payload can't masquerade as a clean scan and auto-resolve.
    private const string MalformedPayload = """{ "results": [ { "foo": "bar" } ] }""";

    // Reset domain data before each test so they're independent.
    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ValidKey_CreatesFindingInRealDatabase()
    {
        var (project, rawKey) = await fixture.SeedProjectWithKeyAsync("ingest-valid");
        using var client = fixture.CreateClient();

        var response = await client.SendAsync(Post(OneVulnReport, rawKey));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<ScanIngestResponse>();
        Assert.NotNull(body);
        Assert.Equal(1, body!.Created);
        Assert.Equal(1, body.OpenTotal);

        await fixture.WithDbAsync(async db =>
        {
            var finding = await db.Findings.SingleAsync(f => f.ProjectId == project.Id);
            Assert.Equal("GHSA-7jgj-8wvc-jh57", finding.VulnerabilityId);
            Assert.Equal("System.Net.Http", finding.PackageName);
            Assert.Equal("4.3.0", finding.PackageVersion);
            Assert.Equal(Severity.High, finding.Severity);
            Assert.Equal(FindingStatus.Open, finding.Status);
            // The SLA engine assigned a remediation deadline from the seeded High policy.
            Assert.NotNull(finding.SlaDueAt);
        });
    }

    [Fact]
    public async Task CleanReport_RecordsScanWithNoFindings()
    {
        var (project, rawKey) = await fixture.SeedProjectWithKeyAsync("ingest-clean");
        using var client = fixture.CreateClient();

        var response = await client.SendAsync(Post(CleanReport, rawKey));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<ScanIngestResponse>();
        Assert.Equal(0, body!.Created);
        await fixture.WithDbAsync(async db =>
            Assert.False(await db.Findings.AnyAsync(f => f.ProjectId == project.Id)));
    }

    [Fact]
    public async Task NoKey_Returns401()
    {
        using var client = fixture.CreateClient();
        var response = await client.SendAsync(Post(OneVulnReport, apiKey: null));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task BadKey_Returns401_AndWritesNothing()
    {
        using var client = fixture.CreateClient();

        var response = await client.SendAsync(Post(OneVulnReport, "rvln_not-a-real-key"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // An unauthenticated push must persist nothing.
        await fixture.WithDbAsync(async db => Assert.False(await db.Findings.AnyAsync()));
    }

    [Fact]
    public async Task MalformedReport_Returns400_NotUnhandled500()
    {
        var (_, rawKey) = await fixture.SeedProjectWithKeyAsync("ingest-malformed");
        using var client = fixture.CreateClient();

        var response = await client.SendAsync(Post(MalformedPayload, rawKey));

        // The untrusted-input contract: fail closed as a client error, never a server crash.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);
    }

    private static HttpRequestMessage Post(string body, string? apiKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Route)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        if (apiKey is not null)
        {
            request.Headers.Add(ApiKeyAuthenticationHandler.HeaderName, apiKey);
        }
        return request;
    }
}
