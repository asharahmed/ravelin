using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Ravelin.Auth;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Ravelin.Infrastructure;
using Ravelin.Infrastructure.Services;
using Ravelin.Shared.Contracts;

namespace Ravelin.Endpoints;

public static class RavelinEndpoints
{
    private const int MaxFindingsPerScan = 5000;

    public static void MapRavelinApi(this WebApplication app)
    {
        MapIngestion(app);
        MapAdmin(app);
        MapReads(app);
    }

    // --- Ingestion (API-key auth; project comes from the key, never the route) ----------
    private static void MapIngestion(WebApplication app)
    {
        app.MapPost("/api/ingest", async (
            ScanIngestRequest request, ClaimsPrincipal user, IngestionService ingestion) =>
        {
            var projectId = Guid.Parse(user.FindFirstValue(ApiKeyAuthenticationHandler.ProjectIdClaim)!);

            if (string.IsNullOrWhiteSpace(request.Tool))
            {
                return Results.BadRequest("Tool is required.");
            }

            if (request.Findings is null || request.Findings.Count > MaxFindingsPerScan)
            {
                return Results.BadRequest($"Findings are required and limited to {MaxFindingsPerScan} per scan.");
            }

            var incoming = new List<IncomingFinding>(request.Findings.Count);
            foreach (var f in request.Findings)
            {
                if (string.IsNullOrWhiteSpace(f.VulnerabilityId) ||
                    string.IsNullOrWhiteSpace(f.PackageName) ||
                    string.IsNullOrWhiteSpace(f.PackageVersion) ||
                    string.IsNullOrWhiteSpace(f.Title))
                {
                    return Results.BadRequest(
                        "Each finding requires VulnerabilityId, PackageName, PackageVersion, and Title.");
                }

                incoming.Add(new IncomingFinding
                {
                    VulnerabilityId = f.VulnerabilityId,
                    PackageName = f.PackageName,
                    PackageVersion = f.PackageVersion,
                    Title = f.Title,
                    Description = f.Description,
                    Severity = ParseSeverity(f.Severity),
                    CvssScore = f.CvssScore,
                    FixedVersion = f.FixedVersion,
                });
            }

            var (scan, result, openTotal) =
                await ingestion.IngestAsync(projectId, request.Tool, request.ToolVersion, incoming);

            return Results.Ok(new ScanIngestResponse
            {
                ScanId = scan.Id,
                Created = result.Created.Count,
                Reopened = result.Reopened.Count,
                Resolved = result.Resolved.Count,
                Seen = result.Seen.Count,
                OpenTotal = openTotal,
            });
        })
        .RequireAuthorization(policy => policy
            .AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName)
            .RequireAuthenticatedUser())
        // Token-authenticated JSON API — CSRF/antiforgery (a cookie-browser concern) does
        // not apply, and the global UseAntiforgery() would otherwise 400 these requests.
        .DisableAntiforgery();
    }

    // --- Admin (bootstrap-token gate; replaced by RBAC in Stage 4) ----------------------
    private static void MapAdmin(WebApplication app)
    {
        var admin = app.MapGroup("/api/admin")
            .AddEndpointFilter<BootstrapTokenFilter>()
            .DisableAntiforgery();

        admin.MapPost("/projects", async (CreateProjectRequest req, RavelinDbContext db) =>
        {
            if (string.IsNullOrWhiteSpace(req.Key) || string.IsNullOrWhiteSpace(req.Name))
            {
                return Results.BadRequest("Key and Name are required.");
            }

            if (await db.Projects.AnyAsync(p => p.Key == req.Key))
            {
                return Results.Conflict($"Project '{req.Key}' already exists.");
            }

            var project = new Project { Key = req.Key, Name = req.Name, RepositoryUrl = req.RepositoryUrl };
            db.Projects.Add(project);
            await db.SaveChangesAsync();

            return Results.Created($"/api/projects/{project.Key}", ToDto(project, 0));
        });

        admin.MapPost("/projects/{key}/api-keys", async (
            string key, CreateApiKeyRequest req, RavelinDbContext db, ApiKeyService apiKeys) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
            {
                return Results.BadRequest("Name is required.");
            }

            var project = await db.Projects.FirstOrDefaultAsync(p => p.Key == key);
            if (project is null)
            {
                return Results.NotFound($"Project '{key}' not found.");
            }

            var (entity, rawKey) = await apiKeys.CreateAsync(project.Id, req.Name);
            return Results.Ok(new CreateApiKeyResponse
            {
                Id = entity.Id,
                Name = entity.Name,
                Key = rawKey,
                Prefix = entity.KeyPrefix,
            });
        });
    }

    // --- Reads (bootstrap-token gate for now; moves to RBAC in Stage 4) -----------------
    private static void MapReads(WebApplication app)
    {
        var reads = app.MapGroup("/api").AddEndpointFilter<BootstrapTokenFilter>();

        reads.MapGet("/projects", async (RavelinDbContext db) =>
        {
            var projects = await db.Projects
                .Select(p => new ProjectDto
                {
                    Id = p.Id,
                    Key = p.Key,
                    Name = p.Name,
                    RepositoryUrl = p.RepositoryUrl,
                    OpenFindings = p.Findings.Count(f => f.Status == FindingStatus.Open),
                })
                .ToListAsync();

            return Results.Ok(projects);
        });

        reads.MapGet("/projects/{key}/findings", async (
            string key, string? status, RavelinDbContext db) =>
        {
            var project = await db.Projects.FirstOrDefaultAsync(p => p.Key == key);
            if (project is null)
            {
                return Results.NotFound($"Project '{key}' not found.");
            }

            var query = db.Findings.Where(f => f.ProjectId == project.Id);
            if (Enum.TryParse<FindingStatus>(status, ignoreCase: true, out var parsed))
            {
                query = query.Where(f => f.Status == parsed);
            }

            var findings = await query
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.PackageName)
                .ToListAsync();

            var now = DateTimeOffset.UtcNow;
            return Results.Ok(findings.Select(f => ToDto(f, now)).ToList());
        });
    }

    // --- Helpers ------------------------------------------------------------------------
    private static Severity ParseSeverity(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" or "moderate" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Unknown,
    };

    private static ProjectDto ToDto(Project p, int openFindings) => new()
    {
        Id = p.Id,
        Key = p.Key,
        Name = p.Name,
        RepositoryUrl = p.RepositoryUrl,
        OpenFindings = openFindings,
    };

    private static FindingDto ToDto(Finding f, DateTimeOffset now) => new()
    {
        Id = f.Id,
        VulnerabilityId = f.VulnerabilityId,
        PackageName = f.PackageName,
        PackageVersion = f.PackageVersion,
        Title = f.Title,
        Severity = f.Severity.ToString(),
        Status = f.Status.ToString(),
        CvssScore = f.CvssScore,
        FixedVersion = f.FixedVersion,
        FirstDetectedAt = f.FirstDetectedAt,
        ResolvedAt = f.ResolvedAt,
        SlaDueAt = f.SlaDueAt,
        SlaBreached = f.Status == FindingStatus.Open && f.SlaDueAt is not null && f.SlaDueAt < now,
    };
}
