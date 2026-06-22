using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Ravelin.Auth;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Ravelin.Domain.Services;
using Ravelin.Infrastructure;
using Ravelin.Infrastructure.Services;
using Ravelin.Shared;
using Ravelin.Shared.Contracts;

namespace Ravelin.Endpoints;

public static class RavelinEndpoints
{
    private const int MaxFindingsPerScan = 5000;

    public static void MapRavelinApi(this WebApplication app)
    {
        MapAuth(app);
        MapAccount(app);
        MapIngestion(app);
        MapAdmin(app);
        MapReads(app);
        MapSla(app);
        MapDashboard(app);
    }

    // --- Human auth: email/password -> JWT ----------------------------------------------
    private static void MapAuth(WebApplication app)
    {
        app.MapPost("/api/auth/login", async (
            LoginRequest request, UserManager<IdentityUser> users, JwtTokenService jwt, AuditService audit) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return Results.BadRequest("Email and password are required.");
            }

            var user = await users.FindByEmailAsync(request.Email);
            // Same response whether the account is missing, locked, or the password is wrong —
            // don't reveal which (avoids account enumeration).
            if (user is null || await users.IsLockedOutAsync(user))
            {
                return Results.Unauthorized();
            }

            if (!await users.CheckPasswordAsync(user, request.Password))
            {
                await users.AccessFailedAsync(user); // increments the count; locks at the threshold
                return Results.Unauthorized();
            }

            await users.ResetAccessFailedCountAsync(user);
            await audit.RecordAsync(user.Email!, "auth.login");

            var roles = await users.GetRolesAsync(user);
            var (token, expiresAt) = jwt.CreateToken(user.Id, user.Email!, roles);

            return Results.Ok(new LoginResponse
            {
                Token = token,
                ExpiresAt = expiresAt,
                Email = user.Email!,
                Roles = roles.ToList(),
            });
        })
        .RequireRateLimiting("auth")
        .DisableAntiforgery();

        // Self-service signup. New accounts are ALWAYS read-only Viewers — registration
        // can never grant Analyst/Admin; those are assigned out-of-band by an administrator.
        app.MapPost("/api/auth/register", async (
            RegisterRequest request, UserManager<IdentityUser> users, JwtTokenService jwt, AuditService audit) =>
        {
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return Results.BadRequest("Email and password are required.");
            }

            var user = new IdentityUser { UserName = request.Email, Email = request.Email };
            var created = await users.CreateAsync(user, request.Password);
            if (!created.Succeeded)
            {
                // Identity validates uniqueness + password policy; surface its messages.
                return Results.BadRequest(string.Join(" ", created.Errors.Select(e => e.Description)));
            }

            await users.AddToRoleAsync(user, RavelinRoles.Viewer);
            await audit.RecordAsync(user.Email!, "auth.register", user.Email, "self-service Viewer");

            var roles = await users.GetRolesAsync(user);
            var (token, expiresAt) = jwt.CreateToken(user.Id, user.Email!, roles);

            return Results.Ok(new LoginResponse
            {
                Token = token,
                ExpiresAt = expiresAt,
                Email = user.Email!,
                Roles = roles.ToList(),
            });
        })
        .RequireRateLimiting("auth")
        .DisableAntiforgery();
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
                return Results.Problem(detail: "Tool is required.", statusCode: StatusCodes.Status400BadRequest);
            }

            if (request.Findings is null || request.Findings.Count > MaxFindingsPerScan)
            {
                return Results.Problem(
                    detail: $"Findings are required and limited to {MaxFindingsPerScan} per scan.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var incoming = new List<IncomingFinding>(request.Findings.Count);
            foreach (var f in request.Findings)
            {
                if (string.IsNullOrWhiteSpace(f.VulnerabilityId) ||
                    string.IsNullOrWhiteSpace(f.PackageName) ||
                    string.IsNullOrWhiteSpace(f.PackageVersion) ||
                    string.IsNullOrWhiteSpace(f.Title))
                {
                    return Results.Problem(
                        detail: "Each finding requires VulnerabilityId, PackageName, PackageVersion, and Title.",
                        statusCode: StatusCodes.Status400BadRequest);
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
        .RequireRateLimiting("ingest")
        // Token-authenticated JSON API — CSRF/antiforgery (a cookie-browser concern) does
        // not apply, and the global UseAntiforgery() would otherwise 400 these requests.
        .DisableAntiforgery();

        // Native scanner adapters: pipe a tool's own JSON straight in — no transform step.
        app.MapPost("/api/ingest/trivy", (HttpRequest http, ClaimsPrincipal user, IngestionService ingestion) =>
                IngestRawAsync(http, user, ingestion, "trivy", TrivyAdapter.Parse))
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName)
                .RequireAuthenticatedUser())
            .RequireRateLimiting("ingest")
            .DisableAntiforgery();

        app.MapPost("/api/ingest/grype", (HttpRequest http, ClaimsPrincipal user, IngestionService ingestion) =>
                IngestRawAsync(http, user, ingestion, "grype", GrypeAdapter.Parse))
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName)
                .RequireAuthenticatedUser())
            .RequireRateLimiting("ingest")
            .DisableAntiforgery();
    }

    // Reads a raw scanner report from the body, maps it with the given adapter, and ingests
    // it through the same pipeline as /api/ingest (dedup + auto-resolve + SLA).
    private static async Task<IResult> IngestRawAsync(
        HttpRequest http, ClaimsPrincipal user, IngestionService ingestion,
        string tool, Func<string, IReadOnlyList<IncomingFinding>> parse)
    {
        var projectId = Guid.Parse(user.FindFirstValue(ApiKeyAuthenticationHandler.ProjectIdClaim)!);

        string body;
        using (var reader = new StreamReader(http.Body))
        {
            body = await reader.ReadToEndAsync();
        }
        if (string.IsNullOrWhiteSpace(body))
        {
            return Results.Problem(detail: "Request body is empty.", statusCode: StatusCodes.Status400BadRequest);
        }

        IReadOnlyList<IncomingFinding> incoming;
        try
        {
            incoming = parse(body);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return Results.Problem(
                detail: $"Could not read the {tool} report: {ex.Message}",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (incoming.Count > MaxFindingsPerScan)
        {
            return Results.Problem(
                detail: $"Findings are limited to {MaxFindingsPerScan} per scan.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // An empty report is valid: it records a clean scan and auto-resolves what's now gone.
        var (scan, result, openTotal) = await ingestion.IngestAsync(projectId, tool, null, incoming);
        return Results.Ok(new ScanIngestResponse
        {
            ScanId = scan.Id,
            Created = result.Created.Count,
            Reopened = result.Reopened.Count,
            Resolved = result.Resolved.Count,
            Seen = result.Seen.Count,
            OpenTotal = openTotal,
        });
    }

    // --- Admin (bootstrap-token gate; replaced by RBAC in Stage 4) ----------------------
    private static void MapAdmin(WebApplication app)
    {
        var admin = app.MapGroup("/api/admin")
            .RequireAuthorization(policy => policy.RequireRole(RavelinRoles.Admin))
            .DisableAntiforgery();

        admin.MapPost("/projects", async (CreateProjectRequest req, RavelinDbContext db,
            AuditService audit, ClaimsPrincipal actor) =>
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
            await audit.RecordAsync(ActorOf(actor), "project.create", project.Key, project.Name);

            return Results.Created($"/api/projects/{project.Key}", ToDto(project, 0));
        });

        admin.MapPost("/projects/{key}/api-keys", async (
            string key, CreateApiKeyRequest req, RavelinDbContext db, ApiKeyService apiKeys,
            AuditService audit, ClaimsPrincipal actor) =>
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
            await audit.RecordAsync(ActorOf(actor), "apikey.create", key, $"{req.Name} ({entity.KeyPrefix}…)");
            return Results.Ok(new CreateApiKeyResponse
            {
                Id = entity.Id,
                Name = entity.Name,
                Key = rawKey,
                Prefix = entity.KeyPrefix,
            });
        });

        // List a project's API keys (no secrets — prefix + lifecycle only).
        admin.MapGet("/projects/{key}/api-keys", async (string key, RavelinDbContext db) =>
        {
            var project = await db.Projects.FirstOrDefaultAsync(p => p.Key == key);
            if (project is null)
            {
                return Results.NotFound($"Project '{key}' not found.");
            }

            var keys = await db.ApiKeys
                .Where(k => k.ProjectId == project.Id)
                .OrderByDescending(k => k.RevokedAt == null)
                .ThenByDescending(k => k.CreatedAt)
                .Select(k => new ApiKeyDto
                {
                    Id = k.Id,
                    Name = k.Name,
                    Prefix = k.KeyPrefix,
                    CreatedAt = k.CreatedAt,
                    LastUsedAt = k.LastUsedAt,
                    RevokedAt = k.RevokedAt,
                    IsActive = k.RevokedAt == null,
                })
                .ToListAsync();

            return Results.Ok(keys);
        });

        // Revoke an API key (idempotent).
        admin.MapDelete("/projects/{key}/api-keys/{id:guid}", async (
            string key, Guid id, RavelinDbContext db, ApiKeyService apiKeys,
            AuditService audit, ClaimsPrincipal actor) =>
        {
            var project = await db.Projects.FirstOrDefaultAsync(p => p.Key == key);
            if (project is null)
            {
                return Results.NotFound($"Project '{key}' not found.");
            }

            var revoked = await apiKeys.RevokeAsync(project.Id, id);
            if (revoked) await audit.RecordAsync(ActorOf(actor), "apikey.revoke", key, id.ToString());
            return revoked ? Results.NoContent() : Results.NotFound($"Key '{id}' not found.");
        });

        // List human users with their role.
        admin.MapGet("/users", async (UserManager<IdentityUser> users) =>
        {
            var accounts = await users.Users.OrderBy(u => u.Email).ToListAsync();
            var dtos = new List<UserDto>(accounts.Count);
            foreach (var u in accounts)
            {
                var roles = await users.GetRolesAsync(u);
                dtos.Add(new UserDto { Id = u.Id, Email = u.Email ?? "", Role = roles.FirstOrDefault() ?? "—" });
            }
            return Results.Ok(dtos);
        });

        // Change a user's role. Guards against removing the last administrator.
        admin.MapPut("/users/{id}/role", async (
            string id, SetUserRoleRequest req, UserManager<IdentityUser> users,
            AuditService audit, ClaimsPrincipal actor) =>
        {
            if (!RavelinRoles.All.Contains(req.Role))
            {
                return Results.BadRequest($"Unknown role '{req.Role}'.");
            }

            var user = await users.FindByIdAsync(id);
            if (user is null)
            {
                return Results.NotFound("User not found.");
            }

            var current = await users.GetRolesAsync(user);
            if (current.Contains(RavelinRoles.Admin) && req.Role != RavelinRoles.Admin)
            {
                var admins = await users.GetUsersInRoleAsync(RavelinRoles.Admin);
                if (admins.Count <= 1)
                {
                    return Results.BadRequest("Cannot remove the last administrator.");
                }
            }

            if (current.Count > 0)
            {
                await users.RemoveFromRolesAsync(user, current);
            }
            await users.AddToRoleAsync(user, req.Role);
            await audit.RecordAsync(ActorOf(actor), "user.role", user.Email, $"{current.FirstOrDefault() ?? "none"} -> {req.Role}");

            return Results.Ok(new UserDto { Id = user.Id, Email = user.Email ?? "", Role = req.Role });
        });

        // Audit trail (newest first) — who did what.
        admin.MapGet("/audit", async (RavelinDbContext db) =>
        {
            var events = await db.AuditEvents
                .OrderByDescending(e => e.At)
                .Take(200)
                .Select(e => new AuditEventDto
                {
                    At = e.At,
                    Actor = e.Actor,
                    Action = e.Action,
                    Target = e.Target,
                    Detail = e.Detail,
                })
                .ToListAsync();
            return Results.Ok(events);
        });

        // Admin-initiated password reset (no email): set a strong temporary password and return
        // it once for out-of-band handoff. The user signs in with it and changes it on /account.
        admin.MapPost("/users/{id}/reset-password", async (
            string id, UserManager<IdentityUser> users, AuditService audit, ClaimsPrincipal actor) =>
        {
            var user = await users.FindByIdAsync(id);
            if (user is null)
            {
                return Results.NotFound("User not found.");
            }

            var temp = GenerateTempPassword();
            var token = await users.GeneratePasswordResetTokenAsync(user);
            var result = await users.ResetPasswordAsync(user, token, temp);
            if (!result.Succeeded)
            {
                return Results.Problem(
                    detail: string.Join(" ", result.Errors.Select(e => e.Description)),
                    statusCode: StatusCodes.Status400BadRequest);
            }

            await audit.RecordAsync(ActorOf(actor), "user.password.reset", user.Email);
            return Results.Ok(new AdminResetPasswordResponse
            {
                Email = user.Email ?? "",
                TemporaryPassword = temp,
            });
        });
    }

    // --- Account (the signed-in user's own profile + password) --------------------------
    private static void MapAccount(WebApplication app)
    {
        app.MapGet("/api/account", (ClaimsPrincipal user) => Results.Ok(new AccountDto
        {
            Email = ActorOf(user),
            Roles = user.FindAll("role").Select(c => c.Value).ToList(),
        }))
        .RequireAuthorization();

        app.MapPost("/api/account/change-password", async (
            ChangePasswordRequest req, UserManager<IdentityUser> users, AuditService audit, ClaimsPrincipal actor) =>
        {
            if (string.IsNullOrWhiteSpace(req.CurrentPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
            {
                return Results.Problem(detail: "Current and new password are required.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var user = await users.FindByEmailAsync(ActorOf(actor));
            if (user is null)
            {
                return Results.Unauthorized();
            }

            var result = await users.ChangePasswordAsync(user, req.CurrentPassword, req.NewPassword);
            if (!result.Succeeded)
            {
                return Results.Problem(
                    detail: string.Join(" ", result.Errors.Select(e => e.Description)),
                    statusCode: StatusCodes.Status400BadRequest);
            }

            await audit.RecordAsync(ActorOf(actor), "account.password");
            return Results.NoContent();
        })
        .RequireAuthorization()
        .RequireRateLimiting("auth")
        .DisableAntiforgery();
    }

    // --- Reads (any authenticated user: Viewer / Analyst / Admin) -----------------------
    private static void MapReads(WebApplication app)
    {
        var reads = app.MapGroup("/api").RequireAuthorization();

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

        // Breached (overdue) open findings, for the compliance report.
        reads.MapGet("/report/breaches", async (RavelinDbContext db) =>
        {
            var now = DateTimeOffset.UtcNow;
            var open = await db.Findings
                .Include(f => f.Project)
                .Where(f => f.Status == FindingStatus.Open)
                .ToListAsync();

            var breaches = open
                .Select(f => new { f, e = SlaEvaluator.Evaluate(f, now) })
                .Where(x => x.e.IsBreached)
                .OrderByDescending(x => x.f.Severity)
                .ThenBy(x => x.e.DaysRemaining)
                .Select(x => new ReportFindingDto
                {
                    ProjectKey = x.f.Project!.Key,
                    ProjectName = x.f.Project.Name,
                    VulnerabilityId = x.f.VulnerabilityId,
                    PackageName = x.f.PackageName,
                    PackageVersion = x.f.PackageVersion,
                    Severity = x.f.Severity.ToString(),
                    DaysOverdue = -(x.e.DaysRemaining ?? 0),
                    SlaDueAt = x.f.SlaDueAt,
                })
                .ToList();

            return Results.Ok(breaches);
        });
    }

    // --- Dashboard rollup (Stage 6) -----------------------------------------------------
    private static void MapDashboard(WebApplication app)
    {
        app.MapGet("/api/dashboard", async (RavelinDbContext db) =>
        {
            var now = DateTimeOffset.UtcNow;

            var projects = await db.Projects
                .Select(p => new { p.Id, p.Key, p.Name })
                .ToListAsync();

            // Open findings drive every "current posture" number.
            var open = await db.Findings
                .Where(f => f.Status == FindingStatus.Open)
                .Select(f => new { f.ProjectId, f.Severity, f.SlaDueAt })
                .ToListAsync();

            SlaState StateOf(DateTimeOffset? dueAt) =>
                SlaEvaluator.Evaluate(FindingStatus.Open, dueAt, now, SlaEvaluator.DefaultDueSoonWindow).State;

            var perProject = projects.Select(p =>
            {
                var items = open.Where(f => f.ProjectId == p.Id).ToList();
                var breached = items.Count(f => StateOf(f.SlaDueAt) == SlaState.Breached);
                var dueSoon = items.Count(f => StateOf(f.SlaDueAt) == SlaState.DueSoon);
                var total = items.Count;
                return new ProjectPostureDto
                {
                    Key = p.Key,
                    Name = p.Name,
                    Open = total,
                    Breached = breached,
                    DueSoon = dueSoon,
                    CompliancePercent = total == 0 ? 100 : Math.Round((double)(total - breached) / total * 100, 1),
                };
            })
            .OrderByDescending(p => p.Breached)
            .ThenByDescending(p => p.Open)
            .ToList();

            var totalOpen = open.Count;
            var totalBreached = open.Count(f => StateOf(f.SlaDueAt) == SlaState.Breached);
            var totalDueSoon = open.Count(f => StateOf(f.SlaDueAt) == SlaState.DueSoon);

            var severity = new SeverityCountsDto
            {
                Critical = open.Count(f => f.Severity == Severity.Critical),
                High = open.Count(f => f.Severity == Severity.High),
                Medium = open.Count(f => f.Severity == Severity.Medium),
                Low = open.Count(f => f.Severity == Severity.Low),
                Unknown = open.Count(f => f.Severity == Severity.Unknown),
            };

            // 8-week opened-vs-resolved flow, bucketed by week from the window start.
            const int weeks = 8;
            var windowStart = now.Date.AddDays(-7 * (weeks - 1) - (int)now.DayOfWeek);
            var detected = await db.Findings
                .Where(f => f.FirstDetectedAt >= windowStart)
                .Select(f => f.FirstDetectedAt)
                .ToListAsync();
            var resolvedAt = await db.Findings
                .Where(f => f.ResolvedAt != null && f.ResolvedAt >= windowStart)
                .Select(f => f.ResolvedAt!.Value)
                .ToListAsync();

            var trend = new List<TrendPointDto>();
            for (var w = 0; w < weeks; w++)
            {
                var start = windowStart.AddDays(7 * w);
                var end = start.AddDays(7);
                trend.Add(new TrendPointDto
                {
                    WeekStart = new DateTimeOffset(start, TimeSpan.Zero),
                    Opened = detected.Count(d => d >= start && d < end),
                    Resolved = resolvedAt.Count(r => r >= start && r < end),
                });
            }

            return Results.Ok(new DashboardDto
            {
                ProjectCount = projects.Count,
                TotalOpen = totalOpen,
                Breached = totalBreached,
                DueSoon = totalDueSoon,
                OnTrack = totalOpen - totalBreached - totalDueSoon,
                CompliancePercent = totalOpen == 0 ? 100 : Math.Round((double)(totalOpen - totalBreached) / totalOpen * 100, 1),
                OpenBySeverity = severity,
                Projects = perProject,
                Trend = trend,
            });
        })
        .RequireAuthorization();
    }

    // --- SLA engine + triage (Stage 5) --------------------------------------------------
    private static void MapSla(WebApplication app)
    {
        // SLA policy: any authenticated user can read; only Admin can change it.
        app.MapGet("/api/sla-policies", async (RavelinDbContext db) =>
        {
            var policies = await db.SlaPolicies
                .OrderByDescending(p => p.Severity)
                .Select(p => new SlaPolicyDto
                {
                    Severity = p.Severity.ToString(),
                    RemediationDays = p.RemediationDays,
                })
                .ToListAsync();

            return Results.Ok(policies);
        })
        .RequireAuthorization();

        app.MapPut("/api/sla-policies", async (UpdateSlaPoliciesRequest req, RavelinDbContext db,
            AuditService audit, ClaimsPrincipal actor) =>
        {
            if (req.Policies is null || req.Policies.Count == 0)
            {
                return Results.BadRequest("At least one policy is required.");
            }

            var updates = new Dictionary<Severity, int>();
            foreach (var p in req.Policies)
            {
                if (!Enum.TryParse<Severity>(p.Severity, ignoreCase: true, out var sev) || sev == Severity.Unknown)
                {
                    return Results.BadRequest($"Unknown severity '{p.Severity}'.");
                }
                if (p.RemediationDays < 1)
                {
                    return Results.BadRequest($"RemediationDays for {sev} must be at least 1.");
                }
                updates[sev] = p.RemediationDays;
            }

            var policies = await db.SlaPolicies.ToListAsync();
            foreach (var policy in policies)
            {
                if (updates.TryGetValue(policy.Severity, out var days))
                {
                    policy.RemediationDays = days;
                }
            }

            // Re-baseline open findings so the new deadline applies immediately (deadline is a
            // snapshot computed from FirstDetected; triaged/resolved findings are left alone).
            var slaDays = policies.ToDictionary(p => p.Severity, p => p.RemediationDays);
            var openFindings = await db.Findings.Where(f => f.Status == FindingStatus.Open).ToListAsync();
            foreach (var finding in openFindings)
            {
                finding.SlaDueAt = SlaEvaluator.ComputeDueDate(finding.FirstDetectedAt, finding.Severity, slaDays);
            }

            await db.SaveChangesAsync();
            await audit.RecordAsync(ActorOf(actor), "sla.update", null,
                string.Join(", ", policies.OrderByDescending(p => p.Severity).Select(p => $"{p.Severity}:{p.RemediationDays}d")));

            return Results.Ok(policies
                .OrderByDescending(p => p.Severity)
                .Select(p => new SlaPolicyDto { Severity = p.Severity.ToString(), RemediationDays = p.RemediationDays })
                .ToList());
        })
        .RequireAuthorization(policy => policy.RequireRole(RavelinRoles.Admin))
        .DisableAntiforgery();

        // Triage a finding (Analyst or Admin). Viewer is read-only.
        app.MapPost("/api/projects/{key}/findings/{id:guid}/triage", async (
            string key, Guid id, TriageFindingRequest req, RavelinDbContext db,
            AuditService audit, ClaimsPrincipal actor) =>
        {
            if (!Enum.TryParse<FindingStatus>(req.Status, ignoreCase: true, out var target))
            {
                return Results.BadRequest($"Unknown status '{req.Status}'.");
            }

            var finding = await db.Findings
                .Include(f => f.Project)
                .FirstOrDefaultAsync(f => f.Id == id && f.Project!.Key == key);
            if (finding is null)
            {
                return Results.NotFound($"Finding '{id}' not found in project '{key}'.");
            }

            var outcome = FindingTriage.Apply(finding, target, req.Note, DateTimeOffset.UtcNow);
            if (!outcome.Success)
            {
                return Results.BadRequest(outcome.Error);
            }

            await db.SaveChangesAsync();
            await audit.RecordAsync(ActorOf(actor), "finding.triage", finding.VulnerabilityId, $"{key}: {target}");
            return Results.Ok(ToDto(finding, DateTimeOffset.UtcNow));
        })
        .RequireAuthorization(policy => policy.RequireRole(RavelinRoles.Admin, RavelinRoles.Analyst))
        .DisableAntiforgery();

        // Per-project SLA posture (open findings only).
        app.MapGet("/api/projects/{key}/sla-summary", async (string key, RavelinDbContext db) =>
        {
            var project = await db.Projects.FirstOrDefaultAsync(p => p.Key == key);
            if (project is null)
            {
                return Results.NotFound($"Project '{key}' not found.");
            }

            var open = await db.Findings
                .Where(f => f.ProjectId == project.Id && f.Status == FindingStatus.Open)
                .Select(f => f.SlaDueAt)
                .ToListAsync();

            var now = DateTimeOffset.UtcNow;
            int onTrack = 0, dueSoon = 0, breached = 0;
            foreach (var dueAt in open)
            {
                switch (SlaEvaluator.Evaluate(FindingStatus.Open, dueAt, now, SlaEvaluator.DefaultDueSoonWindow).State)
                {
                    case SlaState.Breached: breached++; break;
                    case SlaState.DueSoon: dueSoon++; break;
                    default: onTrack++; break;
                }
            }

            var total = open.Count;
            var compliance = total == 0 ? 100.0 : Math.Round((double)(total - breached) / total * 100, 1);

            return Results.Ok(new SlaSummaryDto
            {
                ProjectKey = key,
                Open = total,
                OnTrack = onTrack,
                DueSoon = dueSoon,
                Breached = breached,
                CompliancePercent = compliance,
            });
        })
        .RequireAuthorization();
    }

    // --- Helpers ------------------------------------------------------------------------
    private static Severity ParseSeverity(string? value) => SeverityMap.Parse(value);

    /// <summary>The acting user's email for audit records (NameClaimType is "email").</summary>
    private static string ActorOf(ClaimsPrincipal user) =>
        user.Identity?.Name ?? user.FindFirstValue("email") ?? "unknown";

    /// <summary>A cryptographically-random 16-char password that satisfies the Identity policy
    /// (upper/lower/digit/symbol, ≥12). Used for admin-initiated resets (no email).</summary>
    private static string GenerateTempPassword()
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lower = "abcdefghijkmnpqrstuvwxyz";
        const string digit = "23456789";
        const string symbol = "!#%-_=+";
        var all = upper + lower + digit + symbol;
        static char Pick(string set) => set[System.Security.Cryptography.RandomNumberGenerator.GetInt32(set.Length)];

        var chars = new List<char> { Pick(upper), Pick(lower), Pick(digit), Pick(symbol) };
        while (chars.Count < 16) chars.Add(Pick(all));
        // Fisher–Yates shuffle so the guaranteed-class characters aren't always first.
        for (var i = chars.Count - 1; i > 0; i--)
        {
            var j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string([.. chars]);
    }

    private static ProjectDto ToDto(Project p, int openFindings) => new()
    {
        Id = p.Id,
        Key = p.Key,
        Name = p.Name,
        RepositoryUrl = p.RepositoryUrl,
        OpenFindings = openFindings,
    };

    private static FindingDto ToDto(Finding f, DateTimeOffset now)
    {
        var sla = SlaEvaluator.Evaluate(f, now);
        return new FindingDto
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
            SlaBreached = sla.IsBreached,
            SlaState = sla.State.ToString(),
            DaysToSla = sla.DaysRemaining,
        };
    }
}
