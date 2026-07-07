using System.Text;
using System.Threading.RateLimiting;
using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Ravelin.Auth;
using Ravelin.Client.Pages;
using Ravelin.Components;
using Ravelin.Endpoints;
using Ravelin.Infrastructure;
using Ravelin.Shared;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

// Health checks: a liveness probe (process is up) plus a DB-backed readiness probe (can we
// actually serve?). Container Apps points its liveness/readiness probes at the two paths below.
builder.Services.AddHealthChecks()
    .AddDbContextCheck<RavelinDbContext>("db", tags: ["ready"]);

// Standardise error responses as RFC 9457 ProblemDetails (JSON) across the API.
builder.Services.AddProblemDetails();

// Persist DataProtection keys so antiforgery + password-reset tokens survive restarts and
// scale-out. In Azure: an encrypted blob, read via the app's user-assigned managed identity.
// Unset (local dev): the framework default (file-system / ephemeral).
var dpBlobUri = builder.Configuration["DataProtection:BlobUri"];
if (!string.IsNullOrWhiteSpace(dpBlobUri))
{
    var dpClientId = builder.Configuration["DataProtection:IdentityClientId"];
    TokenCredential dpCredential = string.IsNullOrWhiteSpace(dpClientId)
        ? new DefaultAzureCredential()
        : new ManagedIdentityCredential(dpClientId);
    builder.Services.AddDataProtection()
        .SetApplicationName("Ravelin")
        .PersistKeysToAzureBlobStorage(new Uri(dpBlobUri), dpCredential);
}

// OpenAPI document generation (API-first: the spec is published, see /openapi/v1.json).
builder.Services.AddOpenApi();

// Behind Azure Container Apps' ingress: trust X-Forwarded-* so the real client IP/scheme
// is used (rate limiting partitions by client IP; https scheme avoids redirect loops).
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

// Rate limiting: cap brute-force on auth and abuse on ingestion, partitioned per client IP.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    static string ClientKey(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    options.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ClientKey(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));
    options.AddPolicy("ingest", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ClientKey(ctx), _ => new FixedWindowRateLimiterOptions { PermitLimit = 60, Window = TimeSpan.FromMinutes(1) }));
});

// EF Core / Azure SQL + application services. Connection string comes from configuration
// ("ConnectionStrings:RavelinDb"); in Azure Container Apps it's injected as the env var
// ConnectionStrings__RavelinDb (a secret). Migrations are applied out-of-band.
builder.Services.AddRavelinInfrastructure(builder.Configuration.GetConnectionString("RavelinDb"));
// Files captured errors as Linear issues when Linear:ApiKey + Linear:TeamId are configured;
// otherwise inert (no-op tracker). The capture pipeline works with or without it.
builder.Services.AddLinearIssueTracker(builder.Configuration);
// Enriches findings with CISA-KEV + FIRST-EPSS exploitation intelligence and drives the
// risk-adjusted SLA — active when VulnIntel:Enabled=true, otherwise inert (no external calls).
builder.Services.AddVulnerabilityIntelligence(builder.Configuration);

// Outbound webhook/Slack delivery for SLA alerts (short timeout; failures are swallowed).
builder.Services.AddHttpClient("webhooks", c => c.Timeout = TimeSpan.FromSeconds(5));
// Hourly SLA re-evaluation so breaches surface + notify without anyone loading a page.
// (Needs at least one running replica — see min_replicas in Terraform.)
builder.Services.AddHostedService<Ravelin.BackgroundServices.SlaReEvaluationHostedService>();

// --- Identity (users + roles) -------------------------------------------------
builder.Services.AddIdentityCore<IdentityUser>(options =>
    {
        options.Password.RequiredLength = 12;
        options.User.RequireUniqueEmail = true;
        // Lock an account after repeated failed logins (per-account brute-force defence,
        // complementing the per-IP rate limit). Uses existing Identity columns — no migration.
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<RavelinDbContext>()
    // Token providers back password-reset tokens (admin-initiated reset; no email).
    .AddDefaultTokenProviders();

// --- AuthN: JWT for humans (default), API keys for pipeline ingestion ----------
var jwtSection = builder.Configuration.GetSection(JwtOptions.SectionName);
builder.Services.Configure<JwtOptions>(jwtSection);
builder.Services.AddScoped<JwtTokenService>();
var jwt = jwtSection.Get<JwtOptions>() ?? new JwtOptions();

// Fail closed on the signing key. A security tool must NEVER validate tokens against a
// guessable key: in Production the key MUST be supplied (from Key Vault) and be long enough
// for HMAC-SHA256. Outside Production we substitute a fixed, clearly-non-secret development
// key so local runs and the test host boot — the effective key is resolved once here so the
// token ISSUER (JwtTokenService) and the VALIDATOR below always agree.
if (string.IsNullOrWhiteSpace(jwt.SigningKey) || Encoding.UTF8.GetByteCount(jwt.SigningKey) < 32)
{
    if (builder.Environment.IsProduction())
    {
        throw new InvalidOperationException(
            "Jwt:SigningKey must be configured with at least 32 bytes in Production (delivered " +
            "from Key Vault). Refusing to start with a missing or weak signing key.");
    }

    jwt.SigningKey = "ravelin-development-only-signing-key-do-not-use-in-production-0123456789";
    builder.Services.PostConfigure<JwtOptions>(o => o.SigningKey = jwt.SigningKey);
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Keep claim names as-is ("role", "email") instead of remapping to long URIs,
        // so RoleClaimType/NameClaimType below match the token and RequireRole works.
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = JwtTokenService.RoleClaim,
            NameClaimType = "email",
        };
    })
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationHandler.SchemeName, _ => { });

builder.Services.AddAuthorization();

var app = builder.Build();

// Apply role + seed-user setup at startup. A transient DB outage here must not take the
// whole app down — log and continue; seeding is idempotent and retried on next start.
try
{
    // Apply any pending EF migrations on boot so a deploy is self-contained (no out-of-band
    // migration step). Idempotent; EF takes a SQL migration lock so concurrent instances are safe.
    using (var scope = app.Services.CreateScope())
    {
        await scope.ServiceProvider.GetRequiredService<RavelinDbContext>().Database.MigrateAsync();
    }
    await IdentitySeeder.SeedAsync(app.Services, app.Configuration);
    // Optional: seed realistic demo data for the public showcase (gated by Seed:DemoData).
    await DemoDataSeeder.SeedAsync(app.Services, app.Configuration);
}
catch (Exception ex)
{
    app.Services.GetRequiredService<ILogger<Program>>()
        .LogError(ex, "Startup seeding failed; continuing without it.");
}

// Honour the ingress's forwarded headers first, so downstream sees the real client IP/scheme.
app.UseForwardedHeaders();

// Correlation id + a single structured log line per request.
app.UseMiddleware<Ravelin.Middleware.CorrelationIdMiddleware>();

// Security response headers. The CSP guards the app UI; the Scalar reference and the OpenAPI
// spec are excluded (Scalar's bundle needs different sources). script-src keeps 'unsafe-inline'
// only because Blazor emits an inline import map — everything else is locked to same-origin.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";

    var path = context.Request.Path;
    if (!path.StartsWithSegments("/scalar") && !path.StartsWithSegments("/openapi"))
    {
        headers["Content-Security-Policy"] =
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; " +
            "script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'";
    }
    await next();
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
// Friendly status-code pages apply to the Blazor UI only. API routes (/api/*) must return
// real status codes / problem details, not re-execute (as the original method) into an HTML
// page — which would turn a 401 into a 400 and break API clients.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/api"),
    branch => branch.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));
app.UseHttpsRedirection();

// Capture unhandled exceptions into the AppError store. Sits below the exception handler so it
// records the fault first, then rethrows for the normal error response. Best-effort; never masks.
app.UseMiddleware<Ravelin.Middleware.ErrorCaptureMiddleware>();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseAntiforgery();

app.MapStaticAssets();

// --- API surface --------------------------------------------------------------
// Health probes (anonymous). Liveness = process up; readiness = DB reachable. /health stays as
// a liveness alias for backward-compatible probes/scripts.
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready") });
app.MapHealthChecks("/health", new HealthCheckOptions { Predicate = _ => false });

// Published OpenAPI document + an interactive API reference at /scalar. Anonymous (it's
// documentation); the endpoints it describes stay authenticated.
app.MapOpenApi();
app.MapScalarApiReference(options => options
    .WithTitle("Ravelin API")
    .WithTheme(ScalarTheme.BluePlanet));

var apiInfo = new ApiInfo(
    Name: "Ravelin",
    Description: "Vulnerability SLA & compliance tracker",
    Version: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
    Environment: app.Environment.EnvironmentName);

app.MapGet("/api/info", () => apiInfo);

// Responsible-disclosure policy (RFC 9116). Apt for a security product.
app.MapGet("/.well-known/security.txt", () => Results.Text(
    "Contact: mailto:ashar@aahmed.ca\n" +
    "Expires: 2027-06-22T00:00:00.000Z\n" +
    "Preferred-Languages: en\n" +
    "Canonical: https://getravelin.xyz/.well-known/security.txt\n",
    "text/plain"));

// Auth (login -> JWT), ingestion (API key), admin (Admin role) + reads (any authenticated
// user). See Endpoints/RavelinEndpoints.cs.
app.MapRavelinApi();

// Internal: trigger an SLA re-evaluation. Gated by a shared secret header (NOT a JWT) so a
// scheduled Container Apps cron Job (alerts-job.tf) can fire it hourly while the app stays
// scale-to-zero. Returns 404 (disabled) when no token is configured.
app.MapPost("/api/internal/reevaluate", async (
    HttpContext http, IConfiguration config, Ravelin.Infrastructure.Services.SlaReEvaluator reEvaluator) =>
{
    var expected = config["Reeval:Token"];
    if (string.IsNullOrEmpty(expected)) return Results.NotFound();

    var provided = http.Request.Headers["X-Reeval-Token"].ToString();
    var ok = provided.Length > 0 && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
        System.Text.Encoding.UTF8.GetBytes(provided), System.Text.Encoding.UTF8.GetBytes(expected));
    if (!ok) return Results.Unauthorized();

    var r = await reEvaluator.ReEvaluateAsync();
    return Results.Ok(new Ravelin.Shared.Contracts.ReEvaluateSummaryDto
    {
        Scanned = r.Scanned, NewBreached = r.NewBreached, NewDueSoon = r.NewDueSoon, Notified = r.Notified,
    });
})
.DisableAntiforgery();

// Test-only: a route that throws an unhandled exception so the error-capture pipeline can be
// exercised end-to-end (integration tests). NEVER mapped in Production. The token is echoed into
// the message purely to prove secret-scrubbing on the way into the AppError store.
if (!app.Environment.IsProduction())
{
    app.MapGet("/api/_test/throw", (string? token) =>
    {
        throw new InvalidOperationException($"Intentional test exception (token={token}).");
    }).AllowAnonymous();
}

// Unmapped /api/* paths return a real 404 (JSON problem), not the Blazor SPA shell, so API
// consumers hitting a wrong route get a proper status instead of HTML.
app.Map("/api/{**rest}", () => Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Not Found"));
// ------------------------------------------------------------------------------

app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(Ravelin.Client._Imports).Assembly)
    // The Blazor pages render interactively in WASM (prerender:false) and authenticate
    // entirely client-side (JWT in localStorage). Their `[Authorize]` attributes are
    // enforced by the client router's AuthorizeRouteView. The SERVER must therefore serve
    // the page shell anonymously — otherwise a hard-load / refresh of a protected route
    // (e.g. /dashboard) is challenged by JwtBearer (the default scheme), which the server
    // can't satisfy, yielding a 404. The real security boundary is the /api/* surface,
    // which stays authenticated. See RavelinEndpoints for the authorized API.
    .AllowAnonymous();

app.Run();

// Top-level statements compile to an internal Program class. Expose it as public so the
// integration test project can drive the real host via WebApplicationFactory<Program>.
public partial class Program;
