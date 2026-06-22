using System.Text;
using System.Threading.RateLimiting;
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
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwt.SigningKey.Length > 0 ? jwt.SigningKey : new string('0', 32))),
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
