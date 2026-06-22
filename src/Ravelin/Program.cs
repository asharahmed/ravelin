using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
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

// Liveness/readiness probe used locally and by Azure Container Apps (Stage 1).
builder.Services.AddHealthChecks();

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
    .AddEntityFrameworkStores<RavelinDbContext>();

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
// Health probe + info endpoint (anonymous).
app.MapHealthChecks("/health");

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

// Auth (login -> JWT), ingestion (API key), admin (Admin role) + reads (any authenticated
// user). See Endpoints/RavelinEndpoints.cs.
app.MapRavelinApi();
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
