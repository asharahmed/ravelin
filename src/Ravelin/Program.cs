using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Ravelin.Auth;
using Ravelin.Client.Pages;
using Ravelin.Components;
using Ravelin.Endpoints;
using Ravelin.Infrastructure;
using Ravelin.Shared;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

// Liveness/readiness probe used locally and by Azure Container Apps (Stage 1).
builder.Services.AddHealthChecks();

// EF Core / Azure SQL + application services. Connection string comes from configuration
// ("ConnectionStrings:RavelinDb"); in Azure Container Apps it's injected as the env var
// ConnectionStrings__RavelinDb (a secret). Migrations are applied out-of-band.
builder.Services.AddRavelinInfrastructure(builder.Configuration.GetConnectionString("RavelinDb"));

// --- Identity (users + roles) -------------------------------------------------
builder.Services.AddIdentityCore<IdentityUser>(options =>
    {
        options.Password.RequiredLength = 12;
        options.User.RequireUniqueEmail = true;
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

// Apply role + seed-user setup at startup.
await IdentitySeeder.SeedAsync(app.Services, app.Configuration);
// Optional: seed realistic demo data for the public showcase (gated by Seed:DemoData).
await DemoDataSeeder.SeedAsync(app.Services, app.Configuration);

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
app.UseAntiforgery();

app.MapStaticAssets();

// --- API surface --------------------------------------------------------------
// Health probe + info endpoint (anonymous).
app.MapHealthChecks("/health");

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
    .AddAdditionalAssemblies(typeof(Ravelin.Client._Imports).Assembly);

app.Run();
