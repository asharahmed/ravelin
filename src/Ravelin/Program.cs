using Microsoft.EntityFrameworkCore;
using Ravelin.Client.Pages;
using Ravelin.Components;
using Ravelin.Infrastructure;
using Ravelin.Shared;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

// Liveness/readiness probe used locally and by Azure Container Apps (Stage 1).
builder.Services.AddHealthChecks();

// EF Core / Azure SQL. Connection string comes from configuration
// ("ConnectionStrings:RavelinDb"); in Azure Container Apps it's injected as the
// env var ConnectionStrings__RavelinDb (a secret). Migrations are applied out-of-band.
builder.Services.AddDbContext<RavelinDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("RavelinDb")
        ?? "Server=(unconfigured)"));

var app = builder.Build();

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
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();

// --- API surface (walking skeleton) -------------------------------------------
// Health probe (no auth) and a tiny info endpoint returning the shared ApiInfo
// contract. This is the seed of the API-first backend; richer endpoints
// (ingestion, findings, SLAs) arrive in later stages.
app.MapHealthChecks("/health");

var apiInfo = new ApiInfo(
    Name: "Ravelin",
    Description: "Vulnerability SLA & compliance tracker",
    Version: typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
    Environment: app.Environment.EnvironmentName);

app.MapGet("/api/info", () => apiInfo);

// DB connectivity check (Stage 2 verification; superseded by real endpoints in Stage 3).
// Returns only a coarse status — no exception detail — to avoid information disclosure.
app.MapGet("/api/db/status", async (RavelinDbContext db) =>
{
    if (!await db.Database.CanConnectAsync())
    {
        return Results.Problem("Database not reachable.", statusCode: 503);
    }

    return Results.Ok(new
    {
        connected = true,
        slaPolicies = await db.SlaPolicies.CountAsync(),
        projects = await db.Projects.CountAsync(),
        findings = await db.Findings.CountAsync(),
    });
});
// ------------------------------------------------------------------------------

app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(Ravelin.Client._Imports).Assembly);

app.Run();
