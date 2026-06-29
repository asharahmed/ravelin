using Microsoft.Playwright;

namespace Ravelin.E2ETests;

/// <summary>
/// Real-browser journeys against the live app. These exercise the entire stack a user touches:
/// Kestrel serving the Blazor WASM bundle, the runtime booting in Chromium, client-side routing
/// and auth, and the authenticated API calls back to the server over real HTTP.
/// </summary>
[Collection(LiveAppCollection.Name)]
public sealed class LiveJourneyTests(LiveAppFixture app)
{
    [Fact]
    public async Task LandingPage_BootsWasm_AndRendersHero()
    {
        var page = await app.NewPageAsync();
        await page.GotoAsync(app.BaseUrl);

        // The hero is rendered by Blazor WASM (prerender:false). Seeing its text proves the
        // runtime downloaded and booted in a real browser, then rendered the component tree.
        await Assertions.Expect(page.Locator("h1.hero-title"))
            .ToContainTextAsync("Every vulnerability", new() { Timeout = 60_000 });
    }

    [Fact]
    public async Task Login_AsSeededAdmin_RedirectsToDashboard()
    {
        var page = await app.NewPageAsync();
        await page.GotoAsync($"{app.BaseUrl}/login");

        await page.FillAsync("#email", LiveAppFixture.AdminEmail);
        await page.FillAsync("#password", LiveAppFixture.AdminPassword);
        await page.ClickAsync("button.auth-submit");

        // Successful auth (real /api/auth/login -> JWT -> localStorage) routes to the protected
        // dashboard, whose header renders only once the client auth state lets the route through.
        await page.WaitForURLAsync("**/dashboard", new() { Timeout = 60_000 });
        await Assertions.Expect(page.Locator("h1.dash-title"))
            .ToContainTextAsync("Security posture", new() { Timeout = 60_000 });
    }
}
