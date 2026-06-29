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
        var diag = BrowserDiagnostics.Attach(page);
        await page.GotoAsync(app.BaseUrl);

        // The hero is rendered by Blazor WASM (prerender:false). Seeing its text proves the
        // runtime downloaded and booted in a real browser, then rendered the component tree.
        await AssertOrReport(diag, () => Assertions.Expect(page.Locator("h1.hero-title"))
            .ToContainTextAsync("Every vulnerability", new() { Timeout = 60_000 }));
    }

    [Fact]
    public async Task Login_AsSeededAdmin_RedirectsToDashboard()
    {
        var page = await app.NewPageAsync();
        var diag = BrowserDiagnostics.Attach(page);
        await page.GotoAsync($"{app.BaseUrl}/login");

        await page.FillAsync("#email", LiveAppFixture.AdminEmail);
        await page.FillAsync("#password", LiveAppFixture.AdminPassword);
        await page.ClickAsync("button.auth-submit");

        // Successful auth (real /api/auth/login -> JWT -> localStorage) routes to the protected
        // dashboard, whose header renders only once the client auth state lets the route through.
        await AssertOrReport(diag, async () =>
        {
            await page.WaitForURLAsync("**/dashboard", new() { Timeout = 60_000 });
            await Assertions.Expect(page.Locator("h1.dash-title"))
                .ToContainTextAsync("Security posture", new() { Timeout = 60_000 });
        });
    }

    // Runs a Playwright assertion; on failure, enriches the error with what the browser actually
    // saw (failed asset loads, console errors, a page-content snippet) so a red run is diagnosable.
    private static async Task AssertOrReport(Func<Task<string>> diagnostics, Func<Task> assertion)
    {
        try
        {
            await assertion();
        }
        catch (Exception ex)
        {
            throw new Xunit.Sdk.XunitException($"{ex.Message}\n\n{await diagnostics()}");
        }
    }
}

/// <summary>Collects browser-side signals (failed responses, console/page errors, final HTML)
/// so an E2E failure explains itself instead of surfacing as a bare timeout.</summary>
internal static class BrowserDiagnostics
{
    public static Func<Task<string>> Attach(IPage page)
    {
        var badResponses = new List<string>();
        var consoleErrors = new List<string>();

        page.Response += (_, res) =>
        {
            if (res.Status >= 400)
            {
                badResponses.Add($"{res.Status} {res.Url}");
            }
        };
        page.Console += (_, msg) =>
        {
            if (msg.Type is "error" or "warning")
            {
                consoleErrors.Add($"[{msg.Type}] {msg.Text}");
            }
        };
        page.PageError += (_, err) => consoleErrors.Add($"[pageerror] {err}");

        return async () =>
        {
            string html;
            try { html = await page.ContentAsync(); }
            catch { html = "(could not read page content)"; }
            var snippet = html.Length > 1000 ? html[..1000] : html;

            return "--- browser diagnostics ---\n" +
                   $"failed responses (>=400):\n{Join(badResponses)}\n" +
                   $"console errors/warnings:\n{Join(consoleErrors)}\n" +
                   $"page html (first 1000 chars):\n{snippet}";
        };

        static string Join(List<string> items) =>
            items.Count == 0 ? "  (none)" : "  " + string.Join("\n  ", items);
    }
}
