using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Playwright;
using Testcontainers.MsSql;

namespace Ravelin.E2ETests;

/// <summary>
/// The "live environment" for end-to-end tests: a throwaway SQL Server container plus the REAL
/// Ravelin app launched as its own OS process on a real Kestrel port against that database, then
/// driven by a real Chromium browser via Playwright. This is the closest tier to production short
/// of the deployed container — real HTTP, real WASM boot in a real browser, real database — so a
/// journey that passes here genuinely works, not just inside an in-memory TestServer.
/// </summary>
public sealed class LiveAppFixture : IAsyncLifetime
{
    public const string AdminEmail = "admin@ravelin.test";
    // Satisfies the 12-char minimum + Identity's default complexity (upper/lower/digit/symbol).
    public const string AdminPassword = "E2e!Sup3r-Secret-Pw";

    private readonly MsSqlContainer _sql = new MsSqlBuilder().Build();
    private readonly StringBuilder _appLog = new();
    private Process _app = null!;
    private IPlaywright _playwright = null!;

    public IBrowser Browser { get; private set; } = null!;
    public string BaseUrl { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _sql.StartAsync();

        BaseUrl = $"http://127.0.0.1:{GetFreePort()}";
        _app = StartApp(_sql.GetConnectionString(), BaseUrl);
        await WaitForHealthyAsync(TimeSpan.FromSeconds(120));

        _playwright = await Playwright.CreateAsync();
        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
    }

    /// <summary>A fresh page with a generous default timeout — the first navigation pays the
    /// one-time cost of the browser downloading and booting the Blazor WASM runtime.</summary>
    public async Task<IPage> NewPageAsync()
    {
        var page = await Browser.NewPageAsync(new BrowserNewPageOptions { IgnoreHTTPSErrors = true });
        page.SetDefaultTimeout(60_000);
        return page;
    }

    private Process StartApp(string connectionString, string baseUrl)
    {
        // CI publishes the host and points RAVELIN_E2E_APP_DLL at it; locally, fall back to the
        // build output discovered relative to the repo root.
        var dll = Environment.GetEnvironmentVariable("RAVELIN_E2E_APP_DLL") ?? FindHostDll();

        var appDir = Path.GetDirectoryName(dll)!;
        var psi = new ProcessStartInfo("dotnet", $"\"{dll}\"")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            // Run from the app's own folder so the content root (and thus wwwroot, where the
            // Blazor WASM bundle lives) resolves correctly. Without this it defaults to the
            // test's cwd, so /_framework/* 404s and the WASM runtime never boots.
            WorkingDirectory = appDir,
        };
        var env = psi.Environment;
        env["ASPNETCORE_ENVIRONMENT"] = "Testing";
        env["ASPNETCORE_CONTENTROOT"] = appDir; // explicit, belt-and-suspenders with WorkingDirectory
        env["ASPNETCORE_URLS"] = baseUrl;
        env["ConnectionStrings__RavelinDb"] = connectionString;
        // A real signing key so login issues a verifiable JWT (the default is empty, which throws).
        env["Jwt__SigningKey"] = "ravelin-e2e-signing-key-0123456789-abcdefghij";
        env["Jwt__Issuer"] = "ravelin";
        env["Jwt__Audience"] = "ravelin";
        // Seed a known admin so the login journey has real credentials (no default ever ships).
        env["Seed__AdminEmail"] = AdminEmail;
        env["Seed__AdminPassword"] = AdminPassword;

        var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        proc.OutputDataReceived += (_, e) => Capture(e.Data);
        proc.ErrorDataReceived += (_, e) => Capture(e.Data);
        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        return proc;
    }

    private void Capture(string? line)
    {
        if (line is null) return;
        lock (_appLog) _appLog.AppendLine(line);
    }

    private async Task WaitForHealthyAsync(TimeSpan timeout)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (_app.HasExited)
            {
                throw new InvalidOperationException(
                    $"App process exited early (code {_app.ExitCode}).\n--- app log ---\n{AppLog()}");
            }
            try
            {
                var res = await http.GetAsync($"{BaseUrl}/health");
                if (res.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch
            {
                // Not listening yet — keep polling.
            }
            await Task.Delay(500);
        }
        throw new TimeoutException($"App did not become healthy within {timeout}.\n--- app log ---\n{AppLog()}");
    }

    private string AppLog()
    {
        lock (_appLog) return _appLog.ToString();
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string FindHostDll()
    {
        // Walk up from the test output dir to the repo root (marked by Ravelin.slnx).
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Ravelin.slnx")))
        {
            dir = dir.Parent;
        }
        if (dir is null)
        {
            throw new InvalidOperationException("Could not locate the repo root (Ravelin.slnx).");
        }

        var dll = Path.Combine(dir.FullName, "src", "Ravelin", "bin", "Release", "net10.0", "Ravelin.dll");
        if (!File.Exists(dll))
        {
            throw new FileNotFoundException(
                $"Host app not found at {dll}. Set RAVELIN_E2E_APP_DLL or build/publish the host first.");
        }
        return dll;
    }

    public async Task DisposeAsync()
    {
        if (Browser is not null)
        {
            await Browser.DisposeAsync();
        }
        _playwright?.Dispose();

        if (_app is not null && !_app.HasExited)
        {
            try { _app.Kill(entireProcessTree: true); } catch { /* already gone */ }
            await _app.WaitForExitAsync();
        }
        _app?.Dispose();

        await _sql.DisposeAsync();
    }
}

/// <summary>One live app + browser shared across the E2E collection (tests run sequentially).</summary>
[CollectionDefinition(Name)]
public sealed class LiveAppCollection : ICollectionFixture<LiveAppFixture>
{
    public const string Name = "ravelin-e2e";
}
