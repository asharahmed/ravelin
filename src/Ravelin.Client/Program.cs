using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Ravelin.Client.Auth;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// --- Auth state + token plumbing ---------------------------------------------
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<TokenStore>();
builder.Services.AddScoped<JwtAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(
    sp => sp.GetRequiredService<JwtAuthenticationStateProvider>());
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<TokenHandler>();

// HttpClient pointed at the host that served this WASM app (same origin as the API),
// with the bearer-token handler attached so authenticated calls carry the JWT.
builder.Services.AddHttpClient("RavelinApi", client =>
        client.BaseAddress = new Uri(builder.HostEnvironment.BaseAddress))
    .AddHttpMessageHandler<TokenHandler>();
builder.Services.AddScoped(sp =>
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("RavelinApi"));

await builder.Build().RunAsync();
