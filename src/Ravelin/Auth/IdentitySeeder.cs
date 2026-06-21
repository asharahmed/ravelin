using Microsoft.AspNetCore.Identity;
using Ravelin.Shared;

namespace Ravelin.Auth;

/// <summary>
/// Ensures the RBAC roles exist and seeds initial users from configuration. Users are only
/// created when a password is configured (Seed:AdminPassword / Seed:DemoPassword), so no
/// default credentials ever ship. Runs once at startup.
/// </summary>
public static class IdentitySeeder
{
    public static async Task SeedAsync(IServiceProvider services, IConfiguration config)
    {
        using var scope = services.CreateScope();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

        foreach (var role in RavelinRoles.All)
        {
            if (!await roles.RoleExistsAsync(role))
            {
                await roles.CreateAsync(new IdentityRole(role));
            }
        }

        await EnsureUserAsync(users,
            config["Seed:AdminEmail"] ?? "admin@ravelin.local",
            config["Seed:AdminPassword"], RavelinRoles.Admin);

        await EnsureUserAsync(users,
            config["Seed:DemoEmail"] ?? "demo@ravelin.local",
            config["Seed:DemoPassword"], RavelinRoles.Viewer);
    }

    private static async Task EnsureUserAsync(
        UserManager<IdentityUser> users, string email, string? password, string role)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return; // No credentials configured — skip (never seed a default password).
        }

        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
            var result = await users.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to seed user {email}: {string.Join("; ", result.Errors.Select(e => e.Description))}");
            }
        }

        if (!await users.IsInRoleAsync(user, role))
        {
            await users.AddToRoleAsync(user, role);
        }
    }
}
