using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Ravelin.Infrastructure;

/// <summary>
/// Design-time factory used by `dotnet ef` (migrations add / database update). It reads the
/// connection string from RAVELIN_DB_CONNECTION; a harmless placeholder is used for
/// `migrations add` (which does not connect), while `database update` needs a real value.
/// At runtime the app configures the context through DI instead (see Program.cs).
/// </summary>
public class RavelinDbContextFactory : IDesignTimeDbContextFactory<RavelinDbContext>
{
    public RavelinDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("RAVELIN_DB_CONNECTION")
            ?? "Server=(placeholder);Database=ravelin;";

        var options = new DbContextOptionsBuilder<RavelinDbContext>()
            .UseSqlServer(connectionString)
            .Options;

        return new RavelinDbContext(options);
    }
}
