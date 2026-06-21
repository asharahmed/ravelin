using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure;

/// <summary>
/// EF Core context for Ravelin. Entity mappings live in IEntityTypeConfiguration classes
/// (see Configurations/) and are applied by convention from this assembly.
/// </summary>
public class RavelinDbContext(DbContextOptions<RavelinDbContext> options) : DbContext(options)
{
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<SlaPolicy> SlaPolicies => Set<SlaPolicy>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(RavelinDbContext).Assembly);
    }
}
