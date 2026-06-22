using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure;

/// <summary>
/// EF Core context for Ravelin. Extends IdentityDbContext so ASP.NET Core Identity user/role
/// tables live alongside the domain tables. Domain entity mappings live in
/// IEntityTypeConfiguration classes (see Configurations/), applied by convention.
/// </summary>
public class RavelinDbContext(DbContextOptions<RavelinDbContext> options)
    : IdentityDbContext<IdentityUser>(options)
{
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<SlaPolicy> SlaPolicies => Set<SlaPolicy>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder); // Identity schema
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(RavelinDbContext).Assembly);
    }
}
