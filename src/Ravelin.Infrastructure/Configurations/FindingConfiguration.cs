using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class FindingConfiguration : IEntityTypeConfiguration<Finding>
{
    public void Configure(EntityTypeBuilder<Finding> builder)
    {
        builder.HasKey(f => f.Id);

        builder.Property(f => f.VulnerabilityId).IsRequired().HasMaxLength(100);
        builder.Property(f => f.PackageName).IsRequired().HasMaxLength(200);
        builder.Property(f => f.PackageVersion).IsRequired().HasMaxLength(100);
        builder.Property(f => f.Title).IsRequired().HasMaxLength(500);
        builder.Property(f => f.FixedVersion).HasMaxLength(100);
        // Description and TriageNote left as nvarchar(max).

        builder.Property(f => f.Severity).HasConversion<string>().HasMaxLength(20);
        builder.Property(f => f.Status).HasConversion<string>().HasMaxLength(20);

        // Optimistic-concurrency token (SQL rowversion): protects against a concurrent ingest +
        // triage silently clobbering each other on the same finding.
        builder.Property(f => f.RowVersion).IsRowVersion();

        // Dedup identity: the same vuln on the same package+version in a project is one finding.
        builder.HasIndex(f => new { f.ProjectId, f.VulnerabilityId, f.PackageName, f.PackageVersion })
            .IsUnique();

        // Common dashboard filter: open findings per project.
        builder.HasIndex(f => new { f.ProjectId, f.Status });

        // Fast lookup of actively-exploited findings (dashboard KEV count, risk-sorted lists).
        builder.HasIndex(f => new { f.ProjectId, f.IsKnownExploited });
    }
}
