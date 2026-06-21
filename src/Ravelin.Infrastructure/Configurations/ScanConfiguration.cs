using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class ScanConfiguration : IEntityTypeConfiguration<Scan>
{
    public void Configure(EntityTypeBuilder<Scan> builder)
    {
        builder.HasKey(s => s.Id);

        builder.Property(s => s.Tool).IsRequired().HasMaxLength(100);
        builder.Property(s => s.ToolVersion).HasMaxLength(50);

        // Store enum as readable text rather than an opaque integer.
        builder.Property(s => s.Source).HasConversion<string>().HasMaxLength(20);

        // Reconciliation queries fetch a project's scans newest-first.
        builder.HasIndex(s => new { s.ProjectId, s.IngestedAt });
    }
}
