using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class FindingAlertConfiguration : IEntityTypeConfiguration<FindingAlert>
{
    public void Configure(EntityTypeBuilder<FindingAlert> builder)
    {
        builder.HasKey(a => a.Id);

        // Enums stored as strings, matching Finding's Severity/Status mapping.
        builder.Property(a => a.Severity).HasConversion<string>().HasMaxLength(16);
        builder.Property(a => a.State).HasConversion<string>().HasMaxLength(16);
        builder.Property(a => a.AcknowledgedBy).HasMaxLength(256);

        // Idempotency: at most one alert per (finding, state) — re-evaluation never duplicates.
        builder.HasIndex(a => new { a.FindingId, a.State }).IsUnique();
        // Timeline + unacknowledged-count lookups.
        builder.HasIndex(a => new { a.ProjectId, a.RaisedAt });
        builder.HasIndex(a => a.AcknowledgedAt);

        // FK on FindingId only (ProjectId is a denormalised column, no FK → no multiple
        // cascade paths). Deleting a finding cleans up its alerts.
        builder.HasOne<Finding>()
            .WithMany()
            .HasForeignKey(a => a.FindingId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
