using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class AppErrorConfiguration : IEntityTypeConfiguration<AppError>
{
    public void Configure(EntityTypeBuilder<AppError> builder)
    {
        builder.HasKey(e => e.Id);

        // Dedup identity: one row per fault (SHA-256 hex is 64 chars).
        builder.Property(e => e.Fingerprint).IsRequired().HasMaxLength(64);
        builder.HasIndex(e => e.Fingerprint).IsUnique();

        builder.Property(e => e.ExceptionType).IsRequired().HasMaxLength(256);
        builder.Property(e => e.Message).HasMaxLength(2000);
        builder.Property(e => e.StackExcerpt).HasMaxLength(4000);
        builder.Property(e => e.RequestMethod).HasMaxLength(16);
        builder.Property(e => e.RequestPath).HasMaxLength(512);
        builder.Property(e => e.LastCorrelationId).HasMaxLength(64);

        // Enum as string, matching the Finding/FindingAlert mapping convention.
        builder.Property(e => e.Status).HasConversion<string>().HasMaxLength(16);

        builder.Property(e => e.IssueIdentifier).HasMaxLength(64);
        builder.Property(e => e.IssueUrl).HasMaxLength(512);

        // Triage/dashboard lookups: open errors, most-recent first.
        builder.HasIndex(e => new { e.Status, e.LastSeenAt });
    }
}
