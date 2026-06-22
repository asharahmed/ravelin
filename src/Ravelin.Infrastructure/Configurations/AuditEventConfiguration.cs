using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Actor).IsRequired().HasMaxLength(256);
        builder.Property(e => e.Action).IsRequired().HasMaxLength(64);
        builder.Property(e => e.Target).HasMaxLength(256);
        builder.Property(e => e.Detail).HasMaxLength(1024);

        // The log is read newest-first.
        builder.HasIndex(e => e.At).IsDescending();
    }
}
