using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class ApiKeyConfiguration : IEntityTypeConfiguration<ApiKey>
{
    public void Configure(EntityTypeBuilder<ApiKey> builder)
    {
        builder.HasKey(k => k.Id);

        builder.Property(k => k.Name).IsRequired().HasMaxLength(200);
        builder.Property(k => k.KeyHash).IsRequired().HasMaxLength(128);
        builder.Property(k => k.KeyPrefix).IsRequired().HasMaxLength(20);

        builder.Ignore(k => k.IsActive);

        // Lookups during authentication are by hash.
        builder.HasIndex(k => k.KeyHash).IsUnique();

        builder.HasOne(k => k.Project)
            .WithMany()
            .HasForeignKey(k => k.ProjectId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
