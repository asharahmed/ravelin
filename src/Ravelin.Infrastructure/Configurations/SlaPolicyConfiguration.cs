using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;

namespace Ravelin.Infrastructure.Configurations;

public class SlaPolicyConfiguration : IEntityTypeConfiguration<SlaPolicy>
{
    // Fixed Ids so the seed data is deterministic across migrations.
    private static readonly Guid CriticalId = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid HighId = new("22222222-2222-2222-2222-222222222222");
    private static readonly Guid MediumId = new("33333333-3333-3333-3333-333333333333");
    private static readonly Guid LowId = new("44444444-4444-4444-4444-444444444444");

    public void Configure(EntityTypeBuilder<SlaPolicy> builder)
    {
        builder.HasKey(p => p.Id);

        builder.Property(p => p.Severity).HasConversion<string>().HasMaxLength(20);

        // One policy per severity.
        builder.HasIndex(p => p.Severity).IsUnique();

        // Seed the agreed default SLAs (Critical 7 / High 30 / Medium 90 / Low 180 days).
        builder.HasData(
            new SlaPolicy { Id = CriticalId, Severity = Severity.Critical, RemediationDays = 7 },
            new SlaPolicy { Id = HighId, Severity = Severity.High, RemediationDays = 30 },
            new SlaPolicy { Id = MediumId, Severity = Severity.Medium, RemediationDays = 90 },
            new SlaPolicy { Id = LowId, Severity = Severity.Low, RemediationDays = 180 });
    }
}
