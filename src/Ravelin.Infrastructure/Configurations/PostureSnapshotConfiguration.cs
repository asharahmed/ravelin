using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class PostureSnapshotConfiguration : IEntityTypeConfiguration<PostureSnapshot>
{
    public void Configure(EntityTypeBuilder<PostureSnapshot> builder)
    {
        builder.HasKey(s => s.Id);

        // One snapshot per calendar day — the DB invariant that keeps history append-only and
        // makes the nightly "ensure" idempotent + safe across replicas.
        builder.HasIndex(s => s.SnapshotDate).IsUnique();
    }
}
