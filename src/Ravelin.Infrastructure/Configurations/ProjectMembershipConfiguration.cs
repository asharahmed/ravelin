using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Configurations;

public class ProjectMembershipConfiguration : IEntityTypeConfiguration<ProjectMembership>
{
    public void Configure(EntityTypeBuilder<ProjectMembership> builder)
    {
        builder.HasKey(m => m.Id);

        builder.Property(m => m.UserId).IsRequired().HasMaxLength(450); // AspNetUsers.Id length
        builder.Property(m => m.GrantedBy).HasMaxLength(256);

        // One membership row per (user, project).
        builder.HasIndex(m => new { m.UserId, m.ProjectId }).IsUnique();

        // Membership is deleted with its project.
        builder.HasOne(m => m.Project)
            .WithMany()
            .HasForeignKey(m => m.ProjectId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
