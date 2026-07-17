namespace Ravelin.Domain.Entities;

/// <summary>
/// Grants a user visibility of a private project. Reads are scoped to the projects a user can
/// see: public projects (visible to any authenticated user), the projects they are a member of,
/// and — for Admins — all projects. A user's global role (Admin/Analyst/Viewer) still governs
/// what actions they may take; membership governs which projects' data they can see.
/// </summary>
public class ProjectMembership
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The Identity user id (AspNetUsers.Id).</summary>
    public required string UserId { get; set; }

    public required Guid ProjectId { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Who granted the membership (email), for the audit trail.</summary>
    public string? GrantedBy { get; set; }

    // Navigation
    public Project? Project { get; set; }
}
