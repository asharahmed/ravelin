using Microsoft.EntityFrameworkCore;
using Ravelin.Domain.Entities;

namespace Ravelin.Infrastructure.Services;

/// <summary>
/// Scopes reads to the projects a user may see: public projects (any authenticated user), the
/// projects the user is a member of, and — for Admins — all projects. A user's global role still
/// governs what they can DO; this governs which projects' data they can SEE.
/// </summary>
public static class ProjectVisibility
{
    /// <summary>Filters a project query to those the user may read (translated to SQL).</summary>
    public static IQueryable<Project> VisibleTo(
        this IQueryable<Project> projects, RavelinDbContext db, string? userId, bool isAdmin)
    {
        if (isAdmin)
        {
            return projects;
        }

        return projects.Where(p =>
            p.IsPublic ||
            (userId != null && db.ProjectMemberships.Any(m => m.ProjectId == p.Id && m.UserId == userId)));
    }

    /// <summary>The set of project ids the user may read — for scoping finding/alert queries.</summary>
    public static Task<HashSet<Guid>> VisibleProjectIdsAsync(
        RavelinDbContext db, string? userId, bool isAdmin, CancellationToken ct = default) =>
        db.Projects.VisibleTo(db, userId, isAdmin).Select(p => p.Id).ToHashSetAsync(ct);

    /// <summary>True when the user may read the given (already-loaded) project.</summary>
    public static async Task<bool> CanReadAsync(
        RavelinDbContext db, Project project, string? userId, bool isAdmin, CancellationToken ct = default)
    {
        if (isAdmin || project.IsPublic)
        {
            return true;
        }
        if (userId is null)
        {
            return false;
        }
        return await db.ProjectMemberships
            .AnyAsync(m => m.ProjectId == project.Id && m.UserId == userId, ct);
    }
}
