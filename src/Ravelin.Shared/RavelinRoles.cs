namespace Ravelin.Shared;

/// <summary>Role names used for RBAC across the API and the Blazor UI.</summary>
public static class RavelinRoles
{
    /// <summary>Full control: manage projects, API keys, SLA policies, users.</summary>
    public const string Admin = "Admin";

    /// <summary>Triages findings (false-positive / accepted-risk), reads everything.</summary>
    public const string Analyst = "Analyst";

    /// <summary>Read-only access to dashboards and reports.</summary>
    public const string Viewer = "Viewer";

    public static readonly IReadOnlyList<string> All = [Admin, Analyst, Viewer];
}
