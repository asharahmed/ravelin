namespace Ravelin.Shared.Contracts;

/// <summary>Cross-project security-posture rollup powering the overview dashboard.</summary>
public record DashboardDto
{
    public required int ProjectCount { get; init; }
    public required int TotalOpen { get; init; }
    public required int Breached { get; init; }
    public required int DueSoon { get; init; }
    public required int OnTrack { get; init; }

    /// <summary>Share of open findings within SLA across all projects (0–100; 100 when none open).</summary>
    public required double CompliancePercent { get; init; }

    /// <summary>Open findings whose CVE is in the CISA KEV catalog (actively exploited).</summary>
    public int ActivelyExploited { get; init; }

    public required SeverityCountsDto OpenBySeverity { get; init; }
    public required IReadOnlyList<ProjectPostureDto> Projects { get; init; }

    /// <summary>Opened-vs-resolved counts per week, oldest first.</summary>
    public required IReadOnlyList<TrendPointDto> Trend { get; init; }
}

/// <summary>Open-finding counts by severity.</summary>
public record SeverityCountsDto
{
    public required int Critical { get; init; }
    public required int High { get; init; }
    public required int Medium { get; init; }
    public required int Low { get; init; }
    public int Unknown { get; init; }
}

/// <summary>One project's SLA posture (open findings only).</summary>
public record ProjectPostureDto
{
    public required string Key { get; init; }
    public required string Name { get; init; }
    public required int Open { get; init; }
    public required int Breached { get; init; }
    public required int DueSoon { get; init; }
    public required double CompliancePercent { get; init; }
}

/// <summary>One week of finding flow for the trend chart.</summary>
public record TrendPointDto
{
    public required DateTimeOffset WeekStart { get; init; }
    public required int Opened { get; init; }
    public required int Resolved { get; init; }
}

/// <summary>An immutable, point-in-time record of org posture (one per day). Historical figures
/// don't change as live deadlines pass — the number an auditor saw stays fixed.</summary>
public record PostureSnapshotDto
{
    public required DateOnly Date { get; init; }
    public required int ProjectCount { get; init; }
    public required int TotalOpen { get; init; }
    public required int Breached { get; init; }
    public required int DueSoon { get; init; }
    public required int OnTrack { get; init; }
    public required double CompliancePercent { get; init; }
    public required int ActivelyExploited { get; init; }
    public required SeverityCountsDto OpenBySeverity { get; init; }
}
