namespace Ravelin.Domain.Entities;

/// <summary>
/// An append-only, point-in-time record of the organisation's security posture. The live
/// dashboard/trend is recomputed from current findings and so silently changes as deadlines pass;
/// a snapshot preserves what was true on a given day, so the compliance figure an auditor saw last
/// quarter still reads the same today. One snapshot per calendar day (UTC); never updated.
/// </summary>
public class PostureSnapshot
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The UTC calendar day this snapshot represents. Unique — one snapshot per day.</summary>
    public required DateOnly SnapshotDate { get; set; }

    /// <summary>When the snapshot was actually written.</summary>
    public DateTimeOffset TakenAt { get; set; } = DateTimeOffset.UtcNow;

    public int ProjectCount { get; set; }
    public int TotalOpen { get; set; }
    public int Breached { get; set; }
    public int DueSoon { get; set; }
    public int OnTrack { get; set; }

    /// <summary>Share of open findings within SLA (0–100).</summary>
    public double CompliancePercent { get; set; }

    /// <summary>Open findings whose CVE is in the CISA KEV catalog.</summary>
    public int ActivelyExploited { get; set; }

    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Unknown { get; set; }
}
