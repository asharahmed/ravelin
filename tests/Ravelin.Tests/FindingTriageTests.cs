using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

namespace Ravelin.Tests;

public class FindingTriageTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 21, 12, 0, 0, TimeSpan.Zero);

    private static Finding OpenFinding() => new()
    {
        ProjectId = Guid.NewGuid(),
        VulnerabilityId = "CVE-2026-0001",
        PackageName = "acme",
        PackageVersion = "1.0.0",
        Title = "test",
        Severity = Severity.High,
        Status = FindingStatus.Open,
        FirstDetectedAt = Now.AddDays(-10),
    };

    [Theory]
    [InlineData(FindingStatus.FalsePositive)]
    [InlineData(FindingStatus.AcceptedRisk)]
    public void Suppressing_requires_a_note(FindingStatus target)
    {
        var finding = OpenFinding();

        var outcome = FindingTriage.Apply(finding, target, note: "  ", Now);

        Assert.False(outcome.Success);
        Assert.Contains("note", outcome.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(FindingStatus.Open, finding.Status); // unchanged
    }

    [Theory]
    [InlineData(FindingStatus.FalsePositive)]
    [InlineData(FindingStatus.AcceptedRisk)]
    public void Suppressing_with_a_note_sets_status_and_trims_note(FindingStatus target)
    {
        var finding = OpenFinding();

        var outcome = FindingTriage.Apply(finding, target, note: "  not exploitable  ", Now);

        Assert.True(outcome.Success);
        Assert.Equal(target, finding.Status);
        Assert.Equal("not exploitable", finding.TriageNote);
        Assert.Null(finding.ResolvedAt); // suppressed != resolved
    }

    [Fact]
    public void Resolving_sets_resolved_timestamp_without_a_note()
    {
        var finding = OpenFinding();

        var outcome = FindingTriage.Apply(finding, FindingStatus.Resolved, note: null, Now);

        Assert.True(outcome.Success);
        Assert.Equal(FindingStatus.Resolved, finding.Status);
        Assert.Equal(Now, finding.ResolvedAt);
    }

    [Fact]
    public void Reopening_clears_resolved_timestamp()
    {
        var finding = OpenFinding();
        finding.Status = FindingStatus.Resolved;
        finding.ResolvedAt = Now.AddDays(-1);

        var outcome = FindingTriage.Apply(finding, FindingStatus.Open, note: null, Now);

        Assert.True(outcome.Success);
        Assert.Equal(FindingStatus.Open, finding.Status);
        Assert.Null(finding.ResolvedAt);
    }

    [Fact]
    public void Unknown_target_is_rejected()
    {
        var finding = OpenFinding();

        var outcome = FindingTriage.Apply(finding, (FindingStatus)999, note: null, Now);

        Assert.False(outcome.Success);
        Assert.Equal(FindingStatus.Open, finding.Status);
    }
}
