using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

namespace Ravelin.Tests;

public class SlaEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 21, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromDays(7);

    [Fact]
    public void Open_far_from_deadline_is_on_track()
    {
        var sla = SlaEvaluator.Evaluate(FindingStatus.Open, Now.AddDays(30), Now, Window);

        Assert.Equal(SlaState.OnTrack, sla.State);
        Assert.Equal(30, sla.DaysRemaining);
        Assert.False(sla.IsBreached);
    }

    [Fact]
    public void Open_within_window_is_due_soon()
    {
        var sla = SlaEvaluator.Evaluate(FindingStatus.Open, Now.AddDays(3), Now, Window);

        Assert.Equal(SlaState.DueSoon, sla.State);
        Assert.Equal(3, sla.DaysRemaining);
    }

    [Fact]
    public void Exactly_at_window_edge_is_still_due_soon()
    {
        // remaining == window (7 days) is inclusive of due-soon, not yet on-track.
        var sla = SlaEvaluator.Evaluate(FindingStatus.Open, Now.AddDays(7), Now, Window);

        Assert.Equal(SlaState.DueSoon, sla.State);
    }

    [Fact]
    public void Past_deadline_is_breached_with_negative_days()
    {
        var sla = SlaEvaluator.Evaluate(FindingStatus.Open, Now.AddDays(-5), Now, Window);

        Assert.Equal(SlaState.Breached, sla.State);
        Assert.True(sla.IsBreached);
        Assert.Equal(-5, sla.DaysRemaining);
    }

    [Fact]
    public void Exactly_at_deadline_is_breached()
    {
        var sla = SlaEvaluator.Evaluate(FindingStatus.Open, Now, Now, Window);

        Assert.Equal(SlaState.Breached, sla.State);
        Assert.Equal(0, sla.DaysRemaining);
    }

    [Theory]
    [InlineData(FindingStatus.Resolved)]
    [InlineData(FindingStatus.FalsePositive)]
    [InlineData(FindingStatus.AcceptedRisk)]
    public void Non_open_findings_are_not_applicable(FindingStatus status)
    {
        // Even with a long-past deadline, a non-open finding never counts against SLA.
        var sla = SlaEvaluator.Evaluate(status, Now.AddDays(-100), Now, Window);

        Assert.Equal(SlaState.NotApplicable, sla.State);
        Assert.Null(sla.DaysRemaining);
        Assert.False(sla.IsBreached);
    }

    [Fact]
    public void Open_without_due_date_is_not_applicable()
    {
        var sla = SlaEvaluator.Evaluate(FindingStatus.Open, dueAt: null, Now, Window);

        Assert.Equal(SlaState.NotApplicable, sla.State);
        Assert.Null(sla.DaysRemaining);
    }

    [Fact]
    public void Compute_due_date_adds_policy_days_to_detection()
    {
        var slaDays = new Dictionary<Severity, int> { [Severity.High] = 30 };

        var due = SlaEvaluator.ComputeDueDate(Now, Severity.High, slaDays);

        Assert.Equal(Now.AddDays(30), due);
    }

    [Fact]
    public void Compute_due_date_is_null_when_no_policy_covers_severity()
    {
        var slaDays = new Dictionary<Severity, int> { [Severity.High] = 30 };

        Assert.Null(SlaEvaluator.ComputeDueDate(Now, Severity.Unknown, slaDays));
    }
}
