using Ravelin.Domain.Enums;
using Ravelin.Domain.Services;

namespace Ravelin.Tests;

public class RiskEvaluatorTests
{
    private static readonly DateTimeOffset From = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<Severity, int> Sla = new()
    {
        [Severity.Critical] = 7,
        [Severity.High] = 30,
        [Severity.Medium] = 90,
        [Severity.Low] = 180,
    };

    // KevDays=14, HighEpssDays=30, threshold=0.5
    private static readonly RiskSlaPolicy Policy = new(14, 30, 0.5);

    [Fact]
    public void Known_exploited_outranks_every_non_exploited_finding()
    {
        // A KEV Low must rank above a non-KEV Critical — exploitation dominates severity.
        var kevLow = RiskEvaluator.Rank(Severity.Low, isKnownExploited: true, epss: 0.0);
        var criticalNoKev = RiskEvaluator.Rank(Severity.Critical, isKnownExploited: false, epss: 0.99);

        Assert.True(kevLow > criticalNoKev);
    }

    [Fact]
    public void Within_a_tier_higher_severity_then_higher_epss_wins()
    {
        var critical = RiskEvaluator.Rank(Severity.Critical, false, 0.1);
        var high = RiskEvaluator.Rank(Severity.High, false, 0.9);
        Assert.True(critical > high);

        var highLowEpss = RiskEvaluator.Rank(Severity.High, false, 0.1);
        var highHighEpss = RiskEvaluator.Rank(Severity.High, false, 0.9);
        Assert.True(highHighEpss > highLowEpss);
    }

    [Theory]
    [InlineData(true, 0.1, "Actively exploited")]
    [InlineData(false, 0.9, "Likely exploited")]
    [InlineData(false, 0.5, "Likely exploited")]  // at the threshold
    [InlineData(false, 0.49, null)]
    [InlineData(false, null, null)]
    public void Label_reflects_the_strongest_signal(bool kev, double? epss, string? expected)
    {
        Assert.Equal(expected, RiskEvaluator.Label(kev, epss, epssThreshold: 0.5));
    }

    [Fact]
    public void Kev_tightens_the_deadline_below_the_severity_sla()
    {
        // A Low (180d) that is KEV gets the 14-day KEV deadline.
        var due = SlaEvaluator.ComputeDueDate(From, Severity.Low, Sla, Policy, isKnownExploited: true, epss: null);
        Assert.Equal(From.AddDays(14), due);
    }

    [Fact]
    public void High_epss_tightens_the_deadline()
    {
        // A Medium (90d) with EPSS 0.7 (>= 0.5) gets the 30-day high-EPSS deadline.
        var due = SlaEvaluator.ComputeDueDate(From, Severity.Medium, Sla, Policy, isKnownExploited: false, epss: 0.7);
        Assert.Equal(From.AddDays(30), due);
    }

    [Fact]
    public void Risk_only_tightens_never_loosens()
    {
        // A Critical (7d) that is KEV keeps 7 days — the 14-day KEV override must not extend it.
        var due = SlaEvaluator.ComputeDueDate(From, Severity.Critical, Sla, Policy, isKnownExploited: true, epss: 0.9);
        Assert.Equal(From.AddDays(7), due);
    }

    [Fact]
    public void Exploited_unknown_severity_still_gets_a_deadline()
    {
        // Unknown severity has no policy → severity-only deadline is null (untracked). If it's
        // actively exploited it must NOT be untracked — the KEV deadline applies.
        var severityOnly = SlaEvaluator.ComputeDueDate(From, Severity.Unknown, Sla);
        Assert.Null(severityOnly);

        var risk = SlaEvaluator.ComputeDueDate(From, Severity.Unknown, Sla, Policy, isKnownExploited: true, epss: null);
        Assert.Equal(From.AddDays(14), risk);
    }

    [Fact]
    public void No_signals_leaves_the_severity_deadline_unchanged()
    {
        var due = SlaEvaluator.ComputeDueDate(From, Severity.High, Sla, Policy, isKnownExploited: false, epss: 0.1);
        Assert.Equal(From.AddDays(30), due);  // High severity SLA, no risk override triggered
    }
}
