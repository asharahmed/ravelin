using Ravelin.Domain.Services;

namespace Ravelin.Infrastructure.Services;

/// <summary>Configuration for exploitation-intelligence enrichment (CISA KEV + FIRST EPSS) and the
/// risk-adjusted SLA it drives. Inert by default: <see cref="Enabled"/> is false until switched on
/// in configuration, so local/dev/test runs make no external calls.</summary>
public sealed class VulnIntelOptions
{
    public const string SectionName = "VulnIntel";

    /// <summary>Master switch. When false, a no-op enricher is registered and nothing is fetched.</summary>
    public bool Enabled { get; set; }

    public string KevFeedUrl { get; set; } =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    public string EpssApiUrl { get; set; } = "https://api.first.org/data/v1/epss";

    /// <summary>Remediation deadline (days from detection) for a CISA-KEV finding.</summary>
    public int KevRemediationDays { get; set; } = 14;

    /// <summary>Remediation deadline for a finding whose EPSS meets <see cref="EpssEscalationThreshold"/>.</summary>
    public int HighEpssRemediationDays { get; set; } = 30;

    /// <summary>EPSS probability (0–1) at/above which the high-EPSS SLA override applies.</summary>
    public double EpssEscalationThreshold { get; set; } = RiskEvaluator.DefaultEpssEscalationThreshold;

    public RiskSlaPolicy ToRiskPolicy() =>
        new(KevRemediationDays, HighEpssRemediationDays, EpssEscalationThreshold);
}

/// <summary>One CVE's EPSS scoring.</summary>
public readonly record struct EpssScore(double Score, double Percentile);

/// <summary>Source of external exploitation intelligence. Implementations must never throw for a
/// remote failure — callers treat a failed fetch as "no authoritative data this pass".</summary>
public interface IVulnerabilityIntelligence
{
    /// <summary>CISA KEV catalog as CVE id → date added (value may be null if the feed omits it).
    /// Returns null when the catalog could not be fetched (distinct from "empty catalog").</summary>
    Task<IReadOnlyDictionary<string, DateTimeOffset?>?> GetKnownExploitedAsync(CancellationToken ct = default);

    /// <summary>EPSS scores for the given CVE ids (only scored CVEs are present). Returns null when
    /// the API could not be reached.</summary>
    Task<IReadOnlyDictionary<string, EpssScore>?> GetEpssScoresAsync(
        IReadOnlyCollection<string> cveIds, CancellationToken ct = default);
}

/// <summary>Refreshes findings with KEV/EPSS intelligence and re-baselines their risk-adjusted SLA.</summary>
public interface IFindingEnricher
{
    Task<EnrichmentResult> EnrichAsync(CancellationToken ct = default);
}

/// <summary>Outcome of one enrichment pass.</summary>
public readonly record struct EnrichmentResult(int Scanned, int KnownExploited, int Escalated, int Updated);

/// <summary>Inert enricher used when intelligence is disabled — keeps the enrichment call sites
/// (re-evaluator, admin endpoint) working with no external dependency.</summary>
public sealed class NullFindingEnricher : IFindingEnricher
{
    public Task<EnrichmentResult> EnrichAsync(CancellationToken ct = default) =>
        Task.FromResult(default(EnrichmentResult));
}
