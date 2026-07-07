using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Domain.Ingestion;
using Ravelin.Domain.Services;

namespace Ravelin.Tests;

public class ScanReconcilerTests
{
    private static readonly Guid Project = Guid.NewGuid();
    private static readonly DateTimeOffset Now = new(2026, 6, 21, 12, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<Severity, int> Sla = new()
    {
        [Severity.Critical] = 7,
        [Severity.High] = 30,
        [Severity.Medium] = 90,
        [Severity.Low] = 180,
    };

    private static IncomingFinding Incoming(
        string vuln, string pkg, string version, Severity sev = Severity.High, string? fixedVersion = null) =>
        new()
        {
            VulnerabilityId = vuln,
            PackageName = pkg,
            PackageVersion = version,
            Title = $"{vuln} in {pkg}",
            Severity = sev,
            FixedVersion = fixedVersion,
        };

    private static Finding Existing(
        string vuln, string pkg, string version, FindingStatus status, DateTimeOffset firstDetected) =>
        new()
        {
            ProjectId = Project,
            VulnerabilityId = vuln,
            PackageName = pkg,
            PackageVersion = version,
            Title = $"{vuln} in {pkg}",
            Severity = Severity.High,
            Status = status,
            FirstDetectedAt = firstDetected,
            LastSeenAt = firstDetected,
            ResolvedAt = status == FindingStatus.Resolved ? firstDetected : null,
        };

    [Fact]
    public void New_finding_is_created_open_with_sla_due_from_now()
    {
        var incoming = new[] { Incoming("CVE-2025-1", "pkgA", "1.0.0", Severity.Critical) };

        var result = ScanReconciler.Reconcile(Project, [], incoming, Sla, Now);

        var created = Assert.Single(result.Created);
        Assert.Equal(FindingStatus.Open, created.Status);
        Assert.Equal(Now, created.FirstDetectedAt);
        Assert.Equal(Now.AddDays(7), created.SlaDueAt); // Critical = 7 days
        Assert.Empty(result.Resolved);
    }

    [Fact]
    public void Existing_open_finding_still_present_is_seen_not_duplicated()
    {
        var existing = new[] { Existing("CVE-2025-1", "pkgA", "1.0.0", FindingStatus.Open, Now.AddDays(-3)) };
        var incoming = new[] { Incoming("CVE-2025-1", "pkgA", "1.0.0") };

        var result = ScanReconciler.Reconcile(Project, existing, incoming, Sla, Now);

        Assert.Empty(result.Created);
        Assert.Empty(result.Resolved);
        var seen = Assert.Single(result.Seen);
        Assert.Equal(Now, seen.LastSeenAt);
        Assert.Equal(FindingStatus.Open, seen.Status);
    }

    [Fact]
    public void Open_finding_absent_from_a_non_empty_scan_is_auto_resolved()
    {
        var existing = new[] { Existing("CVE-2025-1", "pkgA", "1.0.0", FindingStatus.Open, Now.AddDays(-3)) };
        // A different vuln is reported — the original is genuinely gone, so it auto-resolves.
        var incoming = new[] { Incoming("CVE-2025-2", "pkgB", "2.0.0") };

        var result = ScanReconciler.Reconcile(Project, existing, incoming, Sla, Now);

        var resolved = Assert.Single(result.Resolved);
        Assert.Equal(FindingStatus.Resolved, resolved.Status);
        Assert.Equal(Now, resolved.ResolvedAt);
        Assert.Equal("CVE-2025-1", resolved.VulnerabilityId);
    }

    [Fact]
    public void Empty_scan_does_not_auto_resolve_open_findings()
    {
        // Guards the worst failure mode: a broken/errored scanner step emits structurally-valid
        // but empty JSON. It must NOT silently resolve every open finding and report false
        // 100% compliance. An empty scan is "no new information", not "everything is fixed".
        var existing = new[]
        {
            Existing("CVE-2025-1", "pkgA", "1.0.0", FindingStatus.Open, Now.AddDays(-3)),
            Existing("CVE-2025-2", "pkgB", "2.0.0", FindingStatus.Open, Now.AddDays(-3)),
        };

        var result = ScanReconciler.Reconcile(Project, existing, [], Sla, Now);

        Assert.Empty(result.Resolved);
        Assert.Empty(result.Created);
        Assert.All(existing, f => Assert.Equal(FindingStatus.Open, f.Status));
    }

    [Fact]
    public void Dedup_identity_is_case_insensitive_matching_the_database_collation()
    {
        // NuGet package ids are case-insensitive and so is Azure SQL's default collation, so the
        // stored "Newtonsoft.Json" and an incoming "newtonsoft.json" are the SAME finding. The
        // reconciler must MATCH them (touch the existing row) rather than queue a duplicate INSERT
        // that would violate the case-insensitive dedup unique index at SaveChanges → HTTP 500.
        var existing = new[] { Existing("CVE-2025-1", "Newtonsoft.Json", "13.0.1", FindingStatus.Open, Now.AddDays(-3)) };
        var incoming = new[] { Incoming("cve-2025-1", "newtonsoft.json", "13.0.1") };

        var result = ScanReconciler.Reconcile(Project, existing, incoming, Sla, Now);

        Assert.Empty(result.Created);   // matched, not inserted
        Assert.Empty(result.Resolved);  // the original is not treated as "gone"
        Assert.Single(result.Seen);
    }

    [Fact]
    public void Resolved_finding_that_reappears_is_reopened()
    {
        var existing = new[] { Existing("CVE-2025-1", "pkgA", "1.0.0", FindingStatus.Resolved, Now.AddDays(-10)) };
        var incoming = new[] { Incoming("CVE-2025-1", "pkgA", "1.0.0", Severity.High) };

        var result = ScanReconciler.Reconcile(Project, existing, incoming, Sla, Now);

        var reopened = Assert.Single(result.Reopened);
        Assert.Equal(FindingStatus.Open, reopened.Status);
        Assert.Null(reopened.ResolvedAt);
        // SLA due is recomputed from the original first-detected date.
        Assert.Equal(Now.AddDays(-10).AddDays(30), reopened.SlaDueAt);
    }

    [Theory]
    [InlineData(FindingStatus.FalsePositive)]
    [InlineData(FindingStatus.AcceptedRisk)]
    public void Triaged_findings_are_not_auto_resolved_or_reopened(FindingStatus status)
    {
        var existing = new[] { Existing("CVE-2025-1", "pkgA", "1.0.0", status, Now.AddDays(-5)) };

        // Absent from scan: must NOT auto-resolve a triaged finding.
        var absent = ScanReconciler.Reconcile(Project, existing, [], Sla, Now);
        Assert.Empty(absent.Resolved);

        // Present in scan: must NOT reopen; triage is respected.
        var present = ScanReconciler.Reconcile(
            Project, existing, new[] { Incoming("CVE-2025-1", "pkgA", "1.0.0") }, Sla, Now);
        Assert.Empty(present.Reopened);
        Assert.Equal(status, existing[0].Status);
    }

    [Fact]
    public void Duplicate_identities_within_one_payload_are_collapsed()
    {
        var incoming = new[]
        {
            Incoming("CVE-2025-1", "pkgA", "1.0.0"),
            Incoming("CVE-2025-1", "pkgA", "1.0.0"),
        };

        var result = ScanReconciler.Reconcile(Project, [], incoming, Sla, Now);

        Assert.Single(result.Created);
    }

    [Fact]
    public void Mixed_scan_creates_resolves_and_keeps_in_one_pass()
    {
        var existing = new[]
        {
            Existing("CVE-A", "pkgA", "1.0.0", FindingStatus.Open, Now.AddDays(-2)), // stays
            Existing("CVE-B", "pkgB", "2.0.0", FindingStatus.Open, Now.AddDays(-2)), // disappears -> resolve
        };
        var incoming = new[]
        {
            Incoming("CVE-A", "pkgA", "1.0.0"),       // seen
            Incoming("CVE-C", "pkgC", "3.0.0"),       // new
        };

        var result = ScanReconciler.Reconcile(Project, existing, incoming, Sla, Now);

        Assert.Single(result.Created);   // CVE-C
        Assert.Single(result.Seen);      // CVE-A
        Assert.Single(result.Resolved);  // CVE-B
        Assert.Equal("CVE-C", result.Created[0].VulnerabilityId);
        Assert.Equal("CVE-B", result.Resolved[0].VulnerabilityId);
    }
}
