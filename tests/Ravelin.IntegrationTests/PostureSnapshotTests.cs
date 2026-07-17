using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Infrastructure.Services;
using Ravelin.Shared;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Immutable posture snapshots (0.8.3): a nightly record captures org compliance once per day so
/// historical figures don't change as live deadlines pass. This proves the record is written once
/// and stays fixed even after the underlying findings change.
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class PostureSnapshotTests(RavelinFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Snapshot_is_captured_once_per_day_and_stays_immutable()
    {
        var findingId = Guid.NewGuid();
        await fixture.WithDbAsync(async db =>
        {
            var project = new Project { Key = "snap-proj", Name = "Snap" };
            db.Projects.Add(project);
            db.Findings.Add(new Finding
            {
                Id = findingId,
                ProjectId = project.Id,
                VulnerabilityId = "CVE-2020-0001",
                PackageName = "pkg",
                PackageVersion = "1.0.0",
                Title = "breached finding",
                Severity = Severity.Critical,
                Status = FindingStatus.Open,
                FirstDetectedAt = DateTimeOffset.UtcNow.AddDays(-30),
                LastSeenAt = DateTimeOffset.UtcNow,
                SlaDueAt = DateTimeOffset.UtcNow.AddDays(-1), // overdue → breached
            });
            await db.SaveChangesAsync();
        });

        var snapshots = fixture.Factory.Services.GetRequiredService<PostureSnapshotService>();

        // First capture writes today's snapshot: 1 open, 1 breached → 0% compliance.
        Assert.True(await snapshots.EnsureSnapshotAsync());
        await fixture.WithDbAsync(async db =>
        {
            var snap = await db.PostureSnapshots.SingleAsync();
            Assert.Equal(1, snap.TotalOpen);
            Assert.Equal(1, snap.Breached);
            Assert.Equal(0d, snap.CompliancePercent);
        });

        // The posture improves — resolve the finding (live compliance would now be 100%).
        await fixture.WithDbAsync(async db =>
        {
            var f = await db.Findings.SingleAsync(x => x.Id == findingId);
            f.Status = FindingStatus.Resolved;
            f.ResolvedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync();
        });

        // A second capture the same day is a no-op, and the day's record is unchanged.
        Assert.False(await snapshots.EnsureSnapshotAsync());
        await fixture.WithDbAsync(async db =>
        {
            var snap = await db.PostureSnapshots.SingleAsync(); // still exactly one row for today
            Assert.Equal(0d, snap.CompliancePercent);           // frozen at the captured value, not 100
        });
    }

    [Fact]
    public async Task Posture_history_endpoint_is_admin_only()
    {
        using var viewer = await fixture.CreateClientForRoleAsync(RavelinRoles.Viewer);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/posture/history")).StatusCode);

        using var admin = await fixture.CreateClientForRoleAsync(RavelinRoles.Admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/posture/history")).StatusCode);
    }
}
