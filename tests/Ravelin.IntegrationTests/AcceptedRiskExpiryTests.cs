using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Ravelin.Domain.Entities;
using Ravelin.Domain.Enums;
using Ravelin.Infrastructure.Services;

namespace Ravelin.IntegrationTests;

/// <summary>
/// Accepted-risk with expiry (0.9.4): an accepted risk can carry an expiry date, after which the
/// re-evaluation automatically reopens the finding so accepted risks don't linger forever.
/// </summary>
[Collection(RavelinCollection.Name)]
public sealed class AcceptedRiskExpiryTests(RavelinFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Expired_accepted_risk_is_reopened_by_reevaluation()
    {
        await fixture.WithDbAsync(async db =>
        {
            var project = new Project { Key = "ar-proj", Name = "AR" };
            db.Projects.Add(project);
            db.Findings.Add(new Finding
            {
                ProjectId = project.Id,
                VulnerabilityId = "CVE-2021-0009",
                PackageName = "pkg",
                PackageVersion = "1.0.0",
                Title = "temporarily accepted",
                Severity = Severity.High,
                Status = FindingStatus.AcceptedRisk,
                FirstDetectedAt = DateTimeOffset.UtcNow.AddDays(-30),
                LastSeenAt = DateTimeOffset.UtcNow,
                TriageNote = "accepted for a sprint",
                AcceptedRiskUntil = DateTimeOffset.UtcNow.AddDays(-1), // already lapsed
            });
            await db.SaveChangesAsync();
        });

        var reeval = fixture.Factory.Services.GetRequiredService<SlaReEvaluator>();
        await reeval.ReEvaluateAsync();

        await fixture.WithDbAsync(async db =>
        {
            var f = await db.Findings.SingleAsync(x => x.VulnerabilityId == "CVE-2021-0009");
            Assert.Equal(FindingStatus.Open, f.Status);   // reopened
            Assert.Null(f.AcceptedRiskUntil);             // expiry cleared
            Assert.NotNull(f.SlaDueAt);                    // SLA deadline recomputed
        });
    }
}
