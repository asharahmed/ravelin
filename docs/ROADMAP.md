# Ravelin — Road to 1.0.0

Ravelin is live and feature-rich, but it is **pre-1.0** on purpose. This document defines what
1.0.0 means for this project, the gap between today and there, and the milestones (0.8 → 0.9 →
1.0) that close it. It is the authoritative planning doc; [`PROJECT_VISION.md`](../PROJECT_VISION.md)
remains the product definition and [`THREAT-MODEL.md`](./THREAT-MODEL.md) the security analysis.

Versioning follows **SemVer**. Pre-1.0, anything may change without notice (schema, API, config).
**1.0.0 is a promise**: the API is stable, the data model migrates cleanly, and the security and
correctness guarantees below hold. We don't tag 1.0 until every box in "Definition of done" is
checked.

---

## What "1.0.0" means for Ravelin

The README pitches Ravelin as *vendor-neutral, API-first, self-hosted*. 1.0 makes those claims
true **for someone who isn't the author**. Four pillars:

1. **A real authorization model** — users see only the projects they're entitled to; registration
   is a deliberate, configurable decision, not "anyone can read everything."
2. **A stable, versioned API** — `/api/v1`, documented, that integrators can build on without fear
   of a breaking change on the next deploy.
3. **A self-host path anyone can run** — one command to a working instance, no Azure account and
   no bespoke Terraform required.
4. **Correctness guarantees on the numbers** — the compliance figure an auditor saw last quarter
   still reads the same today; SLA/breach math is deterministic and tested.

Everything below is in service of one of those four.

---

## Current state (pre-1.0, ~0.7.x)

**Shipped and live** (`getravelin.xyz`): ingestion (Trivy/Grype/dotnet adapters) with hashed,
project-scoped API keys and dedup/auto-resolve; Identity + JWT + RBAC (Admin/Analyst/Viewer); SLA
engine + triage; dashboards; SLA alerting (webhook/Slack + hourly re-eval); audit trail; unhandled-
error capture → Linear; **risk-based prioritization (CISA KEV + FIRST EPSS → risk-adjusted SLA)**;
published OpenAPI + Scalar; three CI test tiers (unit / Testcontainers integration / Playwright
E2E) + a self-scanning pipeline (SCA/SAST/secret/image/IaC); STRIDE threat model + architecture
docs.

**The honest gap to 1.0** (each expanded below): reads are not scoped per user; JWTs can't be
revoked; the compliance trend is recomputed live (history isn't immutable); services read the clock
directly (hard to test time-dependent behavior); there's no one-command self-host; the API isn't
versioned; and several operability items from the code review are still open (deploy health gate,
fail-closed migrations, infra hardening).

---

## Milestone 0.8 — "The numbers are trustworthy" (correctness + security model)

The blockers that make Ravelin's core claims *true*. Nothing here is optional for 1.0.

### 0.8.1 — Per-project authorization / membership  🔴 top blocker
Today any authenticated user (including a self-registered Viewer) can read **every** project's
findings, dashboard, and reports (`RavelinEndpoints.cs` reads are gated only by
`RequireAuthorization()`; `sec-api` review finding #2). A security team cannot adopt a tool that
leaks all data to any account.
- [ ] `ProjectMembership` entity (user ↔ project, with a per-project role) + migration.
- [ ] Scope every read (`/api/projects`, `/findings`, `/dashboard`, `/report/*`, `/sla-summary`,
      `/alerts`) to the caller's memberships; Admin sees all.
- [ ] `Registration:Mode` config — `Open` / `InviteOnly` / `Disabled` (default `Disabled` for a
      real deploy; `Open` only for the public demo).
- [ ] Admin UI + endpoints to grant/revoke membership.
- [ ] Integration tests: user A cannot see project B; membership grant/revoke; registration modes.

### 0.8.2 — Token revocation (security stamp)
A role change, account disable, or password reset does not take effect until the 60-minute JWT
expires (`sec-api` finding #3). A departing or compromised admin keeps access for up to an hour.
- [ ] Add Identity `SecurityStamp` (or a token-version claim) to issued JWTs.
- [ ] Validate it per request in a `JwtBearer.OnTokenValidated` handler; stamp it on role/password
      change and disable.
- [ ] Shorten access-token lifetime; add refresh if UX needs it. Tighten `ClockSkew` (done: 30s).
- [ ] Tests: demoted admin's existing token is rejected on the next call.

### 0.8.3 — Immutable posture snapshots
The compliance trend is recomputed live from current findings, so **history silently changes** as
deadlines pass. An audit-ready tool must preserve what was true at a point in time.
- [ ] `PostureSnapshot` entity (append-only: date, per-project + org compliance %, open/breached/
      due-soon by severity, KEV count) + migration.
- [ ] Nightly job (extend the existing `SlaReEvaluator` / cron path) writes one snapshot/day.
- [ ] Reports and trends read from snapshots for historical periods, live for "now".
- [ ] Tests: a snapshot taken today reads identically after simulated time passes.

### 0.8.4 — `TimeProvider` refactor
Prerequisite for deterministically testing 0.8.3 and every SLA-transition path. Services currently
read `DateTimeOffset.UtcNow` directly (`IngestionService`, `SlaReEvaluator`, endpoints; `test`
review). The pure domain already takes `now` as a parameter — thread `TimeProvider` through the
services that don't.
- [ ] Inject `TimeProvider`; replace direct `UtcNow` reads in services/endpoints.
- [ ] Fake-clock integration tests for breach/due-soon transitions and the trend buckets.

---

## Milestone 0.9 — "A stranger can run it and integrate with it"

Turns an impressive-but-unrunnable repo into one someone clones and uses.

### 0.9.1 — Docker Compose quickstart  ⭐ highest visible-progress win
`docker compose up` → app + SQL Server, migrated and demo-seeded, browsable at `localhost`. Today
"self-hosted" means reproducing the Azure/Terraform stack.
- [ ] `compose.yaml`: the app image + `mcr.microsoft.com/mssql/server`, healthchecks, a dev JWT
      key + seed passwords via `.env.example`, `Seed:DemoData=true`.
- [ ] `README` quickstart section; verify a clean `up` reaches a seeded dashboard.
- [ ] (The app already migrates on boot and runs against SQL Server in dev — this mostly wires it.)

### 0.9.2 — API versioning + stability
Move the surface under `/api/v1`; commit to not breaking it within a major. That's what "API-first"
means at 1.0.
- [ ] Introduce `/api/v1` (route prefix or `Asp.Versioning`); keep unversioned aliases deprecated.
- [ ] Versioned OpenAPI doc; publish it as a release artifact.
- [ ] Adopt `TypedResults` / `.Produces<T>()` so the OpenAPI schema documents response bodies
      (currently `Results.Ok(object)` erases them — noted during the live `/openapi` check).

### 0.9.3 — SARIF ingestion  ⭐ highest value-to-effort feature
SARIF is the universal static-analysis format (CodeQL, Semgrep, Trivy, Grype all emit it). One
adapter in the existing `Ravelin.Domain/Ingestion/` pattern makes Ravelin ingest almost anything —
and lets it eat its own CI's SARIF.
- [ ] `SarifAdapter` (parse `runs[].results[]`, map rule/level/location → `IncomingFinding`;
      `FormatException` on non-SARIF, matching the other adapters).
- [ ] `POST /api/ingest/sarif`; unit tests over real CodeQL + Semgrep samples.

### 0.9.4 — Accepted-risk with expiry + exception workflow
`PROJECT_VISION.md §7` wanted expiring accepted-risk; today an accepted risk never lapses.
- [ ] `Finding.AcceptedRiskUntil`; the re-evaluator auto-reopens on expiry (+ audit + alert).
- [ ] Optional approval step (analyst requests → admin approves), both audited.
- [ ] Tests: an accepted risk reopens the day after it expires.

---

## Milestone 1.0 — "Production-operable and documented"

The operability and documentation a 1.0 tag implies.

### 1.0.1 — Safe deploys
The review found deploys have **no health gate or rollback**, and startup **swallows migration
failures** (`Program.cs` try/catch), so a bad deploy can serve against a mismatched schema.
- [ ] Post-deploy `/health/ready` gate in the pipeline (and `scripts/deploy.sh`) — fail/rollback on
      non-200.
- [ ] Let a genuine migration failure fail startup (keep only *seeding* best-effort).

### 1.0.2 — Notifications: email + digest
Only webhook/Slack exist. Add email as a first-class channel and a weekly breach/posture digest
(the re-eval loop already produces the data).
- [ ] SMTP/provider email channel (config-gated, inert by default — the Linear/VulnIntel pattern).
- [ ] Weekly digest job; per-project + org rollup.

### 1.0.3 — Operator documentation
- [ ] `CHANGELOG.md` (Keep a Changelog); start tagging releases.
- [ ] Configuration reference: every env var, its default, and whether it's a secret.
- [ ] Backup/restore + upgrade notes (Azure SQL PITR; migration-on-boot behavior).

### 1.0.4 — Infra hardening (from the code review)
- [ ] Lock down the Terraform state account (versioning, soft-delete, disable shared-key,
      network default-deny) — state holds all secrets in plaintext.
- [ ] Trim the CI identity from RG Contributor to Container-App-scoped.
- [ ] Finish managed-identity SQL auth + least-privilege contained DB user (removes the last
      admin-password path; `sql.tf` deferral).
- [ ] Key Vault audit diagnostics + an availability alert on the app.

---

## Beyond 1.0 (post-1.0 backlog)

Valuable, but not required to earn the tag. Roughly by demand:
- **Jira integration** (a second `IIssueTracker` impl — the abstraction already exists).
- **Pull-based ingestion** (Dependabot / registry APIs) — removes the pipeline-step friction.
- **Per-project / per-environment SLA overrides** (policy is org-global today).
- **Compliance-framework mapping** (SOC 2 / ISO 27001 / PCI vulnerability-management controls).
- **VEX** (`not_affected` + justification) as a triage extension.
- **SBOM ingestion** (CycloneDX / SPDX) for asset inventory.
- **Server-rendered PDF** reports (today: browser print).
- **Multi-tenancy / organizations** — explicitly out of scope in the current vision; only if the
  product repositions beyond single-org.
- **Java/Spring read-only client** — the vision's stretch goal (§10).

---

## Definition of done for 1.0.0

Tag 1.0.0 only when **all** hold:
- [ ] Reads are scoped per user; registration mode is configurable and defaults closed (0.8.1).
- [ ] Credential/role changes take effect immediately (0.8.2).
- [ ] Historical compliance numbers are immutable (0.8.3), and time-dependent behavior is tested
      via an injectable clock (0.8.4).
- [ ] `docker compose up` yields a working, seeded instance (0.9.1).
- [ ] The API is served under `/api/v1` with a published, response-typed OpenAPI doc (0.9.2).
- [ ] Deploys are health-gated and migrations fail closed (1.0.1).
- [ ] `CHANGELOG.md` + a configuration reference exist; the state account and CI identity are
      hardened (1.0.3, 1.0.4).

Everything else on this page is welcome before 1.0 but not blocking.
