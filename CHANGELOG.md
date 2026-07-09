# Changelog

All notable changes to Ravelin are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0 onward. Pre-1.0, minor
versions may include breaking changes.

## [Unreleased] — Road to 1.0.0

Working toward the 1.0 contract (see [`docs/ROADMAP.md`](docs/ROADMAP.md)).

### Added
- **Per-project authorization** (`0.8.1`): project membership + public/private visibility; reads
  scoped per user (Admins see all); configurable `Registration:Mode` (self-service signup off by
  default). Closes the "any authenticated user sees every project's data" gap.
- **Token revocation** (`0.8.2`): JWTs carry the Identity security stamp, validated per request —
  a role change / password reset / disable revokes existing tokens immediately.
- **Immutable posture snapshots** (`0.8.3`): an append-only daily record of org compliance, so
  historical figures don't change as live deadlines pass. `GET /api/posture/history` (Admin).
- **Accepted-risk with expiry** (`0.9.4`): an accepted risk can carry an expiry after which the
  finding is auto-reopened.
- **SARIF ingestion** (`0.9.3`): `POST /api/ingest/sarif` for the universal analysis format
  (CodeQL, Semgrep, Trivy, Grype, …).
- **Docker Compose quickstart** (`0.9.1`): `docker compose up --build` brings up the app + SQL
  Server, migrated and demo-seeded.
- Operator docs: this changelog and [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

### Changed
- `TimeProvider` injected into time-dependent services (`0.8.4`), enabling deterministic tests.

### Fixed
- Startup no longer swallows a migration failure in Production — it fails closed so the app never
  serves against a mismatched schema; the deploy pipeline gates on `/health/ready` (`1.0.1`).
- `Dockerfile` restore graph was missing `Ravelin.Infrastructure.csproj` (`docker build` would
  fail); the SDK-container deploy path had hidden it.

## Shipped so far (0.1 – 0.7)

The initial build, delivered in reviewable stages and live at
[getravelin.xyz](https://getravelin.xyz):

- **Foundations & cloud** — .NET 10 clean-architecture solution; Terraform → Azure Container Apps
  + Azure SQL + ACR + Key Vault; CI/CD.
- **Ingestion** — Trivy / Grype / `dotnet list` adapters, hashed project-scoped API keys, dedup +
  auto-resolve.
- **Identity & RBAC** — ASP.NET Identity + JWT, Admin/Analyst/Viewer, login + self-service signup.
- **SLA engine & triage**, **dashboards**, **point-in-time compliance report**.
- **SLA alerting** (webhook/Slack + hourly re-eval), **audit trail**, **error capture → Linear**.
- **Risk-based prioritization** — CISA KEV + FIRST EPSS enrichment driving a risk-adjusted SLA.
- **DevSecOps** — self-scanning CI (SCA/SAST/secret/image/IaC), secrets in Key Vault via managed
  identity, STRIDE threat model, published OpenAPI + Scalar.

[Unreleased]: https://github.com/asharahmed/ravelin/commits/main
