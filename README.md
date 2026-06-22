# Ravelin

Vendor-neutral vulnerability **SLA & compliance tracker**. Ravelin takes the dependency-scan
results your CI already produces and holds each finding to a remediation deadline based on its
severity — then shows what's overdue, how your posture is trending, and produces evidence you
can hand an auditor.

[![.NET](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Blazor WebAssembly](https://img.shields.io/badge/Blazor-WASM-512BD4?logo=blazor&logoColor=white)](https://learn.microsoft.com/aspnet/core/blazor/)
[![Azure Container Apps](https://img.shields.io/badge/Azure-Container%20Apps-0078D4?logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/products/container-apps)
[![IaC: Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform&logoColor=white)](./infra)
[![License: MIT](https://img.shields.io/badge/License-MIT-success)](./LICENSE)

> A *ravelin* is a triangular outwork built in front of a fortress wall — a detached first
> line of defence. The product is named for it, and the logo is its salient.

**[Live demo →](https://ca-ravelin-dev.thankfulsea-7af22cac.canadacentral.azurecontainerapps.io)**
(hosted on scale-to-zero infrastructure, so the first request after an idle period takes a few
seconds to wake).

![Ravelin](./docs/screenshot.png)

---

## The problem

Every category of finding already has good scanners — Dependabot, Snyk and Trivy for
dependencies; SonarQube and CodeQL for code; GitGuardian for secrets. They are excellent at
*surfacing* problems and poor at *holding teams accountable* for fixing them. The questions an
auditor or a security lead actually asks are different:

- Are we meeting our own remediation SLAs?
- Is our security posture getting better or worse?
- Can I produce a clean, point-in-time report on demand?

Ravelin is the layer that answers those. It doesn't replace your scanners; it consumes their
output and adds severity-based SLAs, posture trends, and audit-ready reporting on top.

## How it works

1. **Ingest.** A pipeline step POSTs scan results to an authenticated endpoint using a scoped,
   hashed API key. Ravelin normalises them, deduplicates against prior scans by a stable
   identity, and auto-resolves anything that's no longer present.
2. **Clock.** Each finding inherits a remediation deadline from its severity (Critical 7d,
   High 30d, Medium 90d, Low 180d by default). The clock starts when the finding is first seen;
   it is *breached* once it passes its deadline.
3. **Account.** Dashboards show compliance %, breaches by project and severity, and an
   opened-vs-resolved trend. Analysts triage findings — marking a false positive or accepted
   risk requires a written justification, which stays on the record.

A scan push is a single request:

```bash
curl -X POST https://<host>/api/ingest \
  -H "X-Api-Key: <project-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "trivy",
    "toolVersion": "0.50.0",
    "findings": [
      {
        "vulnerabilityId": "CVE-2024-21907",
        "packageName": "Newtonsoft.Json",
        "packageVersion": "12.0.1",
        "title": "Improper handling of exceptional conditions",
        "severity": "High",
        "cvssScore": 7.5,
        "fixedVersion": "13.0.1"
      }
    ]
  }'
# -> { "scanId": "...", "created": 1, "reopened": 0, "resolved": 0, "seen": 0, "openTotal": 1 }
```

## Features

- **Severity-based SLAs** with breach detection computed on read, so deadlines stay correct as
  time passes. Editing a policy re-baselines open findings.
- **Smart reconciliation** — dedup, auto-resolve, and reopen across scans, with triage
  decisions respected.
- **Dashboards** — compliance gauge, open-by-severity, per-project posture, and an 8-week
  opened-vs-resolved trend (no chart libraries; plain SVG).
- **Auditable triage** — false-positive and accepted-risk states require a justification.
- **Two authentication models** — JWT + RBAC (Admin / Analyst / Viewer) for people, scoped and
  hashed API keys for pipelines.
- **API-first** — every capability is a documented HTTP endpoint; the Blazor UI is just one
  client.
- **CSV export** of findings for offline analysis.

## Architecture

| Layer | Choice |
|-------|--------|
| Language | C# / .NET 10 |
| UI | Blazor WebAssembly, served by the API host (one deployable unit) |
| API | ASP.NET Core minimal API, OpenAPI published |
| Data | EF Core → SQL Server / Azure SQL (serverless) |
| Auth | ASP.NET Core Identity + JWT (RBAC); hashed, scoped API keys for pipelines |
| Packaging | Docker — chiseled, non-root runtime image |
| Hosting | Azure Container Apps (scale-to-zero) + Azure Container Registry |
| CI/CD | Azure Pipelines |
| IaC | Terraform (remote state in Azure Storage) |

The solution is split so the domain has no infrastructure dependencies:

```
src/
  Ravelin/                ASP.NET Core host — Web API + serves the Blazor client
  Ravelin.Client/         Blazor WebAssembly UI
  Ravelin.Domain/         Entities + pure business logic (reconciliation, SLA engine, triage)
  Ravelin.Infrastructure/ EF Core, persistence, API-key + ingestion services
  Ravelin.Shared/         DTOs / contracts shared by API and client
tests/
  Ravelin.Tests/          xUnit tests (reconciler, SLA evaluation, triage, CSV)
infra/terraform/          Azure infrastructure
```

## Running locally

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download), Docker (for SQL Server), and
the EF Core tools (`dotnet tool install --global dotnet-ef`).

```bash
git clone https://github.com/asharahmed/ravelin.git
cd ravelin

# 1. SQL Server (dev matches prod)
docker run -d --name ravelin-sql -p 1433:1433 \
  -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=Your_strong_Pass123" \
  mcr.microsoft.com/mssql/server:2022-latest

export RAVELIN_DB_CONNECTION="Server=localhost,1433;Database=ravelin;User Id=sa;Password=Your_strong_Pass123;TrustServerCertificate=true"

# 2. Apply migrations
dotnet ef database update \
  --project src/Ravelin.Infrastructure --startup-project src/Ravelin.Infrastructure

# 3. Run (UI + API on the printed URL)
export ConnectionStrings__RavelinDb="$RAVELIN_DB_CONNECTION"
export Jwt__SigningKey="dev-signing-key-at-least-32-characters-long"
export Seed__AdminEmail="admin@ravelin.local" Seed__AdminPassword="Admin_pass_123!"
export Seed__DemoData="true"   # seeds demo projects + findings
dotnet run --project src/Ravelin/Ravelin.csproj
```

Then sign in with the seeded admin account. Build and test the whole solution with:

```bash
dotnet build Ravelin.slnx
dotnet test  Ravelin.slnx
```

Infrastructure and deployment are documented in [`infra/README.md`](./infra/README.md).

## Security

This is a security tool, so it is built to model good practice and to scan itself:

- Scan payloads are treated as untrusted and validated at the API boundary.
- API keys are stored hashed (SHA-256, 256-bit keys); RBAC is enforced per endpoint,
  deny-by-default.
- The scope of an ingested scan comes from the API key, never from the request route.
- Secrets are delivered as Container App secrets (Azure Key Vault is on the roadmap), and are
  never logged.
- The CI pipeline scans Ravelin's own dependencies, code, container image, and IaC.

## Status & roadmap

Live and deployed through dashboards. Built in reviewable stages:

| Stage | Scope | State |
|-------|-------|-------|
| 0 | Solution, clean architecture, walking skeleton, container | Done |
| 1 | Terraform infra, Azure Container Apps, CI/CD pipeline | Done |
| 2 | Domain model, EF Core, Azure SQL | Done |
| 3 | Ingestion API, hashed keys, dedup + auto-resolve | Done |
| 4 | Identity + JWT + RBAC, Blazor login | Done |
| 5 | SLA engine + triage | Done |
| 6 | Dashboards | Done |
| 7 | Point-in-time compliance report export | Planned |
| 8 | DevSecOps hardening — pipeline scanners, Key Vault, managed-identity DB auth | Planned |

Design rationale and the full decision log are in [`PROJECT_VISION.md`](./PROJECT_VISION.md);
the design system is documented in [`DESIGN.md`](./DESIGN.md) and rendered live at `/styleguide`.

## License

[MIT](./LICENSE).
