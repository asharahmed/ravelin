# Ravelin

**A lightweight, vendor-neutral vulnerability SLA & compliance tracker.**
*Hold the line on security debt.*

Ravelin ingests dependency-vulnerability scan results from CI/CD pipelines and focuses on
the **accountability layer** that most tools do poorly: tracking remediation against
**severity-based SLAs**, showing **security-posture trends over time**, and producing
**audit-ready compliance reports**.

> A *ravelin* is a triangular defensive outwork in front of a fortress wall — an outer
> layer of defense.

This is a portfolio + learning project that deliberately showcases **AppSec / DevSecOps**,
**Azure DevOps & CI/CD**, and **C# / .NET**. See [`PROJECT_VISION.md`](./PROJECT_VISION.md)
for the full vision, decisions, and roadmap.

## Tech stack

| Layer | Choice |
|-------|--------|
| Language | C# / .NET 10 (LTS) |
| UI | Blazor WebAssembly (hosted by the API) |
| Backend | ASP.NET Core Web API (OpenAPI, API-first) |
| Data | EF Core → Azure SQL Database (serverless) |
| Auth | ASP.NET Core Identity + JWT (RBAC); hashed API keys for pipelines |
| Packaging | Docker (chiseled, non-root runtime) |
| Hosting | Azure Container Apps (scale-to-zero) |
| CI/CD | Azure Pipelines (build → test → scan → deploy) |
| IaC | Terraform |

## Repository layout

```
src/
  Ravelin/          ASP.NET Core host — serves the Web API and the Blazor client
  Ravelin.Client/   Blazor WebAssembly UI
  Ravelin.Domain/   Pure domain model & business logic (no external dependencies)
  Ravelin.Shared/   DTOs/contracts shared between API and client
tests/
  Ravelin.Tests/    xUnit tests
Dockerfile          Multi-stage build → chiseled non-root runtime image
```

## Getting started

Prerequisites: [.NET 10 SDK](https://dotnet.microsoft.com/download). For containers, Docker.

```bash
# Build everything
dotnet build Ravelin.slnx

# Run the tests
dotnet test Ravelin.slnx

# Run the app (serves UI + API)
dotnet run --project src/Ravelin/Ravelin.csproj
# then open the printed https URL

# Health check & info endpoint
curl http://localhost:5080/health     # -> 200
curl http://localhost:5080/api/info   # -> { name, description, version, environment }
```

### Run in a container

```bash
docker build -t ravelin:dev .
docker run --rm -p 8080:8080 ravelin:dev
curl http://localhost:8080/health
```

## Status

Early development. Current: **Stage 0 — foundations / walking skeleton** (solution
structure, end-to-end client→API→shared-contract slice, containerization). Roadmap and
stage breakdown in [`PROJECT_VISION.md`](./PROJECT_VISION.md) §10.
