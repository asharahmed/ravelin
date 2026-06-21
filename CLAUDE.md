# CLAUDE.md — Ravelin

Guidance for AI sessions working in this repo. Read this first, then
[`PROJECT_VISION.md`](./PROJECT_VISION.md) for the full, authoritative project definition.

## What this is
**Ravelin** — a lightweight, vendor-neutral **vulnerability SLA & compliance tracker**.
CI/CD pipelines push dependency-scan (SCA) results to an authenticated API; the product's
differentiator is the **accountability layer**: severity-based remediation SLAs, security-
posture trends over time, and audit-ready compliance reports. Goal: simultaneously
**(1)** deepen AppSec skills, **(2)** showcase Azure DevOps / CI-CD / C# / .NET, and
**(3)** be genuinely useful. Built under job-hunt time pressure.

**`PROJECT_VISION.md` is the single source of truth.** If anything here conflicts with it,
the vision doc wins. Keep both updated as decisions are made.

## Owner context
- **AppSec:** comfortable (knows OWASP Top 10, applied secure coding). Wants to go deeper.
- **C#/.NET & Azure:** new to both — **explain .NET/Azure choices in plain language**;
  treat build steps as learning. Comfortable on security concepts.

## Tech stack (all decided — see PROJECT_VISION.md §8)
- **Everything in C#/.NET** (latest LTS). UI = **Blazor WebAssembly (hosted)** served by
  the ASP.NET Core host.
- **ASP.NET Core Web API** (JSON + authenticated pipeline-ingestion endpoint), **OpenAPI**
  published. **API-first** — the API never assumes a particular UI.
- **EF Core** + migrations → **Azure SQL Database (serverless)**; local dev uses a **SQL
  Server container** so dev matches prod.
- **Auth:** ASP.NET Core **Identity + JWT** for humans (RBAC: Admin/Analyst/Viewer,
  Entra-ready); **scoped, hashed, rotatable API keys** for pipelines.
- **Docker** → **Azure Container Apps** (scale-to-zero) + Azure Container Registry.
- **Public GitHub repo** + **Azure Pipelines** (Azure Boards optional). **Terraform** IaC
  (remote state in Azure Storage).
- **Optional stretch:** a Java/Spring Boot (Thymeleaf) read-only client on the same API.

## How to work here
- **Stage-by-stage.** Follow the build plan in PROJECT_VISION.md §10. The user reviews
  each stage; keep changes PR-sized and reviewable. Do not jump ahead or scaffold the
  whole app at once.
- **Confirm before large/irreversible moves.** Flag anything costly or hard to undo.
- **Don't write code until the current stage is agreed.** As of this file's creation,
  **no application code exists yet** — next up is Stage 0 (foundations / walking skeleton).
- **Use current docs, not memory.** Use `ctx7` / find-docs for .NET, ASP.NET Core, EF Core,
  Blazor, Azure Container Apps, Terraform azurerm, and Azure Pipelines APIs/syntax.
- **CLIs are the integration surface:** `dotnet`, `docker`, `terraform`, `az`, `gh`.

## Security-first conventions (this is a security tool — it must model good AppSec)
- Validate all input at the API boundary; treat ingested scan payloads as untrusted.
- Never log secrets/API keys; store API keys **hashed**; secrets live in **Azure Key Vault**.
- Enforce RBAC on every endpoint; deny by default.
- The pipeline must scan **this app itself** (SCA, SAST, secret, container image, IaC) —
  "eats its own dog food." See PROJECT_VISION.md §9.
- Maintain a STRIDE threat model doc as the app grows.

## Watch out for (environment notes)
- There is an **unrelated TypeScript project** at `../cadence` — do not touch it.
- Keep the GitHub repo and Azure DevOps project **public** to ease free pipeline minutes.
- Azure SQL serverless and Container Apps **cold-start** after idle — expected/acceptable.

## Current status
Vision + all 6 technical decisions agreed. Build plan defined.
**Stage 0 (foundations / walking skeleton) — code complete & verified natively:**
- .NET 10 solution (`Ravelin.slnx`) with clean separation: `Ravelin` (host), `Ravelin.Client`
  (Blazor WASM), `Ravelin.Domain`, `Ravelin.Shared`, `Ravelin.Tests`.
- End-to-end slice working: Blazor Home page calls `/api/info` (returns shared `ApiInfo`
  DTO); `/health` probe added. Verified via `dotnet run` (health 200, api/info JSON, root
  page served). `dotnet build` + `dotnet test` green (2 tests).
- Containerized: multi-stage `Dockerfile` → chiseled non-root runtime; `.dockerignore`.
- **Git/GitHub:** initialized; first commit pushed to **public** repo
  `https://github.com/asharahmed/ravelin` (branch `main`, remote `origin`).
- **Deferred:** in-container smoke test (`docker build`/`run`) — OrbStack daemon would not
  start in the session (stuck "Starting" on pre-release macOS 27; no Docker Desktop). The
  Dockerfile will be validated for real by the Stage 1 pipeline build. Re-run locally once
  Docker is fixed (`brew reinstall --cask orbstack` may help).

**Stage 0 = DONE** (only the optional local Docker smoke test deferred).

**Stage 1 in progress:**
- **1a (Terraform) — authored & `terraform validate` clean** (azurerm v4.78, TF 1.5.7).
  `infra/terraform/` provisions RG, Log Analytics, ACR (admin disabled), user-assigned
  identity + AcrPull, Container Apps env + app (scale-to-zero, /health probes, placeholder
  image; pipeline updates image, TF ignores image drift). Remote state via
  `scripts/bootstrap-tfstate.sh` + `backend.hcl`. Azure SQL deferred to Stage 2.
- **1b (Azure Pipeline) — authored, valid YAML.** `azure-pipelines.yml`: build/test →
  `az acr build` → `az containerapp update`. Security scanning deferred to Stage 8.
- **1c (interactive cloud) — PENDING:** user has Azure subscription ready; needs to finish
  creating Azure DevOps org + `ravelin` project, then `az login`, then: bootstrap state →
  `terraform apply` → create `ravelin-azure` ARM service connection + pipeline in ADO →
  set `acrName`/`acrLoginServer` vars from TF outputs → run pipeline → live URL.
