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

## Stage 2 — DONE (domain model + Azure SQL, live)
- **Domain** (`Ravelin.Domain`): entities Project, Scan, Finding, SlaPolicy + enums
  (Severity, FindingStatus, ScanSource). Finding dedup identity = (ProjectId,
  VulnerabilityId, PackageName, PackageVersion).
- **Infrastructure** (`Ravelin.Infrastructure`): EF Core 10 (SqlServer), `RavelinDbContext`,
  IEntityTypeConfiguration classes (unique indexes incl. dedup; SLA seed via HasData),
  design-time factory (reads `RAVELIN_DB_CONNECTION`). Migration `InitialCreate`.
- **Azure SQL** added to Terraform (`sql.tf`): serverless `GP_S_Gen5_1`, auto-pause 60m,
  firewall (AllowAzureServices + optional client IP via `client_ip_address` var). Conn
  string delivered to Container App as secret `db-connection` → env
  `ConnectionStrings__RavelinDb`. Server `sql-ravelin-dev-s8066d`, db `sqldb-ravelin-dev`.
- Migration applied to Azure SQL; app verified live: `/api/db/status` →
  `{connected:true, slaPolicies:4, ...}`. Current deployed image **ravelin:0.2.3**.
- **GOTCHA fixed:** chiseled base image lacks ICU → SqlClient throws "Globalization
  Invariant Mode is not supported." Fixed by base image **`aspnet:10.0-noble-chiseled-extra`**
  + `<InvariantGlobalization>false</InvariantGlobalization>` in `src/Ravelin/Ravelin.csproj`
  (applied to Dockerfile + pipeline too).
- **Tech debt (→ Stage 8):** app uses SQL admin creds via connection-string secret;
  harden to managed-identity auth + least-priv DB user + Key Vault. `/api/db/status` is a
  temporary diagnostic (coarse status only); replaced by real API in Stage 3.

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
- **1c (interactive cloud) — PARTIALLY DONE:**
  - Azure sub: **"Azure for Students"** (id `216b2b76-179a-438f-8d2c-b3e4d302fcb9`),
    **University of Birmingham tenant** `b024cacf-...`. Resource providers registered.
  - **Terraform applied — infra LIVE** (8 resources). Outputs:
    - app_url: `https://ca-ravelin-dev.thankfulsea-7af22cac.canadacentral.azurecontainerapps.io`
    - acr: `acrravelindevs8066d` / `acrravelindevs8066d.azurecr.io`
    - rg: `rg-ravelin-dev`, container app: `ca-ravelin-dev`
    - State storage: `rg-ravelin-tfstate` / `stravelintfdfe8f1bd` / container `tfstate`.
  - **APP IS LIVE & HEALTHY** at the app_url (health 200, /api/info returns
    environment=Production, Blazor served). Real image `ravelin:0.1.0` deployed; revision
    `ca-ravelin-dev--0000001` healthy, scales to zero on idle.
  - **How we built/deployed without Docker or ACR Tasks (both blocked):**
    - `az acr build` is **blocked** on Azure for Students (`TasksOperationsNotAllowed`).
    - Local Docker (OrbStack) won't boot its VM on macOS 27 (times out).
    - SOLUTION: **.NET SDK container publish** (`dotnet publish -t:PublishContainer`,
      `Microsoft.NET.Build.Containers`) builds an OCI image with **no Docker daemon** and
      pushes straight to ACR. Auth via `az acr login --expose-token` (Owner session, no
      service principal). Targeted `--os linux --arch x64` (Container Apps is amd64) on the
      chiseled base. Then `az containerapp update`. The Dockerfile is kept but unused by
      this path.
  - **Pipeline (`azure-pipelines.yml`) rewritten** to the same Docker-less SDK-container
    approach (build/test → `dotnet publish -t:PublishContainer` to ACR → `az containerapp
    update`), all under one ARM service connection.
  - **REMAINING (user-gated): Stage 1c pipeline automation.** Needs the user to: create the
    Azure DevOps org + `ravelin` project, create the **`ravelin-azure` ARM service
    connection** (requires app registration — may be restricted in the Birmingham tenant;
    user must drive this, NOT autonomous), point a pipeline at `azure-pipelines.yml`, run
    it. The app is already live via the manual path regardless.
