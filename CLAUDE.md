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

## Stage 3 — DONE (ingestion API, live)
- **Domain:** `ScanReconciler` (pure dedup + auto-resolve + reopen + triage-respect),
  `IncomingFinding`, `ApiKey` entity. 8 reconciler unit tests (10 total, all green).
- **Infrastructure:** `ApiKeyService` (256-bit keys, SHA-256 hash, prefix), `IngestionService`
  (loads SLA policies + existing findings → reconcile → persist + record Scan),
  `AddApiKeys` migration (applied to Azure SQL), `AddRavelinInfrastructure` DI extension.
- **API:** `ApiKeyAuthenticationHandler` (scheme "ApiKey", X-Api-Key / Bearer; project from
  the key, never the route). Endpoints: `POST /api/ingest` (API-key auth, input validation,
  5000-finding cap), admin `POST /api/admin/projects` + `/projects/{key}/api-keys` and reads
  `GET /api/projects`, `/api/projects/{key}/findings` (bootstrap-token gated via
  `BootstrapTokenFilter`, constant-time compare). DTOs in `Ravelin.Shared/Contracts`.
- **Verified live (image ravelin:0.3.2):** created project demo-app + API key; scan#1
  created 2; scan#2 → created 1, resolved 1 (auto), seen 1 → dedup + auto-resolve work.
  Auth matrix: no/bad key ingest → 401, no/bad token read → 401, good → 200. Confirmed
  unauthenticated ingestion writes NO data.
- **Bugs fixed this stage:** (1) `.DisableAntiforgery()` on token APIs; (2) scoped
  `UseStatusCodePagesWithReExecute` to non-/api paths (it was mangling API 401s into 400 by
  re-executing as POST into the Blazor not-found page).
- **Notes / debt:** bootstrap-token admin gate is temporary → replaced by Identity+RBAC in
  Stage 4. No API-key revoke endpoint yet. DataProtection keys not persisted across
  container restarts (log warning) — address when JWT signing keys arrive (Stage 4) or via
  Key Vault (Stage 8). Demo API key value appeared in session output — fine (demo data).

## Stage 4a — DONE (server auth + RBAC, live)
- `RavelinDbContext` now extends `IdentityDbContext<IdentityUser>`; `AddIdentity` migration
  applied to Azure SQL (AspNet* tables).
- Identity (AddIdentityCore + roles + EF stores), password min length 12. Roles
  Admin/Analyst/Viewer (`RavelinRoles` in Shared). `IdentitySeeder` seeds roles + admin +
  read-only demo user at startup from config (no default passwords — only seeds if a
  password is configured).
- **JWT**: `JwtTokenService` issues HMAC-SHA256 tokens (claims: sub, email, role). JwtBearer
  is the default scheme; **`MapInboundClaims=false`** + `RoleClaimType="role"` /
  `NameClaimType="email"` (without MapInboundClaims=false, RequireRole(Admin) failed 403 —
  the role claim was remapped). ApiKey scheme still used for `/api/ingest`.
- Endpoints: `POST /api/auth/login` (email/pw → JWT). Admin endpoints now
  `RequireAuthorization(RequireRole(Admin))`; reads `RequireAuthorization()` (any user).
  **Bootstrap-token gate removed** (`BootstrapTokenFilter` deleted).
- Terraform: replaced bootstrap-token secret with `jwt-signing-key`, `seed-admin-password`,
  `seed-demo-password` secrets + Jwt__*/Seed__* env. Outputs: admin_email/admin_password,
  demo_email/demo_password (sensitive). `terraform output -raw admin_password` to log in.
- **Verified live (image ravelin:0.4.3):** admin login→JWT→create project 201 / create
  api-key 200; viewer create 403, viewer read 200; no-token 401; bad login 401.
- **Debt:** JWT signing key is symmetric in a Container App secret (→ Key Vault in Stage 8);
  no token refresh yet; DataProtection keys not persisted across restarts.

## Stage 4b — DONE (Blazor login UI)
- Client auth in `src/Ravelin.Client/Auth/`: `TokenStore` (JWT in localStorage via JS interop),
  `JwtParser` (decode payload claims; NO client signature check — server validates every call),
  `JwtAuthenticationStateProvider` (ClaimsPrincipal with roleType `"role"`/nameType `"email"`;
  drops expired tokens), `AuthService` (login/logout → store token → `NotifyAuthChanged`),
  `TokenHandler` (`DelegatingHandler` adding `Authorization: Bearer`).
- DI (`Program.cs`): `AddAuthorizationCore`; HttpClient via `IHttpClientFactory`
  (`AddHttpClient("RavelinApi").AddHttpMessageHandler<TokenHandler>()`). New packages:
  `Microsoft.AspNetCore.Components.Authorization` + `Microsoft.Extensions.Http` (10.0.x).
- UI: `/login` (`EditForm`+DataAnnotations), `Routes.razor` → `CascadingAuthenticationState` +
  `AuthorizeRouteView` (unauth → `RedirectToLogin` w/ `returnUrl`; wrong role → warning),
  `NavMenu` Sign in/out + Projects link via `AuthorizeView`, protected `Projects.razor`
  (`@attribute [Authorize]`, admin-only note via `<AuthorizeView Roles="Admin">`).
- **Verified server-side vs live Azure SQL** (admin→Admin; `/api/projects` 401 w/o token, 200
  w/ bearer → web-frontend/demo-app; demo→Viewer; bad pw→401; WASM shell served). Build clean
  (0 warn), 10 tests green. Browser click-through is the final user check on the live URL.
- **GOTCHA:** reference `RedirectToLogin.razor` as bare `<RedirectToLogin />` (with
  `@using Ravelin.Client.Pages` in `_Imports`), NOT `<Pages.RedirectToLogin />` → RZ10012.
- Client is **Blazor Web App, InteractiveWebAssembly, prerender:false** — auth components run
  in WASM only, so the host needs no AuthenticationStateProvider.

## Stage 5 — DONE (SLA engine + triage); deploy pending
- **Domain** (`Ravelin.Domain/Services`): `SlaEvaluator` (pure) — `SlaState`
  (NotApplicable/OnTrack/DueSoon/Breached), `Evaluate(status,dueAt,now,window)` returns
  state + whole `DaysRemaining` (negative=overdue); `ComputeDueDate` (now reused by
  `ScanReconciler`). `FindingTriage.Apply(finding,target,note,now)` — validated transitions
  (Open/Resolved/FalsePositive/AcceptedRisk); **note required** to suppress (FP/AcceptedRisk);
  sets/clears `ResolvedAt`. SLA *due date* is still a snapshot computed at ingestion; breach
  is evaluated on read (time-dependent).
- **Contracts** (`Ravelin.Shared/Contracts`): `FindingDto` gains `SlaState` + `DaysToSla`;
  new `TriageFindingRequest`, `SlaPolicyDto`, `UpdateSlaPoliciesRequest`, `SlaSummaryDto`.
- **API** (`RavelinEndpoints.MapSla`): `GET /api/sla-policies` (any auth),
  `PUT /api/sla-policies` (Admin; re-baselines open findings' `SlaDueAt` from new days),
  `POST /api/projects/{key}/findings/{id}/triage` (Admin+Analyst), `GET
  /api/projects/{key}/sla-summary` (any auth; open-only, compliance% = (open-breached)/open).
  No schema migration (all columns already existed).
- **Tests:** `SlaEvaluatorTests` + `FindingTriageTests` → **28 total green** (was 10).
- **Verified locally vs Azure SQL:** policies read/PUT, summary (compliance 100%), findings
  carry SLA state, triage works, RBAC (viewer 403 on triage+PUT, note-required 400). Demo
  data restored after test.

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
  - **Stage 1c pipeline automation — ✅ DONE & GREEN (2026-06-21).** Pipeline runs
    end-to-end on push to `main` (build/test → SDK-container publish to ACR → `az containerapp
    update`). First green run shipped `ravelin:1` (tag = `Build.BuildId`) → revision
    `ca-ravelin-dev--0000016`, healthy.
    - **App-registration was blocked** in the Birmingham tenant ("Insufficient privileges …
      create a Microsoft Entra Application"). Solved via **managed-identity workload identity
      federation**: `infra/terraform/cicd.tf` provisions a dedicated CI identity
      `id-ravelin-dev-cicd` (AcrPush + RG Contributor; deliberately separate from the app's
      AcrPull-only runtime identity). ADO service connection `ravelin-azure` uses **Identity
      type = Managed identity** → ADO writes the federated credential onto the MI (ARM op, no
      Graph perms). The MI's `az acr login --expose-token` push worked.
    - First-run gotcha: ADO pauses to **Permit** the `ravelin-azure` connection + `ravelin-dev`
      environment before Image/Deploy stages run.
    - Note: pipeline tags images by `Build.BuildId` (e.g. `:1`); the manual deploy path uses
      semver (`:0.4.x`). Both push to the same `ravelin` repo + `latest`.
    - ⚠️ **Parallelism gate (2026-06-21):** runs after #1 hang on "Acquiring an agent" — org
      has no granted Microsoft-hosted parallelism, and **public projects are blocked by the
      Birmingham tenant policy** (so going public is not a fix). Resolution: request the free
      grant (`https://aka.ms/azpipelines-parallelism-request`, ~2-3 business days); deploy via
      the manual Docker-less path meanwhile. See `next_steps.md` §6.1.
