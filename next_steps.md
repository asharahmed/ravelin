# Ravelin — Next Steps (session handoff)

> Handoff for a fresh session/collaborator. Read order: **this file → `CLAUDE.md` →
> `PROJECT_VISION.md`**. This file is the "pick up and keep building" guide; `CLAUDE.md`
> has detailed status + gotchas; `PROJECT_VISION.md` has the vision, decisions, and roadmap.
> Last updated: 2026-06-21.

---

## 1. TL;DR — where we are

Ravelin is a **vulnerability SLA & compliance tracker** (.NET 10, Blazor WASM, ASP.NET Core
API, EF Core, Azure SQL, Azure Container Apps, Terraform). **Stages 0–4a are built, committed,
and live on Azure.** Next up is **Stage 4b (Blazor login UI)**, then Stages 5–8.

- **Live app:** https://ca-ravelin-dev.thankfulsea-7af22cac.canadacentral.azurecontainerapps.io
- **Repo:** https://github.com/asharahmed/ravelin (branch `main`)
- **Deployed image:** `ravelin:0.5.0` (Stage 5 + dark mode; revision `ca-ravelin-dev--0000018`)
- **Working dir:** `/Users/ashar/proj/ravelin`

| Stage | Summary | State |
|------|---------|-------|
| 0 | Solution, clean architecture, walking skeleton, Dockerfile | ✅ live |
| 1 | Terraform infra + Azure Container Apps; CI pipeline | ✅ live (pipeline wired & green — see §6) |
| 2 | Domain model + EF Core + Azure SQL | ✅ live |
| 3 | Ingestion API (hashed API keys, dedup + auto-resolve, validation) | ✅ live |
| 4a | Identity + JWT + RBAC (Admin/Analyst/Viewer) | ✅ live |
| 4b | Blazor login UI | ✅ live |
| 5 | SLA engine + triage workflow | ✅ live |
| 6 | Dashboards (Compliance Ledger UI) | ✅ built (deploy pending) |
| 7 | Compliance report export (PDF/shareable) | ⬜ |
| 8 | DevSecOps hardening (pipeline scanners, Key Vault, MI→SQL) | ⬜ |
| 9 | (Optional) Java/Spring Boot read-only client | ⬜ |
| 10 | (Later) pull-based ingestion; alerting | ⬜ |

---

## 2. Environment & prerequisites

Installed on this machine: .NET 10 SDK (`10.0.301`), `dotnet-ef` (10.0.9, at
`~/.dotnet/tools`), Azure CLI (`az`, logged in to **"Azure for Students"**, University of
Birmingham tenant), Terraform 1.5.7, GitHub CLI (`gh`, authed as `asharahmed`), git.

- **PATH note:** prefix shell commands with `export PATH="/opt/homebrew/bin:$PATH:$HOME/.dotnet/tools"`.
- **Docker is NOT usable here** — OrbStack will not boot its VM on macOS 27, and
  `az acr build` (ACR Tasks) is blocked on Azure for Students. We build images **without
  Docker** via the .NET SDK container publish (see §4).
- If `az` session expired: `az login` (interactive, needs the user).

---

## 3. Run / build / test locally

```bash
export PATH="/opt/homebrew/bin:$PATH:$HOME/.dotnet/tools"
cd /Users/ashar/proj/ravelin

dotnet build Ravelin.slnx -c Release          # build all
dotnet test  Ravelin.slnx -c Release          # 10 tests (ScanReconciler + ApiInfo)
dotnet run --project src/Ravelin/Ravelin.csproj --urls http://localhost:5080
# Local DB: needs ConnectionStrings__RavelinDb. Either point at Azure SQL (add your IP to
# the firewall, see §5) or run SQL Server in a container once Docker works.
```

Solution layout: `src/Ravelin` (host: API + Blazor), `src/Ravelin.Client` (Blazor WASM),
`src/Ravelin.Domain` (pure), `src/Ravelin.Infrastructure` (EF Core + services),
`src/Ravelin.Shared` (DTOs/contracts/roles), `tests/Ravelin.Tests`.

---

## 4. Deploy (the proven, Docker-less path)

```bash
export PATH="/opt/homebrew/bin:$PATH"
cd /Users/ashar/proj/ravelin
VER=0.4.4   # bump each deploy
TOKEN=$(az acr login --name acrravelindevs8066d --expose-token --query accessToken -o tsv)
export SDK_CONTAINER_REGISTRY_UNAME="00000000-0000-0000-0000-000000000000"
export SDK_CONTAINER_REGISTRY_PWORD="$TOKEN"
dotnet publish src/Ravelin/Ravelin.csproj -c Release -t:PublishContainer --os linux --arch x64 \
  -p:ContainerRegistry=acrravelindevs8066d.azurecr.io -p:ContainerRepository=ravelin \
  "-p:ContainerImageTags=\"$VER;latest\"" \
  -p:ContainerBaseImage=mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra
az containerapp update --name ca-ravelin-dev --resource-group rg-ravelin-dev \
  --image acrravelindevs8066d.azurecr.io/ravelin:$VER
```

- **Base image MUST be `*-chiseled-extra`** (ICU) — plain chiseled breaks SqlClient
  ("Globalization Invariant Mode is not supported"). `InvariantGlobalization=false` is set
  in `src/Ravelin/Ravelin.csproj`.
- After deploy, wait for the new revision to reach 100% traffic before testing (rollover
  briefly serves the old revision — caused several false "it's broken" readings before):
  ```bash
  az containerapp revision list --name ca-ravelin-dev --resource-group rg-ravelin-dev \
    --query "[?properties.trafficWeight==\`100\`].properties.template.containers[0].image" -o tsv
  ```

---

## 5. Azure resources, secrets & credentials

Provisioned by Terraform in `infra/terraform/` (remote state in Azure Storage
`rg-ravelin-tfstate` / `stravelintfdfe8f1bd` / container `tfstate`). Key resources:
RG `rg-ravelin-dev`, ACR `acrravelindevs8066d`, Container App `ca-ravelin-dev`, Azure SQL
`sql-ravelin-dev-s8066d` / db `sqldb-ravelin-dev` (serverless, auto-pause 60m).

```bash
cd /Users/ashar/proj/ravelin/infra/terraform
terraform output                          # non-sensitive outputs
terraform output -raw admin_password      # admin@ravelin.local
terraform output -raw demo_password       # demo@ravelin.local (read-only Viewer)
terraform output -raw sql_connection_string   # for migrations
```

**Terraform apply protocol (a guardrail blocks blind auto-approve):**
```bash
MYIP=$(curl -s https://api.ipify.org)
terraform plan  -input=false -var="client_ip_address=$MYIP" -out=tfplan   # review output
terraform apply -input=false tfplan
```
`client_ip_address` opens the SQL firewall for your current IP so you can run migrations.

**Apply EF migrations to Azure SQL:**
```bash
export RAVELIN_DB_CONNECTION="$(cd infra/terraform && terraform output -raw sql_connection_string)"
dotnet-ef database update \
  --project src/Ravelin.Infrastructure/Ravelin.Infrastructure.csproj \
  --startup-project src/Ravelin.Infrastructure/Ravelin.Infrastructure.csproj
```

App config (Container App env, set by Terraform): `ConnectionStrings__RavelinDb`,
`Jwt__SigningKey`/`Jwt__Issuer`/`Jwt__Audience`, `Seed__AdminEmail`/`Seed__AdminPassword`,
`Seed__DemoEmail`/`Seed__DemoPassword` — all secrets via Container App secrets.

---

## 6. Open threads (not blockers)

1. **Azure DevOps pipeline (Stage 1c) — ✅ WIRED & GREEN (2026-06-21).** `azure-pipelines.yml`
   (build/test → `dotnet publish` container to ACR → `az containerapp update`) runs end-to-end
   on push to `main`. First green run deployed `ravelin:1` (tag = `Build.BuildId`) →
   revision `ca-ravelin-dev--0000016`, healthy.
   - **The Entra app-registration block was real** ("Insufficient privileges … create a
     Microsoft Entra Application"). Worked around with **managed-identity workload identity
     federation**: Terraform (`infra/terraform/cicd.tf`) provisions a dedicated CI identity
     `id-ravelin-dev-cicd` (AcrPush on ACR + Contributor on RG — kept OFF the app's runtime
     pull identity). The ADO service connection `ravelin-azure` uses **Identity type =
     Managed identity** pointing at it; ADO writes the federated credential onto the MI (an
     ARM op, no Graph perms needed). Outputs: `terraform output cicd_identity_name /
     cicd_identity_client_id`.
   - The MI's `az acr login --expose-token` push path worked (no AcrPush-token fallback needed).
   - First-run gotcha: ADO pauses to **Permit** the service connection + `ravelin-dev`
     environment before the Image/Deploy stages start — normal, click Permit once.
   - ⚠️ **PARALLELISM GATE (discovered deploying 4b, 2026-06-21).** After run #1, later runs
     hang on *"Acquiring an agent from the cloud"* — the org has **no granted Microsoft-hosted
     parallelism** (Parallel-jobs screen: Private→MS-hosted "free tier 1 job/1800min" but
     **0 consumed** = entitlement shown, not granted; Public→MS-hosted **0**). **Public is
     blocked** by the Birmingham tenant policy ("Allow public projects" can't be enabled —
     same wall as app registration), so going public is NOT a fix. **Resolution chosen:
     request the free grant** at `https://aka.ms/azpipelines-parallelism-request` (org owner,
     Private project; ~2-3 business days) → then the YAML auto-deploys on push, no changes.
     **Until granted, deploy via the manual Docker-less path (§4).** Cancel any stuck queued
     run so it doesn't linger. (Alt not taken: self-hosted agent — 1 free slot — would need
     `pool: name: 'Default'` in the YAML + a registered agent on a dev machine.)
2. **Demo data exists** in the DB: projects `demo-app` (+ an API key whose raw value leaked
   into an earlier session transcript — low risk, demo only; consider rotating when a
   revoke endpoint exists) and `web-frontend`; a few findings on `demo-app`.

---

## 7. Known gotchas (already solved — keep them solved)

- **Chiseled base needs ICU** → use `-noble-chiseled-extra` + `InvariantGlobalization=false`.
- **JWT roles**: `MapInboundClaims=false` + `RoleClaimType="role"` in JwtBearer, else
  `RequireRole` 403s even for the right role.
- **Status-code pages**: `UseStatusCodePagesWithReExecute` is scoped to non-`/api` paths,
  else API 401s get re-executed (as POST) into the Blazor not-found page and surface as 400.
- **Token APIs**: `.DisableAntiforgery()` on ingest/admin/auth POST endpoints.
- **Revision rollover**: always confirm 100% traffic on the new image before testing.

---

## 8. Stage 4b — DONE (Blazor login UI). NEXT: Stage 5 (SLA engine + triage)

**Stage 4b shipped (client plumbing in `src/Ravelin.Client`, all in `Auth/`):**
- `TokenStore` (JWT in localStorage via `IJSRuntime`), `JwtParser` (decode payload claims, no
  client-side signature check — server validates every call), `JwtAuthenticationStateProvider`
  (builds `ClaimsPrincipal`; roleType `"role"`, nameType `"email"`; drops expired tokens),
  `AuthService` (login/logout → store token → `NotifyAuthChanged`), `TokenHandler`
  (`DelegatingHandler` attaching `Authorization: Bearer`).
- DI: `AddAuthorizationCore`; HttpClient is now built via `IHttpClientFactory`
  (`AddHttpClient("RavelinApi").AddHttpMessageHandler<TokenHandler>()`) — needs the
  `Microsoft.Extensions.Http` + `Microsoft.AspNetCore.Components.Authorization` packages.
- UI: `/login` page (`EditForm` + DataAnnotations), `Routes.razor` wrapped in
  `CascadingAuthenticationState` + `AuthorizeRouteView` (unauth → `RedirectToLogin` with
  `returnUrl`; wrong role → warning), `NavMenu` shows Sign in / Sign out + "Projects" link via
  `AuthorizeView`, protected `Projects.razor` (`@attribute [Authorize]`, role-gated admin note
  via `<AuthorizeView Roles="Admin">`).
- **Verified server-side against live Azure SQL** (admin login→Admin role; `/api/projects` 401
  without token, 200 with bearer; demo→Viewer; bad pw→401; WASM shell served). Browser
  click-through is the user's final check on the live URL.
- Gotcha to keep: `RedirectToLogin.razor` referenced as bare `<RedirectToLogin />` (with
  `@using Ravelin.Client.Pages` in `_Imports`), not `<Pages.RedirectToLogin />` (RZ10012).

**NEXT — Stage 5 (SLA engine + triage):** compute breach states, time-to-remediation, and
triage actions (false-positive / accepted-risk) on findings; expose via API; add unit tests
for SLA math. See `PROJECT_VISION.md` §10. (Note: `SlaPolicy` is already seeded — 4 rows.)

---

## 9. Working agreement (how to proceed)

- Build **stage by stage**; keep changes PR-sized; the user reviews each stage.
- **Confirm before costly/irreversible actions**; show a Terraform plan before apply.
- Use **current docs** (`ctx7`/find-docs) for .NET/Azure/EF/Terraform APIs, not memory.
- Update `CLAUDE.md` + this file as stages complete. Commit only when the user asks (they
  have so far asked to commit each completed stage).
- This is a **security tool** — model good AppSec (validate input, least privilege, no secret
  leakage, deny by default). The app should eventually scan itself in CI (Stage 8).
- Don't touch the unrelated TypeScript project at `../cadence`.
