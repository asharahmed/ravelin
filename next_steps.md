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
- **Deployed image:** `ravelin:0.4.3`
- **Working dir:** `/Users/ashar/proj/ravelin`

| Stage | Summary | State |
|------|---------|-------|
| 0 | Solution, clean architecture, walking skeleton, Dockerfile | ✅ live |
| 1 | Terraform infra + Azure Container Apps; CI pipeline authored | ✅ live (pipeline not wired — see §6) |
| 2 | Domain model + EF Core + Azure SQL | ✅ live |
| 3 | Ingestion API (hashed API keys, dedup + auto-resolve, validation) | ✅ live |
| 4a | Identity + JWT + RBAC (Admin/Analyst/Viewer) | ✅ live |
| 4b | Blazor login UI | ⬜ **next** |
| 5 | SLA engine + triage workflow | ⬜ |
| 6 | Dashboards | ⬜ |
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

1. **Azure DevOps pipeline (Stage 1c) is authored but NOT wired up.** `azure-pipelines.yml`
   exists (build → `dotnet publish` container → `az containerapp update`). To activate, the
   **user** must: create an Azure DevOps org + `ravelin` project, create an Azure RM
   **service connection** named `ravelin-azure`, point a pipeline at the repo's YAML.
   ⚠️ The university tenant may block the app registration a service connection needs — if
   so, fall back to ACR scoped tokens for push and revisit ARM auth. **Do not autonomously
   create directory identities / service principals** in the shared tenant.
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

## 8. IMMEDIATE NEXT TASK — Stage 4b: Blazor login UI

**Goal:** a person can log in through the browser; the UI reflects auth state and role.
Server side is done (`POST /api/auth/login` → JWT; RBAC enforced). This is client plumbing in
`src/Ravelin.Client`.

Suggested steps (verify against current Blazor WASM docs via `ctx7`/find-docs — the client is
**Blazor Web App, InteractiveWebAssembly, prerender disabled**):

1. **Token storage** — store the JWT in browser `localStorage` (via `IJSRuntime` interop or a
   small wrapper). Avoid heavy deps; a tiny JS interop is fine.
2. **`AuthenticationStateProvider`** — custom provider that reads the stored JWT, parses
   claims (incl. `role`), and exposes auth state. Clear on logout/expiry.
3. **Login page** (`/login`) — email + password form → `POST /api/auth/login` → store token →
   notify auth state → redirect. Show error on 401. Use the `LoginRequest`/`LoginResponse`
   contracts in `Ravelin.Shared.Contracts`.
4. **Attach Bearer token** — a `DelegatingHandler` on the `HttpClient` that adds
   `Authorization: Bearer <token>` to API calls (the client already registers an HttpClient
   in `src/Ravelin.Client/Program.cs`).
5. **`AuthorizeView` / `CascadingAuthenticationState`** — wrap `Routes`/layout; show
   login/logout in `NavMenu`; gate admin-only UI by role (`RavelinRoles` in Shared).
6. **Wire `Routes.razor`** to `AuthorizeRouteView` so protected pages require auth.
7. **Verify**: log in as admin (creds in §5) in the browser; confirm authed UI + a protected
   call works; log in as the demo Viewer; confirm read-only. Then build/deploy (§4) and
   re-verify on the live URL.

**Definition of done:** browser login works end-to-end on the live app for both admin and
demo users; unauthenticated users are redirected to login; role-gated UI behaves.

After 4b: **Stage 5 (SLA engine + triage)** — compute breach states, time-to-remediation,
and triage actions (false-positive / accepted-risk) on findings; expose via API; add unit
tests for SLA math. See `PROJECT_VISION.md` §10.

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
