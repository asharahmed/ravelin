# Ravelin — Threat Model (STRIDE)

Ravelin is a vulnerability SLA & compliance tracker: CI/CD pipelines push dependency-scan
results to an authenticated API, and Ravelin gives each finding a remediation deadline, tracks
breaches, and exports audit evidence. Because it is itself a security product, it is held to the
practices it measures. This document models the system with **STRIDE** (Spoofing, Tampering,
Repudiation, Information disclosure, Denial of service, Elevation of privilege) and maps each
threat to the mitigation that exists in the codebase today, with file references.

Scope: the deployed single-instance application (`getravelin.xyz`), its API surface, its data
store, and the CI/CD and pipeline-ingestion actors around it. Companion docs:
[`architecture.md`](./architecture.md), [`../SECURITY.md`](../SECURITY.md),
[`../PROJECT_VISION.md`](../PROJECT_VISION.md) §9.

---

## 1. System overview & data-flow diagram

The whole application ships as one deployable unit: an ASP.NET Core host that serves both the
JSON API and the compiled Blazor WebAssembly client. It runs on Azure Container Apps
(scale-to-zero) behind managed-TLS ingress, backed by Azure SQL, with secrets in Azure Key
Vault read through a user-assigned managed identity.

```mermaid
flowchart TB
    subgraph internet["🌐 Internet (untrusted)"]
        browser["Human user<br/>(Blazor WASM in browser)"]
        pipeline["CI/CD pipeline step<br/>(scanner → /api/ingest)"]
        attacker["Unauthenticated / hostile client"]
    end

    subgraph azure["Azure subscription (trust boundary)"]
        subgraph ingress["Container Apps ingress (TLS termination)"]
            direction TB
            fqdn["Managed cert · static IP<br/>X-Forwarded-* forwarded"]
        end

        subgraph app["ASP.NET Core host (Ravelin) — app trust boundary"]
            direction TB
            mw["Middleware: forwarded headers → correlation id →<br/>security headers/CSP → error capture →<br/>authN → authZ → rate limiter → antiforgery"]
            api["Minimal API (/api/*)<br/>JWT scheme (humans) · ApiKey scheme (pipelines)"]
            bg["Hourly SlaReEvaluator hosted service"]
        end

        sql[("Azure SQL (serverless)<br/>users, findings, keys, audit, errors")]
        kv["Azure Key Vault<br/>db-connection, jwt-signing-key, seed passwords"]
        blob["Blob storage<br/>DataProtection keys"]
        acr["Azure Container Registry"]
        logs["Log Analytics"]
        cron["Container Apps cron Job<br/>hourly → /api/internal/reevaluate"]
    end

    subgraph external["External services"]
        slack["Slack / generic webhook"]
        linear["Linear API (issue filing)"]
    end

    cicd["Azure Pipelines / GitHub Actions<br/>(build · scan · deploy · dogfood push)"]

    browser -->|HTTPS + JWT bearer| fqdn
    pipeline -->|HTTPS + X-Api-Key| fqdn
    attacker -.->|blocked at authN/authZ| fqdn
    fqdn --> mw --> api
    api -->|conn string from Key Vault| sql
    app -->|managed identity, RBAC| kv
    app -->|managed identity| blob
    app -->|structured logs| logs
    bg --> sql
    api -->|SSRF-validated https| slack
    app -->|config-gated, scrubbed| linear
    cron -->|shared-token header| fqdn
    cicd -->|AcrPush (CI identity)| acr
    acr -->|AcrPull (runtime identity)| app
    cicd -->|dogfood: X-Api-Key → /api/ingest/dotnet| fqdn
```

---

## 2. Assets & trust boundaries

**Assets**

| Asset | Where | Why it matters |
|---|---|---|
| User password hashes | `AspNetUsers` (Azure SQL) | Account takeover |
| JWT signing key | Key Vault (`jwt-signing-key`) | Forge any user/role token |
| Pipeline API keys | `ApiKeys.KeyHash` (SHA-256, Azure SQL) | Write findings into a project |
| DB connection string (admin login) | Key Vault (`db-connection`) | Full data access |
| Findings & posture data | `Findings`, dashboards | Discloses a target's known-unpatched CVEs |
| Audit trail | `AuditEvents` | Repudiation defence; must resist tampering |
| Captured errors | `AppErrors` | May carry sensitive request context if unscrubbed |
| DataProtection keys | Blob storage | Antiforgery + password-reset token integrity |

**Trust boundaries** (crossed by an arrow in the diagram)

1. **Internet → Container Apps ingress** — TLS terminates here; every request is untrusted.
2. **Ingress → ASP.NET host** — the app trusts `X-Forwarded-*` from the ingress only (to get the
   real client IP for rate limiting); it does not trust arbitrary proxies.
3. **App → Azure SQL / Key Vault / Blob** — inside the Azure boundary, authenticated by the
   app's user-assigned managed identity (Key Vault, Blob) or a KV-sourced connection string (SQL).
4. **App → external webhook / Linear** — outbound to the public internet; treated as hostile
   sinks (SSRF validation, secret scrubbing).
5. **CI/CD → ACR → App** — the pipeline is a distinct actor with its own identity, separate from
   the app runtime identity.
6. **Pipeline ingestion (API key)** — a scanner pushing findings is a distinct, least-privilege
   actor that can only write to the one project its key is bound to.

---

## 3. STRIDE analysis

Each row states the threat, then the concrete mitigation and where it lives.

### Spoofing — impersonating a user, pipeline, or internal caller

| Threat | Mitigation (file) |
|---|---|
| Attacker poses as a human user | JWT bearer auth is the default scheme; tokens are HMAC-SHA256 signed and validated for issuer/audience/lifetime/signing-key on every request — `src/Ravelin/Program.cs:109-131`, issued by `src/Ravelin/Auth/JwtTokenService.cs`. |
| Credential stuffing / brute force on login | Per-account lockout after 5 failed attempts for 15 min (`src/Ravelin/Program.cs:88-97`) plus per-IP `auth` rate limit of 10/min (`src/Ravelin/Program.cs:62-71`). |
| Account enumeration via login responses | Login returns the same `401` whether the account is missing, locked, or the password is wrong — `src/Ravelin/Endpoints/RavelinEndpoints.cs:44-56`. |
| Attacker forges a pipeline identity | API keys are 256-bit CSPRNG secrets stored only as SHA-256 hashes; the raw key is shown once at creation. Auth compares hashes — `src/Ravelin.Infrastructure/Services/ApiKeyService.cs`, handler `src/Ravelin/Auth/ApiKeyAuthenticationHandler.cs`. |
| Attacker calls the internal re-eval endpoint | `/api/internal/reevaluate` requires a shared token compared in constant time; returns `404` when no token is configured — `src/Ravelin/Program.cs:251-268`. |
| Human token used against machine endpoints (or vice-versa) | Ingestion endpoints pin the `ApiKey` scheme explicitly; human endpoints use the JWT scheme — the two never overlap (`src/Ravelin/Endpoints/RavelinEndpoints.cs:170-203`). |

### Tampering — unauthorised modification of data or requests

| Threat | Mitigation (file) |
|---|---|
| Writing to a project you don't own via the ingest route | The project is taken from the API key's claim, never from the route or body — `ApiKeyAuthenticationHandler.cs` (`ProjectIdClaim`), consumed at `RavelinEndpoints.cs:117,212`. |
| Malformed / oversized scan payloads | Every ingested finding is validated for required fields and capped at 5000 per scan; native adapters reject non-matching reports (`FormatException`) so a bad payload can't masquerade as a clean scan and auto-resolve everything — `RavelinEndpoints.cs:119-155,208-254`. |
| SQL injection | All data access is EF Core with parameterised queries / LINQ; no string-built SQL — `src/Ravelin.Infrastructure`. |
| Illegal finding state changes (e.g. silently suppressing a breach) | Triage transitions are validated and a written justification is required to mark a finding false-positive or accepted-risk — `src/Ravelin.Domain/Services/FindingTriage.cs`. |
| Cross-site request forgery | Antiforgery is enabled globally (`src/Ravelin/Program.cs:210`); token-authenticated JSON APIs opt out deliberately (`.DisableAntiforgery()`) because bearer-token auth is not ambient-credential based. |
| Tampering with the outbound webhook target to hit internal services | Admin-supplied webhook URLs are validated https-only with loopback/RFC1918/link-local/metadata hosts blocked — `src/Ravelin.Infrastructure/Services/NotificationService.cs:73-107`. |

### Repudiation — denying an action took place

| Threat | Mitigation (file) |
|---|---|
| An operator denies making a security-relevant change | An append-only audit trail records the actor, action, target, and detail for login, registration, project create/archive, API-key create/revoke, user role change, password reset, SLA policy change, triage, webhook config, and alert ack/re-eval — `src/Ravelin.Infrastructure/Services/AuditService.cs`, recorded throughout `RavelinEndpoints.cs`, exposed at `GET /api/admin/audit` (Admin only). |
| A request can't be traced through the logs | Every request is tagged with a correlation id (inbound or generated), echoed on the response, and emitted as one structured log line to Log Analytics — `src/Ravelin/Middleware/CorrelationIdMiddleware.cs`. |
| Audit writes lost in the failing request's transaction | Audit records are written in their own DB scope, isolated from the request's unit of work — `AuditService.cs`. |

### Information disclosure — exposing data to the wrong party

| Threat | Mitigation (file) |
|---|---|
| Secrets leaked into logs, error records, or issue trackers | `SecretScrubber` redacts API-key / bearer / JWT / high-entropy substrings before anything is persisted or sent externally — `src/Ravelin.Domain/Diagnostics/SecretScrubber.cs`, applied in `AppErrorService.cs`. Captured errors store the request path only, never the query string — `ErrorCaptureMiddleware.cs:33`. |
| Secrets embedded in config / IaC state | DB connection, JWT signing key, and seed passwords live in Azure Key Vault and are read at runtime via a managed identity — `src/Ravelin/Program.cs:37-47`, `infra/terraform/keyvault.tf`. Not inline in the Container App definition. |
| Browser-side attacks (XSS, clickjacking, MIME sniff) | A Content-Security-Policy plus `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Permissions-Policy` are sent on every response — `src/Ravelin/Program.cs:165-182`. |
| API keys read back after creation | List endpoints return only the non-secret prefix and lifecycle metadata, never the key or its hash — `RavelinEndpoints.cs:311-336`. |
| Client trusting an unverified token | The Blazor client decodes the JWT only to render UI; the server independently validates the signature on every `/api/*` call — the real boundary is the API (`src/Ravelin/Program.cs:286-296`). |
| Verbose errors leaking internals | Errors are normalised as RFC 9457 ProblemDetails; production uses the exception handler, not developer pages — `src/Ravelin/Program.cs:32,185-194`. |

### Denial of service — degrading availability

| Threat | Mitigation (file) |
|---|---|
| Auth brute force / login flooding | Per-IP `auth` fixed-window limit of 10/min — `src/Ravelin/Program.cs:62-71`. |
| Ingestion abuse / flooding | Per-IP `ingest` limit of 60/min plus the 5000-finding-per-scan cap — `src/Ravelin/Program.cs:69-70`, `RavelinEndpoints.cs:19,124,236`. |
| A slow/hostile webhook stalling background work | The webhook HTTP client has a 5-second timeout and failures are swallowed so they never block ingestion or re-evaluation — `src/Ravelin/Program.cs:82`, `NotificationService.cs`. |
| Client IP spoofing to evade rate limits | The app trusts `X-Forwarded-For` from the Container Apps ingress only, so rate-limit partitioning uses the real client IP — `src/Ravelin/Program.cs:52-59`. |
| Cost-based DoS on idle infra | Scale-to-zero bounds spend; the hourly SLA check runs from a tiny cron Job that wakes the app briefly rather than an always-on replica — `infra/terraform/alerts-job.tf`. (Accepted trade-off: cold-start latency on the first request after idle.) |

### Elevation of privilege — gaining rights you shouldn't have

| Threat | Mitigation (file) |
|---|---|
| Unauthenticated access to protected data/actions | Deny-by-default: reads require any authenticated user, and every mutating endpoint carries an explicit `RequireAuthorization` / `RequireRole` — `RavelinEndpoints.cs` (`MapAdmin`, `MapReads`, `MapSla`, `MapAlerts`). |
| Self-registration granting elevated roles | New self-service accounts are always assigned the read-only Viewer role; Analyst/Admin are only assignable by an existing Admin — `RavelinEndpoints.cs:75-108`. |
| Removing the last administrator (lock-out / takeover setup) | The role-change endpoint refuses to demote the final Admin — `RavelinEndpoints.cs:384-391`. |
| A pipeline key used to read data or administer the app | API keys authenticate only ingestion endpoints; they carry no role and cannot reach read/admin routes (scheme separation), and each key is bound to a single project — `ApiKeyAuthenticationHandler.cs`, `RavelinEndpoints.cs:170-203`. |
| CI/CD identity over-privileged into the running app | The pipeline uses a dedicated managed identity with `AcrPush` + RG Contributor, deliberately separate from the app's runtime identity which holds only `AcrPull` — `infra/terraform/cicd.tf`. |
| Analyst/Viewer performing admin-only changes | SLA policy edits and API-key/user/project/webhook administration require the Admin role; triage and alert-ack require Admin or Analyst; Viewer is read-only — enforced per endpoint in `RavelinEndpoints.cs`. |

---

## 4. Known residual risks (accepted for a single-tenant demo)

Being explicit about what is *not* mitigated is part of the exercise. These are conscious
trade-offs for a portfolio project running as a single-tenant demo, not oversights.

- **Open self-service registration exposes all project data to any Viewer.** Anyone can sign up
  and read every project's findings, dashboards, and SLA posture — there is no per-project
  authorization for humans. This is intentional so a visitor can explore the live demo. A real
  multi-tenant deployment would gate registration and scope reads to a user's projects.
- **JWTs are not revocable within their lifetime.** A token stays valid for 60 minutes
  (`JwtOptions.ExpiryMinutes`); a role change, password reset, or logout does not invalidate an
  already-issued token until it expires. Acceptable for a demo; a production build would add
  short-lived tokens plus refresh, or a revocation list.
- **SQL still authenticates with the admin login.** The connection string is Key Vault-managed
  and identity-read, but switching to managed-identity SQL auth with a least-privilege contained
  DB user is deferred (it needs a T-SQL provisioning step that can lock the app out if
  mis-ordered) — see `infra/terraform/keyvault.tf` header.
- **The JWT signing key is a symmetric HMAC secret.** Whoever holds it can mint any token. It
  lives in Key Vault, but an asymmetric signing key would shrink the blast radius.
- **Terraform state contains secrets.** The remote `tfstate` (Azure Storage) holds the SQL
  connection string and generated passwords; its confidentiality depends on the storage
  account's access control.
- **Webhook SSRF defence is a denylist.** It blocks loopback/RFC1918/link-local/metadata hosts
  but does not defeat DNS rebinding or an allowlist-only posture. Admins are trusted here; it is
  cheap defence-in-depth, not a hard boundary.
- **Signup has no email verification** and the audit log is best-effort (a write failure is
  logged and dropped rather than blocking the action) — availability is favoured over guaranteed
  capture under a DB outage.

---

## 5. Self-scanning (the app secures itself)

Consistent with being a vulnerability tracker, Ravelin's own CI runs the controls it advocates —
SCA (`dotnet list package --vulnerable`), SAST (CodeQL), IaC & secret scanning (Trivy config /
secret scanners), and container-image scanning (Trivy) — with results published as SARIF to the
repository's Security tab (`.github/workflows/security.yml`). The "dogfood" step can push the
app's own dependency vulnerabilities into the live instance so `getravelin.xyz` tracks Ravelin's
own remediation SLAs (see [`../PROJECT_VISION.md`](../PROJECT_VISION.md) §9).
</content>
</invoke>
