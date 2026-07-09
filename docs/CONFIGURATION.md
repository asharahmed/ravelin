# Configuration reference

Every setting Ravelin reads, its default, and whether it's a secret. Settings use the standard
ASP.NET Core configuration system: a `Section:Key` maps to the environment variable
`Section__Key` (double underscore). In Azure the secret-marked values are delivered from Key
Vault via the app's managed identity; locally they come from `.env` / environment / user-secrets.

**Never commit secrets.** `.env`, `appsettings.*.local.json`, and `terraform.tfvars` are gitignored.

## Core

| Setting (env var) | Secret | Default | Purpose |
|---|---|---|---|
| `ConnectionStrings__RavelinDb` | **yes** | — | Azure SQL / SQL Server connection string. Required. |
| `ASPNETCORE_ENVIRONMENT` | no | `Production` (in container) | `Development` / `Production`. Production enforces the JWT key and fail-closed migrations. |
| `ASPNETCORE_HTTP_PORTS` | no | `8080` | Port the app listens on. |

## Authentication & registration

| Setting | Secret | Default | Purpose |
|---|---|---|---|
| `Jwt__SigningKey` | **yes** | — | HMAC-SHA256 signing key. **≥ 32 bytes; the app refuses to start in Production without it.** |
| `Jwt__Issuer` | no | `ravelin` | JWT `iss`. |
| `Jwt__Audience` | no | `ravelin` | JWT `aud`. |
| `Jwt__ExpiryMinutes` | no | `60` | Access-token lifetime. Revocation is immediate via the security stamp regardless. |
| `Registration__Mode` | no | `Disabled` | `Disabled` = admin-created accounts only; `Open` = self-service signup (read-only Viewer). The public demo uses `Open`. |

## Seeding

| Setting | Secret | Default | Purpose |
|---|---|---|---|
| `Seed__AdminEmail` | no | `admin@ravelin.local` | Seeded Admin account. |
| `Seed__AdminPassword` | **yes** | — | If unset, **no** admin is seeded (never ships a default password). |
| `Seed__DemoEmail` | no | `demo@ravelin.local` | Seeded read-only Viewer. |
| `Seed__DemoPassword` | **yes** | — | If unset, no demo user is seeded. |
| `Seed__DemoData` | no | `false` | When `true`, seeds demo projects/findings (marked public). |

## Risk intelligence (CISA KEV + FIRST EPSS)

| Setting | Secret | Default | Purpose |
|---|---|---|---|
| `VulnIntel__Enabled` | no | `false` | Turn KEV/EPSS enrichment on. Off = no external calls. |
| `VulnIntel__KevFeedUrl` | no | CISA KEV feed | Override the KEV catalog URL. |
| `VulnIntel__EpssApiUrl` | no | FIRST EPSS API | Override the EPSS API URL. |
| `VulnIntel__KevRemediationDays` | no | `14` | SLA (days) for an actively-exploited finding. |
| `VulnIntel__HighEpssRemediationDays` | no | `30` | SLA (days) for a high-EPSS finding. |
| `VulnIntel__EpssEscalationThreshold` | no | `0.5` | EPSS (0–1) at/above which the high-EPSS SLA applies. |

## Alerting & integrations

| Setting | Secret | Default | Purpose |
|---|---|---|---|
| `Reeval__Token` | **yes** | — | Shared secret for `POST /api/internal/reevaluate` (the scheduled alerts cron). Endpoint 404s when unset. |
| `Linear__ApiKey` | **yes** | — | Enables filing captured errors as Linear issues. Inert when unset. |
| `Linear__TeamId` | no | — | Linear team for created issues. |

## DataProtection (key persistence, Azure)

| Setting | Secret | Default | Purpose |
|---|---|---|---|
| `DataProtection__BlobUri` | no | — | Blob URI for persisted DataProtection keys (antiforgery / reset tokens). Unset = ephemeral local keys. |
| `DataProtection__IdentityClientId` | no | — | Managed-identity client id used to read that blob. |

## Notes

- **Production hard requirements:** `ConnectionStrings__RavelinDb` and a strong `Jwt__SigningKey`.
  Everything else has a safe default or is inert when unset.
- **Local quickstart:** `.env.example` provides working values for `docker compose up`.
- **Migrations** are applied on boot (fail-closed in Production); no separate migration step.
