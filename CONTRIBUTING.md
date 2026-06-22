# Contributing to Ravelin

Thanks for taking a look. Ravelin is a portfolio project, but it's built like a real one, and
contributions are welcome.

## Getting set up

See [Running locally](./README.md#running-locally) in the README — SQL Server in a container,
migrations, then `dotnet run`. The domain has no infrastructure dependencies, so most logic is
unit-testable without a database.

```bash
dotnet build Ravelin.slnx
dotnet test  Ravelin.slnx
```

## How the code is organised

- `Ravelin.Domain` — entities and pure business logic (reconciliation, SLA engine, triage,
  scanner adapters). No EF, no ASP.NET — this is where most tests live.
- `Ravelin.Infrastructure` — EF Core, persistence, and application services.
- `Ravelin` — the ASP.NET Core host and the HTTP API (`Endpoints/RavelinEndpoints.cs`).
- `Ravelin.Client` — the Blazor WebAssembly UI.
- `Ravelin.Shared` — DTOs shared by the API and the client.

## Conventions

- **Keep the domain pure.** New finding sources are adapters in `Ravelin.Domain.Ingestion`
  that map to `IncomingFinding`; add unit tests alongside them.
- **API-first.** Every capability is an HTTP endpoint with an OpenAPI description (browse it
  at `/scalar`); the UI is one client.
- **Security by default.** Validate input at the boundary, enforce RBAC on every endpoint,
  never log secrets, and store credentials hashed.
- **Match the surrounding style** — naming, comment density, and the existing patterns.
- Keep changes PR-sized and reviewable; run `dotnet build` and `dotnet test` (both should be
  clean) before opening a PR.

## Reporting bugs and vulnerabilities

Open an issue for bugs. For security issues, follow [SECURITY.md](./SECURITY.md) instead of
filing a public issue.
