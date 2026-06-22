# Security Policy

Ravelin is a security tool, so it holds itself to the practices it tracks.

## Reporting a vulnerability

Email **ashar@aahmed.ca** with a description, reproduction steps, and the affected commit or
deployed version. A machine-readable contact is also published at
[`/.well-known/security.txt`](./src/Ravelin/Program.cs) (RFC 9116).

Please report privately first and give a reasonable window to fix before any public
disclosure. There is no bug-bounty program; this is a portfolio project, but reports are
genuinely welcome and will be credited if you'd like.

## What's in scope

- The API surface under `/api/*` (authn/authz, input validation, the ingestion endpoint).
- API-key and JWT handling, RBAC enforcement, and the admin console.
- The Terraform infrastructure and the container image.

## Hardening already in place

- RBAC enforced per endpoint, deny-by-default; API keys stored hashed (SHA-256).
- Application secrets (database connection, JWT signing key, seeded passwords) live in
  Azure Key Vault and are read at runtime via a managed identity — not embedded in the
  app definition or Terraform state.
- Per-IP rate limiting on auth and ingestion; account lockout after repeated failed logins.
- A Content-Security-Policy plus `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and `Permissions-Policy` on every response.
- An append-only audit trail of security-relevant actions.
- The CI pipeline scans Ravelin's own dependencies, code, container image, and IaC.

## Supported versions

This is an actively developed single-instance application; only the latest `main` /
deployed revision is supported.
