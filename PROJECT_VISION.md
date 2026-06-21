# Project Vision — Ravelin

**Ravelin** — a vulnerability SLA & compliance tracker. *Tagline: "Hold the line on security debt."*
(A *ravelin* is a triangular defensive outwork in front of a fortress wall — an outer layer of defense.)

> **Naming note:** "Ravelin" is also an existing UK fraud-detection company. Fine for a
> portfolio piece; if you ever want a unique repo/domain, consider a qualifier like
> `ravelin-sec` or `ravelin-appsec`. Folder/repo: `ravelin`. To revisit later.

> **Status:** Vision + all 6 decisions agreed; build plan set. **Stage 0 code complete &
> verified natively** (Docker smoke test + git/GitHub still pending). Next: finish Stage 0,
> then Stage 1.
> **Last updated:** 2026-06-21
> This document is the single source of truth for the project. It is written so that a
> fresh AI session or a new collaborator can understand the project 100% without
> re-explaining. Update it as decisions are made.

---

## 1. Why this project exists (goals)

The owner is building this to achieve **three goals at once, weighted equally**:
1. **Deepen AppSec skills** through genuine hands-on practice (secure coding, threat
   modeling, security testing, DevSecOps).
2. **Showcase Azure DevOps, CI/CD, C#, and .NET** — currently the most in-demand
   skills for the owner's job search.
3. **Be a genuinely useful tool**, not a throwaway demo.

This is a **portfolio + learning + real-tool** project, built under **job-hunt time
pressure** (owner can work full-time-ish on it, wants a strong showcase ASAP).

### Owner's starting point
- **AppSec:** Comfortable — knows OWASP Top 10, has applied secure coding / some
  security testing. Wants to go deeper and build a portfolio of it.
- **C#/.NET & Azure DevOps:** New to both. Needs every .NET and Azure choice explained
  in plain language; build stages should double as learning.

---

## 2. What we're building (one-liner)

A **lightweight, vendor-neutral, self-hostable vulnerability SLA & compliance tracker**:
it ingests dependency-vulnerability scan results from CI/CD pipelines, then focuses on
the **accountability layer** that existing tools do poorly — tracking remediation
against SLAs, showing security-posture trends over time, and producing audit-ready
compliance reports.

### The gap it fills (why it's not "just another scanner dashboard")
Every *finding type* already has mature tools (Dependabot/Snyk/Trivy for dependencies,
SonarQube/CodeQL for SAST, GitGuardian for secrets), and aggregation-of-everything is
done by DefectDojo (heavy/sprawling) and GitHub Advanced Security (paid, ecosystem-
locked). **The genuine, defensible niche is the accountability layer:** Are we meeting
our own remediation SLAs? Is our posture trending up or down? Can I hand an auditor a
clean report? Existing tools show findings well but hold teams accountable poorly. This
tool is the **lightweight, vendor-neutral SLA + trend + compliance-report layer wrapped
around the findings.**

The novelty is **not** the finding type — it's what we do with the findings.

---

## 3. Scope decisions (AGREED)

| # | Topic | Decision |
|---|-------|----------|
| 1 | Core function | **Trend & compliance tracking** (posture over time, SLA adherence, audit-style reports). This is the differentiator. |
| 2 | Finding substrate | **Dependency vulnerabilities only (SCA)** for v1 — e.g. Trivy / Dependabot output. Most universal, easiest to demo with real CVEs/severities, keeps scope tight. |
| 3 | Data ingestion | **Push now, pull later.** v1 = CI/CD pipelines POST scan results to an authenticated API endpoint. Design a clean **normalized-finding seam** so pull-based sources (GitHub Dependabot API, Azure DevOps, registries) can be added later as a separate stage **without rework**. |
| 4 | Users & tenancy | **Single organization, multiple roles (RBAC).** Roles: **Admin** (manages SLA policies, projects, users), **Security Analyst** (triages findings), **Viewer** (read-only reports). No multi-tenant isolation. |
| 5 | SLA model | **Severity-based deadlines.** Admin sets a remediation deadline per severity (e.g. Critical=7d, High=30d, Medium=90d, Low=180d). A finding's clock starts at **first detected**; it is **breached** if still open past its deadline. |
| 6 | Finding lifecycle | **Smart dedup + auto-resolve.** Findings are matched across scans by a stable identity (e.g. CVE + package + project). New findings get a `firstDetected` date. Findings **absent from the latest scan** are auto-marked **Resolved** with a `resolvedAt` date. This is what makes SLA/trend math correct. |
| 7 | Triage states | **Open / Resolved (auto)** + **False-positive** (excluded from SLA/metrics) + **Accepted-risk** (acknowledged, excluded or shown separately, ideally with an expiry). Industry-standard minimum for credible compliance. |
| 8 | Reporting output | **Web dashboards + exportable report.** Interactive dashboards (posture over time, SLA compliance %, breaches by project/severity) **plus** a generated point-in-time report exportable as **PDF and/or shareable link** for auditors/customers. |
| 9 | Alerting | **Pull-only for v1**, but keep the data model **alert-ready** (SLA-breach states are computed) so email/Slack alerts can be added later without rework. |
| 10 | Live demo | **Live hosted demo on Azure + public repo.** A running instance a recruiter/employer can log into (seeded demo data + read-only demo account), plus the public repo, pipeline, IaC, and docs. Forces real public-facing-app hardening (good AppSec story). |
| 11 | Budget | **Use Azure free credit** (free trial / student / MSDN). Plan around free tiers and scale-to-zero to make credits last; cold starts acceptable. |

---

## 4. Core domain model (working draft)

Entities (to be refined during technical-design):
- **Project** — a codebase/repo whose pipeline pushes scans (name, identifier, optional
  per-project metadata). Findings are grouped under a Project.
- **Scan** — a single ingestion event for a Project (timestamp, source, tool, raw
  payload reference). Used for dedup/auto-resolve reconciliation.
- **Finding** — a normalized vulnerability: stable identity (CVE + package + project +
  version range as applicable), severity, package/component, status (Open / Resolved /
  False-positive / Accepted-risk), `firstDetected`, `resolvedAt`, `slaDeadline`,
  `slaBreached` (computed), triage notes.
- **SlaPolicy** — severity → deadline (days). Org-level for v1.
- **User** — with **Role** (Admin / Analyst / Viewer).
- **(Alert-ready)** — breach state computed and queryable, no delivery in v1.
- **(Audit trail)** — at minimum, state-change history sufficient for compliance.

**Normalized-finding seam:** all ingestion (push now; pull later) must convert source
formats into one internal normalized Finding shape, so new sources are additive.

---

## 5. Key showcase angles (what employers should see)

- **AppSec:** secure-by-design (authn/authz/RBAC, input validation, secrets handling,
  tenant/role boundaries), threat model document, and **security tooling wired into the
  CI/CD pipeline itself** (SAST, dependency scanning, secret scanning, possibly DAST) —
  the app *eats its own dog food* since it's a vuln tracker.
- **Azure DevOps / CI/CD:** a real **Azure Pipelines** build → test → security-scan →
  deploy flow; infrastructure-as-code; environments; the pipeline visibly produces the
  scan data the app consumes.
- **C#/.NET:** a real .NET web API + UI, tests, clean architecture.
- **Useful product:** the SLA/compliance angle is a credible niche, demoed live.

---

## 6. Technical decisions log

### Decided
- **D1 — App shape / UI:** **Blazor WebAssembly (hosted) + ASP.NET Core Web API.**
  Entire project in C# (no JavaScript framework). The same ASP.NET Core app serves both
  the JSON API (including the authenticated pipeline-ingestion endpoint) and the compiled
  Blazor WASM client as static files → **single deployable unit, cheap to host.**
  Consequence: the UI runs in the browser, so **auth is token-based** (client obtains a
  token and calls the API with it) — feeds into D3.
  *Hard-to-undo:* moderate (UI rewrite); keep API/business logic cleanly separated so the
  backend is reusable if the UI ever changes.

- **D2 — Database:** **Azure SQL Database (serverless tier, using the Azure SQL free
  offer), accessed via EF Core.** Serverless **auto-pauses when idle** to preserve free
  credit (cold-start on first request is acceptable). Local development uses the **same
  engine** via a SQL Server container (e.g. `mssql` in Docker) so dev matches prod. EF
  Core migrations manage schema.
  *Hard-to-undo:* moderate — EF Core abstracts the provider, but real data + provider-
  specific migrations make an engine swap a chore.

### Architecture principle (locked)
- **API-first / contract-first.** The C# Web API is the single source of truth and
  publishes an **OpenAPI/Swagger** spec. The Blazor WASM client is just *one* consumer;
  the API must never assume a particular UI. This keeps the backend reusable and makes
  additional clients (see below) cheap to add.

### Optional / stretch components (build AFTER core is working)
- **Java/Spring Boot secondary client — read-only dashboard (Thymeleaf).** A separate,
  server-rendered Spring Boot web app that authenticates to and consumes the **same C#
  API**, showing a read-only view of posture/SLA data. Purpose: demonstrate **polyglot
  ability + API-first design** ("one backend, two frontend stacks": Blazor + Spring).
  Strictly optional and time-boxed; never blocks the core .NET deliverable. Ideally gets
  its own build/test/security pipeline too. Auth approach must align with whatever D3
  decides (it will need to obtain and send tokens like any other client).
  *Scope flag:* a full second app in a second language is real ongoing work — payoff is
  the polyglot story, cost is time; that's why it's optional.

- **D3 — Auth mechanism:** Two separated concerns.
  - *Human auth:* **ASP.NET Core Identity (local accounts) issuing JWT bearer tokens** the
    Blazor WASM client sends to the API. Not "rolling your own" — Identity is Microsoft's
    vetted framework (password hashing, lockout, etc.). Maximizes AppSec showcase surface,
    frictionless seeded demo login, cheap/self-contained. RBAC (Admin/Analyst/Viewer) via
    claims. **Kept abstracted so Microsoft Entra ID external login can be added later** for
    an enterprise-SSO story.
  - *Machine/pipeline auth:* **scoped API keys** — per-project, stored **hashed at rest**,
    rotatable, scoped to ingestion only (least privilege). The Spring client (if built) and
    any other consumer obtain/send credentials the same token way.
  *Hard-to-undo:* moderate — switching identity providers later means migrating the user
  store; abstraction limits the pain.

- **D4 — Hosting / compute:** **Azure Container Apps**, app packaged as a **Docker
  container**. Serverless **scale-to-zero** (best free-credit fit; cold start acceptable).
  Containerizing unlocks **self-scanning the app's own image** (e.g. Trivy) in CI — a
  standout DevSecOps "eats its own dog food" moment for this security tool. Container
  registry: Azure Container Registry (or GitHub Container Registry). Database remains
  Azure SQL serverless (D2).
  *Hard-to-undo:* low — containerizing makes the app portable and *reduces* lock-in.

- **D5 — Source control + CI/CD home:** **Public GitHub repo** (recruiter-facing
  visibility) **+ Azure Pipelines** for CI/CD (build, test, security-scan, containerize,
  deploy) — the marketable core of Azure DevOps. Keep GitHub repo + Azure DevOps project
  **public** to ease free pipeline-minutes grant. **Azure Boards (optional)**, linked to
  the repo, to round out the suite story if time allows.
  *Hard-to-undo:* low-to-moderate — git host is easy to move; Azure Pipelines YAML is
  platform-specific (a later switch to GitHub Actions would mean rewriting pipeline YAML).

- **D6 — Infrastructure-as-code:** **Terraform** (cloud-agnostic, most in-demand IaC
  skill). Remote state stored in an **Azure Storage account**. Defines all Azure
  resources: Container App(s) + environment, Azure SQL serverless, container registry,
  storage, and supporting config.
  *Hard-to-undo:* low — self-contained; doesn't touch application code.

### Still later (not yet decided)
- PDF/report generation approach.
- Pull-based ingestion sources (explicitly a later stage).
- Azure Boards usage (optional).

---

## 8. Final stack at a glance

| Layer | Choice |
|-------|--------|
| Language (everything) | **C# / .NET** (latest LTS) — UI included via Blazor |
| UI | **Blazor WebAssembly (hosted)** — served by the API host |
| Backend | **ASP.NET Core Web API** (JSON + authenticated pipeline-ingestion endpoint), OpenAPI/Swagger published |
| Data access | **EF Core** with migrations |
| Database | **Azure SQL Database (serverless, free offer)**; local = SQL Server container |
| Human auth | **ASP.NET Core Identity + JWT**; RBAC (Admin/Analyst/Viewer); Entra-ready |
| Machine auth | **Scoped, hashed, rotatable API keys** (pipeline → API) |
| Packaging | **Docker** container |
| Hosting | **Azure Container Apps** (serverless, scale-to-zero) + Azure Container Registry |
| Source control | **Public GitHub repo** |
| CI/CD | **Azure Pipelines** (build → test → security-scan → containerize → deploy); Azure Boards optional |
| IaC | **Terraform** (remote state in Azure Storage) |
| Optional 2nd client | **Java / Spring Boot (Thymeleaf)** read-only dashboard consuming the same API (stretch) |

## 9. DevSecOps / AppSec tooling to wire into the pipeline
*(The app is a vuln tracker, so it should visibly secure itself — "eats its own dog food.")*
- **SCA (dependency scanning):** scan the project's own NuGet/npm/Maven deps (e.g.
  `dotnet list package --vulnerable`, **Trivy**, or **OWASP Dependency-Check**).
- **SAST (static code analysis):** **CodeQL** and/or **Semgrep** on the C# (and Java) code.
- **Secret scanning:** **Gitleaks** / **TruffleHog** in the pipeline + pre-commit.
- **Container image scanning:** **Trivy** against the built Docker image (enabled by D4).
- **IaC scanning:** **Checkov** / **tfsec** against the Terraform.
- **(Optional) DAST:** **OWASP ZAP** baseline scan against the deployed demo.
- **Dogfooding loop:** these scans' SARIF/JSON output can be **fed into Ravelin itself**
  as a real data source — the tool tracking its own remediation SLAs.
- **Supporting practices:** threat model document (STRIDE), security headers, secrets in
  Azure Key Vault, dependency pinning, branch protection + required checks.

---

## 10. Build plan (staged, reviewable)

Each stage ends in something runnable/reviewable. Within each stage we'll split work into
small PR-sized chunks. **Deliberate sequencing:** the CI/CD + cloud deployment loop is
built EARLY (Stage 1) on a "walking skeleton" — a tiny app pushed through the entire
pipeline to Azure before features exist. This de-risks the hardest integration and means
every later feature ships through a working pipeline (best practice + great showcase).

- **Stage 0 — Foundations / walking skeleton.** GitHub repo, .NET solution structure
  (clean separation: API/domain/infrastructure + Blazor client), a trivial "it runs"
  endpoint + page, Dockerfile, runs locally in a container. *Outcome: app runs locally.*
- **Stage 1 — CI/CD + cloud loop.** Terraform provisions Container Apps + ACR + Azure SQL
  (serverless) + storage; Azure Pipeline builds → tests → containerizes → deploys the
  skeleton to Azure. *Outcome: live (empty) app on Azure, deployed by pipeline.*
- **Stage 2 — Domain & data model.** EF Core entities (Project, Scan, Finding, SlaPolicy,
  User/Role), migrations applied to Azure SQL. *Outcome: schema live, can persist data.*
- **Stage 3 — Ingestion + API keys + lifecycle.** Authenticated ingestion endpoint,
  normalized-finding mapping (Trivy/Dependabot JSON), scoped hashed API keys, smart dedup
  + auto-resolve. *Outcome: a pipeline/curl can push a scan; findings persist correctly.*
- **Stage 4 — Human auth + RBAC.** ASP.NET Core Identity + JWT, roles enforced, Blazor
  login. *Outcome: users log in; Admin/Analyst/Viewer boundaries work.*
- **Stage 5 — SLA engine + triage.** Severity-based SLA deadlines, breach computation,
  triage states (false-positive/accepted-risk). *Outcome: findings carry SLA status;
  analysts can triage.*
- **Stage 6 — Dashboards.** Blazor: posture-over-time, SLA-compliance %, breaches by
  project/severity. *Outcome: the visual showcase.*
- **Stage 7 — Compliance report export.** Point-in-time PDF / shareable report.
  *Outcome: tangible auditor-ready deliverable.*
- **Stage 8 — DevSecOps hardening + demo polish.** Wire SAST/SCA/secret/container/IaC
  scans into the pipeline; threat model (STRIDE); Key Vault; security headers; seed demo
  data + read-only demo account; dogfood scan output back into Ravelin.
  *Outcome: AppSec showcase complete; public demo polished.*
- **Stage 9 — (Optional/stretch) Java Spring Boot read-only client** + its own pipeline.
- **Stage 10 — (Later) Pull-based ingestion sources; alerting.**

### Prerequisites to set up (one-time)
Accounts: **Azure** (with free credit), **GitHub**, **Azure DevOps** org. Local tools:
**.NET SDK** (latest LTS), **Docker**, **Terraform**, **Azure CLI** (`az`), **GitHub CLI**
(`gh`), and (if doing Stage 9) a **JDK + Maven/Gradle**.

### Tools / connectors / skills that help
- **`ctx7` / find-docs** (already configured): pull current docs for .NET, ASP.NET Core,
  EF Core, Blazor, Azure Container Apps, Terraform azurerm, Azure Pipelines — use instead
  of relying on training data.
- **CLIs as the integration surface:** `az`, `gh`, `terraform`, `docker`, `dotnet`.
- **Optional MCP connectors (not yet configured):** a GitHub connector and/or an Azure
  connector could let the assistant manage repos/PRs/resources directly. To be evaluated
  if useful; CLIs cover most needs.
- **claude-code-guide agent:** for questions about Claude Code / pipelines automation.

---

## 7. Process agreement
1. ✅ Understand the product fully (done — this document).
2. ⏳ Walk through key technical decisions **one at a time**, plain language, flagging
   anything costly or hard to undo.
3. ⏳ Only then, a build plan in **small, reviewable stages** (not all at once).
4. Along the way, call out any tools/connectors/skills that would specifically help and
   how to connect them.
