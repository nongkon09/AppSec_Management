# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/); this project is pre-1.0, so minor
versions may still include breaking changes.

## [Unreleased]

### Added

- **Microsoft Entra ID**: sign in with Microsoft (OIDC authorization code flow
  with PKCE; the backend verifies the ID token against the tenant keys, audience,
  issuer, tenant, state and nonce), SCIM 2.0 provisioning of users and groups,
  and role mappings that turn an Entra app role or group into a platform role,
  approval level and owner team (Settings › Entra ID). Entra accounts have no
  local password and cannot be edited locally except the on/off switch; SCIM
  never sees local accounts. `LOCAL_LOGIN_ENABLED=false` leaves passwords to the
  System Admin (break-glass) and the CI/CD account. Setup guide:
  `docs/entra-id.md`. New settings: `APP_PUBLIC_URL`, `API_PUBLIC_URL`,
  `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`,
  `ENTRA_JIT_PROVISIONING`, `SCIM_BEARER_TOKEN`, `LOCAL_LOGIN_ENABLED`.
- Migration `f3a9c1d7e2b4`: `users.role` and `users.hashed_password` become
  nullable; new tables `directory_groups`, `directory_group_members`,
  `role_mappings`.

### Changed

- A risk acceptance on a vulnerability that is already past its SLA may run
  for one SLA period of the residual severity from today (previously none could
  be raised). The remediation plan of an overdue finding says an exception is
  required.
- New dependency: `cryptography` (via `pyjwt[crypto]`), pinned in
  `backend/constraints.txt`; rebuild images.

### Fixed

- Maven purls written as `group:artifact` and `group/artifact` now give the same
  issue key, so the SLA start date carries over between versions.

## [0.3.0]

### Added

- **Dependency-Track integration** (4.14): pull-sync of projects, components and
  findings; GHSA→CVE aliasing via OSV.dev; CISA KEV and FIRST EPSS enrichment;
  CVSS vector scoring; separate read-only sync key and SBOM upload key.
- **Risk Exception register with Maker–Checker** (replaces Waiver and direct VEX
  edits): risk acceptance, false positive and not affected; reference numbers
  (`EXC-YYYY-NNNN`); approval matrix by severity/KEV/scope with approver levels
  L1–L3; separation of duties (no self-approval, one vote per person, admin never
  decides); residual severity backed by a Control Library; expiry bounded by the
  SLA; upstream-tool bypass records; daily sweep (expire, close, flag for review).
  Existing waivers migrate as `legacy` exceptions. See
  `docs/risk-exception-design.md` and `docs/workflows.md`.
- **SLA per issue, not per version**: findings carry an `issue_key`
  (purl-based) and `sla_started_on` inherited from the first detection in the
  application, so a new release no longer restarts the clock.
- **Deployments and audit evidence**: which version runs where (recorded by a
  `pipeline` service role or by hand); backlog counts running versions only;
  scan snapshots with the exported SBOM stored by SHA-256 and DT project tags
  (commit, image digest, tool, pipeline run); Evidence Pack export per period.
- **Production pack** `deploy/production/`: one Compose stack with the platform
  and Dependency-Track (separate DB logins), `install.sh` (generates secrets,
  configures DT), `backup.sh`, offline image bundle, and the Thai deployment
  guide `docs/deployment-guide.md`. Clean installs create a single admin via
  `python -m app.bootstrap` instead of the demo accounts.
- Frontend: Exceptions list/detail, request form on findings, Control Library,
  deployments and evidence export on applications, approval level on users.

### Changed

- Background jobs run in a dedicated `worker` container (`python -m
  app.worker`). Previously `ENABLE_SCHEDULER` inside a 4-worker API ran every
  sync and sweep four times per interval.
- The Go-Live Gate is shown as reference only: upstream scanners are the gate.
- `docker-compose.prod.yml` is replaced by `deploy/production/docker-compose.yml`.

### Fixed

- `GET /auth/me` omitted `approval_level`, so the UI could not tell checkers
  apart.
- Fresh production builds could pick up untested dependency releases: a clean
  install resolved SQLAlchemy 2.1, under which migration `ed804b338ac7` fails
  (`type "finding_source" already exists`). Images, the dev image and CI now
  install with `backend/constraints.txt`, the exact versions the tests passed
  against; `sqlalchemy` is also capped below 2.1.

## [0.2.1]

### Added

- Production deployment package: multi-stage `backend/Dockerfile` (Python
  builder → slim runtime, non-root user, `alembic upgrade head` on every
  start via `docker-entrypoint.sh`) and `frontend/Dockerfile` (Node build →
  nginx runtime, SPA fallback, gzip, reverse proxy to the backend so the
  browser never needs the API's hostname), `docker-compose.prod.yml`, and a
  "Production Deployment" section in README.md. Verified end-to-end (build,
  migrate, seed, serve, API proxy, auth) against a throwaway stack before
  being committed.
- Version control: this project's git history starts here (see
  `git log` — no prior history existed). Tagged `v0.2.0` / `v0.2.1`.

### Fixed

- `CORS_ALLOWED_ORIGINS` could never actually be overridden via environment
  variable — pydantic-settings tries to JSON-decode a `list[str]` field's env
  value *before* the custom comma-splitting validator runs, so setting the
  variable to anything (e.g. the exact value `docker-compose.dev.yml` sets)
  crashed the app at startup with `SettingsError`. This went unnoticed all
  session because the one long-lived dev container that appeared to work
  pre-dated the variable being added to Compose, so it was only ever running
  on the Python-literal default, never actually exercising the env-var path.
  Fixed with pydantic-settings' `NoDecode` annotation. Found while smoke-
  testing the new production Docker image against a real environment
  variable for the first time.

## [0.2.0]

### Added

- **Go-Live Security Gate** (FR-6.1, FR-6.3, FR-6.4): per-Application-Version
  checklist (SBOM/SAST/Pentest, re-verified server-side on approval) and an
  approval record trail. Break-glass override (FR-6.7) is not included.
- **Waiver / Exception workflow** (FR-6.2): request → approve/reject →
  active/revoke, plus a scheduled (and manually-triggerable) auto-expiry sweep
  that reopens the covered Finding.
- **Pentest Project Management** (FR-6.5): fixed lifecycle (Requested →
  Scoping → Testing In Progress → Report Draft → Report Final →
  Remediation Verification → Closed, plus Cancelled/On-hold), engagement type
  and cost metadata (cost visibility restricted to AppSec/Admin/Management),
  report file upload/download, and retest-owner defaulting by engagement type.
  A Pentest Finding may only be attached once its Project reaches Report
  Final, per FR-6.5.6.
- **VEX & Global Suppression** (FR-8.1, FR-8.2, FR-8.3): AppSec/Admin-only VEX
  status per Finding, plus a Global Suppression action applied to every open
  Finding sharing a CVE across all Applications (API only, no dedicated
  frontend screen yet).
- **Pentest reporting** (FR-10.6, FR-10.7): org-wide Engagement Report
  (internal/vendor split, vendor frequency, cost by year, average duration,
  fixed/open Finding counts) and a Project Board across all Applications.
- **ITSM / Ticketing Integration** (FR-7): pluggable connector framework
  (Jira implemented; ServiceDesk Plus and a generic webhook are configurable
  but have no working implementation yet), severity-based routing policy,
  manual ticket creation, retry-on-failure.
- **Integration Settings & User Management** admin screens (Section 4).
- A production deployment package: multi-stage Dockerfiles for backend and
  frontend, `docker-compose.prod.yml`, and deployment instructions (see
  README's "Production Deployment" section).

### Fixed

- Test suite dates compared against the local system clock instead of the
  service layer's UTC "today," causing spurious failures for part of every
  day outside UTC.
- `PentestProject.start_date`/`end_date`/`cost` (and related date columns)
  were typed with SQLAlchemy's column-type classes instead of the
  corresponding Python types, which `mypy` could not catch until the fields
  were actually used in date/decimal arithmetic.
- `SlaBadge` showed a confusing negative "Due in −N days" for a Finding whose
  due date had passed but which was no longer actually overdue (e.g. resolved
  by an approved Waiver or a VEX suppression).
- `.page-head`/`.card`/`.card-pad` CSS classes were referenced by several
  pages but never defined in the stylesheet.

## [0.1.0]

Initial functional core: Application Inventory (FR-1), SBOM ingestion (FR-2)
via a pluggable SCA connector (Dependency-Track), continuous vulnerability
reconciliation (FR-3), the CVSS+EPSS+KEV severity/SLA policy engine (FR-4,
FR-5), the shared SBOM/SAST/Pentest Finding backlog (FR-5.4, FR-10.2), the
Security Team dashboard (FR-10.1), and the append-only Audit Trail (FR-11).
