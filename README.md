# AppSec Management Platform

Application Security Management Platform for centralized inventory, SBOM-based
vulnerability monitoring, severity policy, and reporting. See
[Requirement.md](Requirement.md) for the full BRD/FRS.

## Architecture

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic, PostgreSQL — modular
  monolith (`backend/app/modules/`: auth, inventory, ...).
- **Frontend**: Vite + React + TypeScript, react-i18next (English/Thai), React Query.
- **Database**: PostgreSQL (clustered/HA in production — see Requirement.md
  Section 11.1).
- **Vulnerability data source**: OWASP Dependency-Track (SBOM ingestion + findings).

## Local Development

Requires Docker and Docker Compose.

```bash
docker compose -f docker-compose.dev.yml up -d
```

Services:

| Service              | URL                              |
| -------------------- | --------------------------------- |
| Frontend             | http://localhost:5173            |
| Backend API          | http://localhost:8000/api/v1     |
| Backend health check | http://localhost:8000/health      |
| Dependency-Track UI  | http://localhost:8082             |
| Dependency-Track API | http://localhost:8081             |
| Adminer (DB browser) | http://localhost:8083             |

Seed default RBAC users (one per Requirement.md Section 4 role, password
`ChangeMe123!`) plus the Section 12 default Severity/SLA policy:

```bash
docker compose -f docker-compose.dev.yml exec backend python -m app.seed
```

Add `--demo` to also seed sample Applications, Components and Findings, so the
dashboard and backlog screens have data before SBOM ingestion (FR-2/FR-3) exists:

```bash
docker compose -f docker-compose.dev.yml exec backend python -m app.seed --demo
```

> After pulling changes that add a migration, run `alembic upgrade head` in the
> backend container — the dev stack only runs migrations when it starts, while
> `uvicorn --reload` picks up new code without restarting.

## Implemented so far

| Area | Requirement | Status |
| ---- | ----------- | ------ |
| Application Inventory | FR-1 | Applications + Versions, Dev Team scoped by OwnerTeam |
| SBOM Ingestion | FR-2 | Pluggable `SCAConnector` (Dependency-Track implementation), manual/COTS upload (CycloneDX + SPDX parser), ingestion history, staleness sweep, background scheduler |
| Vulnerability Monitoring | FR-3 | Pull-sync reconciliation: create/update/auto-close Findings against the SCA platform's current data, delta-matched without waiting for a rebuild |
| Severity & SLA Policy | FR-4, FR-5.1, FR-5.2, §12 | Versioned effective-dated policy; CVSS+EPSS+KEV rule engine; configurable SLA per tier |
| Finding Backlog | FR-3.3, FR-5.4, FR-10.2 | Shared backlog for SBOM/SAST/Pentest findings, filters, per-app breakdown, remediation plans |
| Go-Live Security Gate | FR-6.1, FR-6.3, FR-6.4 | Per-Version SBOM/SAST/Pentest checklist (server re-verified, never trusts the client), approval record trail. Break-glass (FR-6.7) and version diff/trend (FR-6.6/FR-10.8) are not built |
| Waiver / Exception workflow | FR-6.2 | Request → approve/reject → active/revoke, with an auto-expiry sweep that reopens the Finding |
| Pentest Project Management | FR-6.5 | Fixed lifecycle (Requested → ... → Closed, + Cancelled/On-hold), engagement/cost metadata, report file upload/download, retest-owner defaulting. Workflow states are fixed, not admin-configurable |
| ITSM / Ticketing Integration | FR-7 | Pluggable connector framework (Jira implemented; ServiceDesk Plus/generic webhook are configurable but not wired to a real API), routing policy by severity, manual ticket creation, retry-on-failure |
| VEX & Exception Management | FR-8.1, FR-8.2, FR-8.3 | Per-Finding VEX status (AppSec/Admin-only), Global Suppression across every Application sharing a CVE. Global Suppression has no dedicated frontend screen yet (API-only) |
| Dashboard | FR-10.1 | KPI tiles, severity breakdown, per-application risk grid |
| Pentest Reporting | FR-10.6, FR-10.7 | Org-wide Engagement Report (cost gated to AppSec/Admin/Management) and Project Board |
| Audit Trail | FR-11.1, FR-11.2 | Append-only log with before/after values, filters, CSV export |
| User & Integration Administration | Section 4 | User/Role management, Integration Connector configuration (Admin-only) |
| Accessibility | UXR-1, UXR-2, UXR-6, UXR-7 | Light/dark themes, icon+label severity chips, role-scoped navigation, error summaries |

Not yet built: License compliance policy (FR-9, though `Component.license` is
already captured from SBOM/SPDX), Application Version history/diff/trend
charts (FR-6.6, FR-10.8), Go-Live break-glass override (FR-6.7), manual Finding
intake UI (SAST/Pentest finding creation exists as an API only), SSO
(Section 7), Management KPI export to PDF/Excel (FR-10.3), Compliance/Audit
read-only export view beyond the existing Audit Trail CSV export (FR-10.4).

### SBOM ingestion notes (FR-2, FR-3)

- Per FR-2.7, automated CI/CD pushes go **directly to Dependency-Track**, never
  through this platform. `POST /api/v1/sbom/sync` (AppSec/Admin) pulls
  Components + already-matched Findings from there via `app/integrations/`
  (a pluggable `SCAConnector` interface — add a new SCA platform without
  touching the sync logic) and reconciles them into our own backlog through
  the Policy engine. It also runs on a schedule when `ENABLE_SCHEDULER=true`
  (`SBOM_SYNC_INTERVAL_HOURS`, default 6).
- `POST /api/v1/sbom/upload` is the COTS/Vendor manual path (FR-2.6): validates
  the file as CycloneDX or SPDX JSON, ingests Components directly, and
  best-effort forwards the raw file into Dependency-Track's own pipeline when
  `DEPENDENCY_TRACK_API_KEY` is configured.
- `POST /api/v1/sbom/stale-check` flags Application Versions that have gone
  past `STALE_SBOM_DAYS` (default 90) without a new SBOM (FR-2.4).
- The Dependency-Track pull-sync is tested against a `FakeConnector` test
  double, not a live instance — that is the point of the connector interface.
  The manual-upload path needs no external service and is tested end-to-end.

### Running the backend without Docker

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # then point DATABASE_URL at a local Postgres or SQLite
alembic upgrade head
uvicorn app.main:app --reload
```

Run tests/lint:

```bash
pytest
ruff check .
mypy app
```

### Running the frontend without Docker

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Lint/build:

```bash
npm run lint
npm run build
```

## Production Deployment

`docker-compose.prod.yml` builds and runs the deployable images (multi-stage
`backend/Dockerfile` and `frontend/Dockerfile`) instead of the dev images —
no bind-mounted source, no `--reload`, no Adminer. Dependency-Track is treated
as an already-running external service (point `DEPENDENCY_TRACK_BASE_URL` /
`DEPENDENCY_TRACK_API_KEY` at it); it is not bundled here.

1. Create a `.env` next to `docker-compose.prod.yml` with at least:

   ```bash
   POSTGRES_PASSWORD=<strong random password>
   SECRET_KEY=<long random string — JWT signing key>
   CORS_ALLOWED_ORIGINS=https://your-dashboard-hostname
   ```

   See `backend/.env.example` for every variable and its default (SBOM
   sync/stale-check/waiver-expiry intervals, the scheduler toggle, etc).
   `VITE_API_BASE_URL` and `FRONTEND_PORT` are also settable but default to
   `/api/v1` (relative — routed by the frontend's own nginx reverse proxy to
   the `backend` service, so the browser never needs to know the API's
   hostname) and `80` respectively.

2. Build and start:

   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```

   The backend image's entrypoint runs `alembic upgrade head` on every start
   before serving traffic — a fresh deployment or a version upgrade both just
   work. Both `backend` and `frontend` publish a Docker `HEALTHCHECK`
   (`/health`, reachable through the frontend too at `/health`, for a load
   balancer that only has a route to the frontend).

3. Seed the initial Admin/AppSec/etc. accounts and the default Severity/SLA
   policy (see Section 4 and Section 12 of Requirement.md):

   ```bash
   docker compose -f docker-compose.prod.yml exec backend python -m app.seed
   ```

   Change every seeded password immediately in a real deployment — `app.seed`
   is meant to bootstrap access, not to be the permanent credential set.

4. Pentest report uploads (FR-6.5.4) persist in the `pentest_reports` named
   volume across container replacement; back it up like any other stateful
   volume. `postgres_data` is the other one that matters.

Upgrading: pull/rebuild the new images and `docker compose -f
docker-compose.prod.yml up -d --build` again — the entrypoint's migration
step handles schema changes; nothing else needs a manual step.

## Repository Layout

```
backend/               FastAPI application, Alembic migrations, tests
  app/core/            config, DB session, security, RBAC deps, audit helper,
                       background scheduler
  app/models/          SQLAlchemy models (Section 8 entities)
  app/modules/         one package per bounded context (auth, inventory,
                       policy, findings, sbom, users, integrations, waivers,
                       golive, pentest, audit)
  app/integrations/    pluggable SCA/ITSM connector interfaces + implementations
  app/schemas/         Pydantic request/response models
frontend/              Vite + React + TypeScript application
  src/features/        one folder per feature (auth, dashboard, inventory,
                       findings, policy, sbom, settings, golive, pentest, audit)
  src/lib/             api client, i18n, theme, RBAC capabilities, icon set
  src/styles/          design tokens + application styles (UXR-1)
deploy/postgres-init/  DB init scripts for local Docker Compose (Dependency-Track DB)
docker-compose.dev.yml Local development stack (bind-mounted source, hot reload)
docker-compose.prod.yml Production stack (built images, no bind mounts)
Requirement.md         Authoritative BRD/FRS specification
```

## Key design decisions

- **Policy is data, not code.** Severity thresholds and SLA windows live in
  effective-dated `PolicySet` rows (FR-4.4, FR-5.1). Published versions are never
  edited, and every Finding records the `policy_version` that set its tier and due
  date, so a past decision stays reproducible (Section 7, Auditability).
- **One backlog for every scan type.** `Finding` is anchored on `AppVersion`, not
  on `Component`, so SAST and Pentest findings — which have no SBOM component —
  share the same backlog, SLA and dashboard as SBOM findings (FR-6.5.6).
- **Scoping fails closed.** Dev Team queries are filtered by `owner_team` in the
  service layer; a Dev Team user with no team assigned sees nothing rather than
  everything (Section 4). Frontend capability checks are usability only.
- **Colour is never the only signal.** Severity and SLA state always render an
  icon and a text label (UXR-2, WCAG 1.4.1).
