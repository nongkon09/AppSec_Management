# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/); this project is pre-1.0, so minor
versions may still include breaking changes.

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
