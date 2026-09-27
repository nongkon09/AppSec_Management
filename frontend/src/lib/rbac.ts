/**
 * Client-side capability map (Requirement.md Section 4, UXR-6).
 *
 * UXR-6 requires that screens a user has no rights to are not shown at all, rather than
 * shown and then blocked on click. This map drives navigation and action visibility.
 *
 * It is a usability aid, never a security control: the backend enforces the same rules in
 * `require_roles` and in the data-scoping queries, and is the only thing standing between
 * a user and data they may not see.
 */
import type { Role } from '../features/auth/types'

export type Capability =
  | 'viewDashboard'
  | 'viewInventory'
  | 'manageInventory'
  | 'viewFindings'
  | 'editRemediationPlan'
  | 'createFinding'
  | 'viewPolicy'
  | 'managePolicy'
  | 'viewAuditTrail'
  | 'manageSbomIngestion'
  | 'manageUsers'
  | 'manageIntegrations'
  | 'createTicket'
  | 'viewExceptions'
  | 'requestException'
  | 'decideException'
  | 'revokeException'
  | 'recordBypass'
  | 'viewControls'
  | 'manageControls'
  | 'recordDeployment'
  | 'exportEvidence'
  | 'viewGoLiveGate'
  | 'approveGoLive'
  | 'viewPentestProjects'
  | 'managePentestProjects'
  | 'viewPentestCostReport'

const CAPABILITIES: Record<Capability, readonly Role[]> = {
  viewDashboard: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  viewInventory: ['appsec', 'dev_team', 'management', 'audit', 'admin', 'legal'],
  manageInventory: ['appsec', 'admin'],
  viewFindings: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  // FR-10.2: the owning Dev Team maintains the plan; AppSec may correct it.
  editRemediationPlan: ['appsec', 'admin', 'dev_team'],
  // FR-6.5.5: manual Pentest/SAST Finding intake is an AppSec responsibility.
  createFinding: ['appsec', 'admin'],
  viewPolicy: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  managePolicy: ['appsec', 'admin'],
  viewAuditTrail: ['appsec', 'audit', 'admin'],
  // FR-2.6: COTS/Vendor manual SBOM intake and Dependency-Track sync triggers are an
  // AppSec/DevOps operation (Section 3 RACI); DevOps has no distinct role in this
  // platform's RBAC model, so Admin covers that side.
  manageSbomIngestion: ['appsec', 'admin'],
  // Section 4: "System Admin | จัดการ User/Role ..." — distinct from AppSec's
  // Policy/Waiver ownership, so this is Admin-only, not shared with AppSec.
  manageUsers: ['admin'],
  // Section 4: Integration Connector Configuration (create/edit/delete, which includes
  // the stored credential) is Admin-only — mirrors the backend's `_INTEGRATION_ADMIN`.
  manageIntegrations: ['admin'],
  // FR-7.8: AppSec creates a ticket manually from a Finding — mirrors the backend's
  // `require_roles(Role.APPSEC, Role.ADMIN)` on `POST /findings/{id}/tickets`.
  createTicket: ['appsec', 'admin'],
  // docs/risk-exception-design.md 3.5: Makers are Dev Team and AppSec; Checkers are AppSec
  // and Management with an approval level. Admin never judges risk. The server also checks
  // level, self-approval and double-approval; `can_approve` on each request is authoritative.
  viewExceptions: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  requestException: ['dev_team', 'appsec'],
  decideException: ['appsec', 'management'],
  revokeException: ['appsec'],
  recordBypass: ['dev_team', 'appsec', 'admin'],
  viewControls: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  manageControls: ['appsec'],
  recordDeployment: ['dev_team', 'appsec', 'admin'],
  exportEvidence: ['appsec', 'audit', 'management', 'admin', 'dev_team'],
  viewGoLiveGate: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  approveGoLive: ['appsec', 'admin'],
  viewPentestProjects: ['appsec', 'dev_team', 'management', 'audit', 'admin'],
  managePentestProjects: ['appsec', 'admin'],
  // FR-6.5.9/FR-10.6: cost figures restricted to AppSec Manager/Management.
  viewPentestCostReport: ['appsec', 'admin', 'management'],
}

export function can(role: Role | undefined, capability: Capability): boolean {
  if (!role) {
    return false
  }
  return CAPABILITIES[capability].includes(role)
}

/** True for roles whose data is narrowed to their own OwnerTeam (UXR-6 scope badge). */
export function isScopedToOwnTeam(role: Role | undefined): boolean {
  return role === 'dev_team'
}
