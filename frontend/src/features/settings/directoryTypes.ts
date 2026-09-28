import type { ApprovalLevel, Role } from '../auth/types'

export type MappingKind = 'app_role' | 'group'

export interface DirectoryStatus {
  sso_enabled: boolean
  scim_enabled: boolean
  local_login_enabled: boolean
  jit_provisioning: boolean
  tenant_id: string | null
  client_id: string | null
  redirect_uri: string
  scim_url: string
}

export interface RoleMapping {
  id: string
  kind: MappingKind
  value: string
  role: Role
  approval_level: ApprovalLevel
  owner_team: string | null
  group_name: string | null
}

export interface RoleMappingInput {
  kind: MappingKind
  value: string
  role: Role
  approval_level: ApprovalLevel
  owner_team: string | null
}

export interface RoleMappingSaved {
  mapping: RoleMapping | null
  users_changed: number
}

export interface DirectoryGroup {
  id: string
  external_id: string
  display_name: string | null
  member_count: number
}

export interface DirectoryAccount {
  app_roles: string[]
  groups: DirectoryGroup[]
  matched: string[]
}
