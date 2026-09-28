import type { ApprovalLevel, AuthSource, Role } from '../auth/types'

export interface PlatformUser {
  id: string
  username: string
  email: string
  full_name: string
  /** null: an Entra ID account that no role mapping matches yet (cannot sign in). */
  role: Role | null
  owner_team: string | null
  is_active: boolean
  approval_level: ApprovalLevel
  auth_source: AuthSource
  last_login_at: string | null
  created_at: string
}

export interface PaginatedUsers {
  items: PlatformUser[]
  total: number
}

export interface UserCreateInput {
  username: string
  email: string
  full_name: string
  role: Role
  owner_team: string | null
  password: string
  approval_level: ApprovalLevel
}

export interface UserUpdateInput {
  full_name?: string
  email?: string
  role?: Role
  owner_team?: string | null
  is_active?: boolean
  approval_level?: ApprovalLevel
}
