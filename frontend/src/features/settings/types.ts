import type { Role } from '../auth/types'

export interface PlatformUser {
  id: string
  username: string
  email: string
  full_name: string
  role: Role
  owner_team: string | null
  is_active: boolean
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
}

export interface UserUpdateInput {
  full_name?: string
  email?: string
  role?: Role
  owner_team?: string | null
  is_active?: boolean
}
