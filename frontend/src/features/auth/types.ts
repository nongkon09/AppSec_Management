export type Role = 'appsec' | 'dev_team' | 'legal' | 'management' | 'audit' | 'admin'

export interface CurrentUser {
  id: string
  username: string
  email: string
  full_name: string
  role: Role
  owner_team: string | null
}

export interface LoginResponse {
  access_token: string
  token_type: string
}
