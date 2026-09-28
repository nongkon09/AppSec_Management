export type Role = 'appsec' | 'dev_team' | 'legal' | 'management' | 'audit' | 'admin' | 'pipeline'

/** Who may act as Checker on a risk decision (docs/risk-exception-design.md 3.5). */
export type ApprovalLevel = 'none' | 'l1' | 'l2' | 'l3'

/** Where the account is managed: here, or in Microsoft Entra ID (docs/entra-id.md). */
export type AuthSource = 'local' | 'entra'

export interface CurrentUser {
  id: string
  username: string
  email: string
  full_name: string
  role: Role
  owner_team: string | null
  approval_level: ApprovalLevel
  auth_source: AuthSource
}

/** What the login page offers; public. */
export interface SsoConfig {
  enabled: boolean
  local_login_enabled: boolean
}

export interface LoginResponse {
  access_token: string
  token_type: string
}
