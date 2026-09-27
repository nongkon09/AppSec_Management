export type Role = 'appsec' | 'dev_team' | 'legal' | 'management' | 'audit' | 'admin' | 'pipeline'

/** Who may act as Checker on a risk decision (docs/risk-exception-design.md 3.5). */
export type ApprovalLevel = 'none' | 'l1' | 'l2' | 'l3'

export interface CurrentUser {
  id: string
  username: string
  email: string
  full_name: string
  role: Role
  owner_team: string | null
  approval_level: ApprovalLevel
}

export interface LoginResponse {
  access_token: string
  token_type: string
}
