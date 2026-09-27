import type { ApprovalLevel } from '../auth/types'
import type { SeverityTier } from '../findings/types'
import type { ControlEffectiveness } from '../controls/types'

export type ExceptionType = 'risk_acceptance' | 'false_positive' | 'not_affected'
export type ExceptionStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'withdrawn'
  | 'expired'
  | 'revoked'
  | 'closed'
export type VexJustification =
  | 'code_not_present'
  | 'code_not_reachable'
  | 'requires_configuration'
  | 'requires_dependency'
  | 'requires_environment'
  | 'protected_by_compiler'
  | 'protected_at_runtime'
  | 'protected_at_perimeter'
  | 'protected_by_mitigating_control'
export type BypassTool = 'rhacs' | 'harbor' | 'trivy' | 'inspector' | 'sast' | 'other'

export const EXCEPTION_TYPES: ExceptionType[] = ['risk_acceptance', 'false_positive', 'not_affected']
export const VEX_JUSTIFICATIONS: VexJustification[] = [
  'code_not_present',
  'code_not_reachable',
  'requires_configuration',
  'requires_dependency',
  'requires_environment',
  'protected_by_compiler',
  'protected_at_runtime',
  'protected_at_perimeter',
  'protected_by_mitigating_control',
]
export const BYPASS_TOOLS: BypassTool[] = ['rhacs', 'harbor', 'trivy', 'inspector', 'sast', 'other']

export interface ExceptionItem {
  application_id: string
  application_name: string
  issue_key: string
  label: string
  origin_finding_id: string | null
}

export interface ExceptionApproval {
  approver: string
  approver_level: ApprovalLevel
  decision: 'approve' | 'reject'
  comment: string | null
  decided_at: string
}

export interface ExceptionBypass {
  tool: string
  reference_url: string | null
  note: string | null
  recorded_by: string
  bypassed_at: string
}

export interface ExceptionControl {
  id: string
  name: string
  effectiveness: ControlEffectiveness
  review_due_on: string
  is_active: boolean
}

export interface RiskException {
  id: string
  reference: string
  exception_type: ExceptionType
  status: ExceptionStatus
  requested_by: string
  created_at: string
  reason: string
  evidence: string | null
  compensating_measures: string | null
  vex_justification: VexJustification | null
  original_severity_tier: SeverityTier
  kev_involved: boolean
  residual_severity_tier: SeverityTier | null
  expires_on: string
  required_approvals: number
  required_min_level: ApprovalLevel
  required_top_level: ApprovalLevel
  decided_at: string | null
  ended_by: string | null
  ended_reason: string | null
  is_legacy: boolean
  needs_review: boolean
  items: ExceptionItem[]
  approvals: ExceptionApproval[]
  bypasses: ExceptionBypass[]
  controls: ExceptionControl[]
  can_approve: boolean
  approve_refusal: string | null
}

export interface PaginatedExceptions {
  items: RiskException[]
  total: number
}

export interface ExceptionCreateInput {
  exception_type: ExceptionType
  finding_ids: string[]
  reason: string
  evidence: string | null
  compensating_measures: string | null
  control_ids: string[]
  residual_severity_tier: SeverityTier | null
  vex_justification: VexJustification | null
  expires_on: string
}

export interface ExceptionListFilters {
  status?: ExceptionStatus[]
  awaiting_me?: boolean
  mine?: boolean
  application_id?: string
  finding_id?: string
  skip?: number
  limit?: number
}
