import type { SeverityTier } from '../findings/types'

export interface SeverityRuleCondition {
  kev?: boolean | null
  cvss_min?: number | null
  cvss_max?: number | null
  epss_min?: number | null
  epss_max?: number | null
}

export interface SeverityRule {
  name: string
  when: SeverityRuleCondition
  tier: SeverityTier
}

export interface SlaDays {
  critical: number | null
  high: number | null
  medium: number | null
  low: number | null
}

export interface PolicySet {
  id: string
  version: number
  effective_from: string
  created_by: string
  notes: string | null
  severity_rules: SeverityRule[]
  sla_days: SlaDays
  downgrade_dev_scope_findings: boolean
  auto_ticket_dev_scope_findings: boolean
}

export interface PolicySetCreate {
  effective_from: string
  severity_rules: SeverityRule[]
  sla_days: SlaDays
  downgrade_dev_scope_findings: boolean
  auto_ticket_dev_scope_findings: boolean
  notes?: string | null
}

export interface SeverityEvaluationRequest {
  cvss?: number | null
  epss?: number | null
  kev_flag: boolean
  scope: string
  policy_version?: number | null
}

export interface SeverityEvaluationResult {
  severity_tier: SeverityTier
  matched_rule: string
  downgraded_for_dev_scope: boolean
  policy_version: number
  sla_days: number | null
  due_date: string | null
}
