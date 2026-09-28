import type { SeverityTier } from '../findings/types'

export interface MonthFigures {
  month: string
  open_at_end: number
  overdue_at_end: number
  new: number
  fixed: number
  fixed_on_time: number
  on_time_percent: number | null
  median_days_to_fix: number | null
}

export interface SeveritySummary {
  severity_tier: SeverityTier
  open_at_end: number
  overdue_at_end: number
  new: number
  fixed: number
  median_days_to_fix: number | null
}

export interface RiskItem {
  finding_id: string
  label: string
  application_name: string
  owner_team: string
  severity_tier: SeverityTier
  kev: boolean
  due_date: string | null
  days_overdue: number
  plan_target_date: string | null
}

export interface ApplicationSummary {
  application_id: string
  application_name: string
  owner_team: string
  open_at_end: number
  critical: number
  high: number
  overdue_at_end: number
}

export interface ExceptionFigures {
  approved_in_month: number
  active_at_end: number
  pending_now: number
  expiring_next_30_days: number
}

export interface ExecutiveSummary {
  period_start: string
  period_end: string
  as_of: string
  is_partial: boolean
  generated_at: string
  generated_by: string
  scope_team: string | null
  current: MonthFigures
  previous: MonthFigures
  trend: MonthFigures[]
  by_severity: SeveritySummary[]
  kev_open_at_end: number
  top_risks: RiskItem[]
  applications: ApplicationSummary[]
  exceptions: ExceptionFigures
  stale_sbom_versions: number
}
