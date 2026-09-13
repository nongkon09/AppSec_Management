export type SeverityTier = 'critical' | 'high' | 'medium' | 'low'
export type FindingSource = 'sbom' | 'sast' | 'pentest'
export type FindingStatus = 'open' | 'fixed' | 'risk_accepted' | 'suppressed'
export type VexStatus = 'affected' | 'not_affected' | 'fixed' | 'under_investigation'
export type SlaStatusFilter = 'overdue' | 'within_sla'

export interface Finding {
  id: string
  app_version_id: string
  component_id: string | null
  pentest_project_id: string | null
  source: FindingSource
  cve_id: string | null
  title: string | null
  description: string | null
  cvss: number | null
  epss: number | null
  kev_flag: boolean
  severity_tier: SeverityTier
  status: FindingStatus
  vex_status: VexStatus
  vex_justification: string | null
  due_date: string | null
  policy_version: number | null
  fixed_version: string | null
  reference_url: string | null
  remediation_plan: string | null
  remediation_plan_updated_by: string | null
  remediation_plan_updated_at: string | null
  first_detected_at: string
  fixed_at: string | null

  /** Denormalised Application → Version → Component chain for the FR-10.5 drill-down. */
  application_id: string
  application_name: string
  owner_team: string
  version_label: string
  component_name: string | null
  component_version: string | null
  component_scope: string | null
  is_overdue: boolean
  days_until_due: number | null
}

export interface PaginatedFindings {
  items: Finding[]
  total: number
}

export interface FindingFilters {
  severity?: SeverityTier[]
  finding_status?: FindingStatus[]
  source?: FindingSource
  sla_status?: SlaStatusFilter
  application_id?: string
  search?: string
  skip?: number
  limit?: number
}

export interface SeverityBreakdown {
  severity_tier: SeverityTier
  within_sla: number
  overdue: number
  total: number
}

export interface ApplicationBacklog {
  application_id: string
  application_name: string
  owner_team: string
  critical: number
  high: number
  medium: number
  low: number
  overdue: number
  total: number
}

export interface BacklogSummary {
  total_open: number
  total_overdue: number
  sla_compliance_percent: number | null
  by_severity: SeverityBreakdown[]
  by_application: ApplicationBacklog[]
}

export type WaiverStatus = 'pending' | 'active' | 'rejected' | 'expired' | 'revoked'

export interface Waiver {
  id: string
  finding_id: string
  requested_by: string
  approved_by: string | null
  reason: string
  expiry_date: string
  status: WaiverStatus
  created_at: string
}

export interface WaiverCreateInput {
  reason: string
  expiry_date: string
}

export interface VexUpdateInput {
  vex_status: VexStatus
  vex_justification?: string | null
}
