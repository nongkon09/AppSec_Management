export type AppType = 'in_house' | 'cots' | 'mobile' | 'api'
export type Criticality = 'critical' | 'high' | 'medium' | 'low'
export type Environment = 'production' | 'staging' | 'dev'

export interface Application {
  id: string
  app_name: string
  app_type: AppType
  owner_team: string
  tech_lead_contact: string | null
  business_unit: string | null
  criticality: Criticality
  environment: Environment
  internet_facing: boolean
  data_classification: string | null
  repo_url: string | null
  ownership_confirmed: boolean
}

export interface PaginatedApplications {
  items: Application[]
  total: number
}

export interface AppVersion {
  id: string
  application_id: string
  version_label: string
  commit_sha: string | null
  environment: Environment
  is_current_production: boolean
  last_ingested_at: string | null
  is_stale: boolean
}
