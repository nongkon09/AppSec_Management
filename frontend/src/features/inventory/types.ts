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
  /** Has an open deployment (or is the latest ingested one of a never-deployed app); only
   * active versions count toward the backlog. */
  is_active: boolean
  last_ingested_at: string | null
  is_stale: boolean
}

export interface Deployment {
  id: string
  application_id: string
  application_name: string
  app_version_id: string
  version_label: string
  environment: Environment
  deployed_at: string
  ended_at: string | null
  image_digest: string | null
  reference_url: string | null
  source: 'pipeline' | 'manual'
  recorded_by: string
}

export interface DeploymentInput {
  application_id: string
  version_label: string
  environment: Environment
  image_digest: string | null
  reference_url: string | null
}
