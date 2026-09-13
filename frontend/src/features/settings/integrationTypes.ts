import type { SeverityTier } from '../findings/types'

export type ConnectorType = 'jira' | 'service_desk_plus' | 'generic_webhook'

export interface IntegrationConnector {
  id: string
  name: string
  connector_type: ConnectorType
  base_url: string
  config: Record<string, unknown>
  routing_severities: SeverityTier[]
  is_enabled: boolean
  created_at: string
  auth_token_configured: boolean
}

export interface ConnectorCreateInput {
  name: string
  connector_type: ConnectorType
  base_url: string
  auth_token: string
  config: Record<string, unknown>
  routing_severities: SeverityTier[]
  is_enabled: boolean
}

export interface ConnectorUpdateInput {
  name?: string
  base_url?: string
  auth_token?: string
  config?: Record<string, unknown>
  routing_severities?: SeverityTier[]
  is_enabled?: boolean
}

export interface Ticket {
  id: string
  finding_id: string
  connector_id: string | null
  external_system: string
  external_id: string
  status: string
  last_error: string | null
  last_synced_at: string | null
  retry_count: number
  created_at: string
}
