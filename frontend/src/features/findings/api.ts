import { apiClient } from '../../lib/api'
import type { Ticket } from '../settings/integrationTypes'
import type {
  BacklogSummary,
  Finding,
  FindingFilters,
  PaginatedFindings,
  RemediationAction,
} from './types'

export async function listFindings(filters: FindingFilters = {}): Promise<PaginatedFindings> {
  const { data } = await apiClient.get<PaginatedFindings>('/findings', {
    params: filters,
    // Repeat multi-value filters as ?severity=critical&severity=high, which is what
    // FastAPI's Query(list) expects.
    paramsSerializer: { indexes: null },
  })
  return data
}

export async function fetchBacklogSummary(applicationId?: string): Promise<BacklogSummary> {
  const { data } = await apiClient.get<BacklogSummary>('/findings/summary', {
    params: applicationId ? { application_id: applicationId } : undefined,
  })
  return data
}

export async function fetchFinding(findingId: string): Promise<Finding> {
  const { data } = await apiClient.get<Finding>(`/findings/${findingId}`)
  return data
}

export interface RemediationPlanInput {
  remediation_plan: string | null
  remediation_action: RemediationAction | null
  remediation_target_date: string | null
}

export async function updateRemediationPlan(findingId: string, plan: RemediationPlanInput): Promise<Finding> {
  const { data } = await apiClient.patch<Finding>(`/findings/${findingId}`, plan)
  return data
}

export async function listFindingTickets(findingId: string): Promise<Ticket[]> {
  const { data } = await apiClient.get<Ticket[]>(`/findings/${findingId}/tickets`)
  return data
}

export async function createFindingTicket(findingId: string, connectorId: string): Promise<Ticket> {
  const { data } = await apiClient.post<Ticket>(`/findings/${findingId}/tickets`, {
    connector_id: connectorId,
  })
  return data
}
