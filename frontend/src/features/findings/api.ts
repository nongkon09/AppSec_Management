import { apiClient } from '../../lib/api'
import type { Ticket } from '../settings/integrationTypes'
import type {
  BacklogSummary,
  Finding,
  FindingFilters,
  PaginatedFindings,
  VexUpdateInput,
  Waiver,
  WaiverCreateInput,
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

export async function updateRemediationPlan(
  findingId: string,
  remediationPlan: string,
): Promise<Finding> {
  const { data } = await apiClient.patch<Finding>(`/findings/${findingId}`, {
    remediation_plan: remediationPlan,
  })
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

export async function updateVexStatus(findingId: string, payload: VexUpdateInput): Promise<Finding> {
  const { data } = await apiClient.patch<Finding>(`/findings/${findingId}/vex`, payload)
  return data
}

export async function listWaivers(findingId: string): Promise<Waiver[]> {
  const { data } = await apiClient.get<Waiver[]>(`/findings/${findingId}/waivers`)
  return data
}

export async function requestWaiver(findingId: string, payload: WaiverCreateInput): Promise<Waiver> {
  const { data } = await apiClient.post<Waiver>(`/findings/${findingId}/waivers`, payload)
  return data
}

export async function approveWaiver(waiverId: string): Promise<Waiver> {
  const { data } = await apiClient.post<Waiver>(`/waivers/${waiverId}/approve`)
  return data
}

export async function rejectWaiver(waiverId: string): Promise<Waiver> {
  const { data } = await apiClient.post<Waiver>(`/waivers/${waiverId}/reject`)
  return data
}

export async function revokeWaiver(waiverId: string): Promise<Waiver> {
  const { data } = await apiClient.post<Waiver>(`/waivers/${waiverId}/revoke`)
  return data
}
