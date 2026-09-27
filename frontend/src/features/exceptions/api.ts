import { apiClient } from '../../lib/api'
import type {
  BypassTool,
  ExceptionCreateInput,
  ExceptionListFilters,
  PaginatedExceptions,
  RiskException,
} from './types'

export async function listExceptions(filters: ExceptionListFilters = {}): Promise<PaginatedExceptions> {
  const { data } = await apiClient.get<PaginatedExceptions>('/exceptions', {
    params: filters,
    paramsSerializer: { indexes: null },
  })
  return data
}

export async function fetchException(id: string): Promise<RiskException> {
  const { data } = await apiClient.get<RiskException>(`/exceptions/${id}`)
  return data
}

export async function fetchExceptionByReference(reference: string): Promise<RiskException> {
  const { data } = await apiClient.get<RiskException>(
    `/exceptions/by-reference/${encodeURIComponent(reference.trim())}`,
  )
  return data
}

export async function submitException(payload: ExceptionCreateInput): Promise<RiskException> {
  const { data } = await apiClient.post<RiskException>('/exceptions', payload)
  return data
}

export async function decideException(
  id: string,
  action: 'approve' | 'reject',
  comment: string | null,
): Promise<RiskException> {
  const { data } = await apiClient.post<RiskException>(`/exceptions/${id}/${action}`, { comment })
  return data
}

export async function endException(
  id: string,
  action: 'withdraw' | 'revoke',
  reason: string,
): Promise<RiskException> {
  const { data } = await apiClient.post<RiskException>(`/exceptions/${id}/${action}`, { reason })
  return data
}

export async function recordBypass(
  id: string,
  payload: { tool: BypassTool; reference_url: string | null; note: string | null },
): Promise<RiskException> {
  const { data } = await apiClient.post<RiskException>(`/exceptions/${id}/bypasses`, payload)
  return data
}
