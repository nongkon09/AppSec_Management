import { apiClient } from '../../lib/api'

export interface AuditLogEntry {
  id: string
  action: string
  actor: string
  entity_type: string
  entity_id: string
  before_value: Record<string, unknown> | null
  after_value: Record<string, unknown> | null
  timestamp: string
}

export interface PaginatedAuditLogs {
  items: AuditLogEntry[]
  total: number
}

export interface AuditFilters {
  entity_type?: string
  entity_id?: string
  actor?: string
  action?: string
  date_from?: string
  date_to?: string
  skip?: number
  limit?: number
}

export async function listAuditLogs(filters: AuditFilters = {}): Promise<PaginatedAuditLogs> {
  const { data } = await apiClient.get<PaginatedAuditLogs>('/audit-logs', { params: filters })
  return data
}

/**
 * Downloads the CSV export (FR-11.2).
 *
 * Fetched through the API client rather than a plain link so the Authorization header is
 * attached; the response is turned into a temporary object URL to trigger the save.
 */
export async function downloadAuditExport(filters: AuditFilters = {}): Promise<void> {
  const response = await apiClient.get('/audit-logs/export', {
    params: filters,
    responseType: 'blob',
  })
  const url = URL.createObjectURL(response.data as Blob)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(link)
    link.click()
    link.remove()
  } finally {
    URL.revokeObjectURL(url)
  }
}
