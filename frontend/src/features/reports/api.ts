import { apiClient } from '../../lib/api'
import type { ExecutiveSummary } from './types'

/** `month` is YYYY-MM. */
export async function fetchExecutiveSummary(month: string): Promise<ExecutiveSummary> {
  const { data } = await apiClient.get<ExecutiveSummary>('/reports/executive-summary', { params: { month } })
  return data
}
