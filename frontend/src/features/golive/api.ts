import { apiClient } from '../../lib/api'
import type { GoLiveApproval, GoLiveChecklist } from './types'

export async function getGoLiveChecklist(appVersionId: string): Promise<GoLiveChecklist> {
  const { data } = await apiClient.get<GoLiveChecklist>(
    `/app-versions/${appVersionId}/go-live-checklist`,
  )
  return data
}

export async function approveGoLive(appVersionId: string): Promise<GoLiveApproval> {
  const { data } = await apiClient.post<GoLiveApproval>(
    `/app-versions/${appVersionId}/go-live-approve`,
  )
  return data
}

export async function getGoLiveHistory(appVersionId: string): Promise<GoLiveApproval[]> {
  const { data } = await apiClient.get<GoLiveApproval[]>(
    `/app-versions/${appVersionId}/go-live-history`,
  )
  return data
}
