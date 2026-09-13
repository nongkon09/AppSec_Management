import { apiClient } from '../../lib/api'
import type { Application, AppVersion, PaginatedApplications } from './types'

export async function listApplications(skip = 0, limit = 50): Promise<PaginatedApplications> {
  const { data } = await apiClient.get<PaginatedApplications>('/applications', {
    params: { skip, limit },
  })
  return data
}

export async function getApplication(applicationId: string): Promise<Application> {
  const { data } = await apiClient.get<Application>(`/applications/${applicationId}`)
  return data
}

export async function listAppVersions(applicationId: string): Promise<AppVersion[]> {
  const { data } = await apiClient.get<AppVersion[]>(`/applications/${applicationId}/versions`)
  return data
}
