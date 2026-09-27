import { apiClient } from '../../lib/api'
import type { Application, AppVersion, Deployment, DeploymentInput, PaginatedApplications } from './types'

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

export async function listDeployments(applicationId: string): Promise<Deployment[]> {
  const { data } = await apiClient.get<Deployment[]>(`/applications/${applicationId}/deployments`)
  return data
}

export async function recordDeployment(payload: DeploymentInput): Promise<Deployment> {
  const { data } = await apiClient.post<Deployment>('/deployments', payload)
  return data
}

export async function endDeployment(deploymentId: string): Promise<Deployment> {
  const { data } = await apiClient.post<Deployment>(`/deployments/${deploymentId}/end`)
  return data
}

/** Evidence Pack (docs/workflows.md W7) saved as a JSON file for the audit request. */
export async function downloadEvidence(
  applicationId: string,
  appName: string,
  dateFrom: string,
  dateTo: string,
): Promise<void> {
  const { data } = await apiClient.get<Blob>(`/applications/${applicationId}/evidence`, {
    params: { date_from: dateFrom, date_to: dateTo },
    responseType: 'blob',
  })
  const url = URL.createObjectURL(data)
  const link = document.createElement('a')
  link.href = url
  link.download = `evidence-${appName}-${dateFrom}-to-${dateTo}.json`
  link.click()
  URL.revokeObjectURL(url)
}
