import { apiClient } from '../../lib/api'
import type {
  DependencyTrackSyncResult,
  IngestionHistoryEntry,
  ManualSbomUploadResult,
  StaleCheckResult,
} from './types'

export async function uploadManualSbom(
  applicationId: string,
  versionLabel: string,
  file: File,
): Promise<ManualSbomUploadResult> {
  const form = new FormData()
  form.set('application_id', applicationId)
  form.set('version_label', versionLabel)
  form.set('file', file)
  const { data } = await apiClient.post<ManualSbomUploadResult>('/sbom/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function triggerDependencyTrackSync(): Promise<DependencyTrackSyncResult> {
  const { data } = await apiClient.post<DependencyTrackSyncResult>('/sbom/sync')
  return data
}

export async function triggerStaleCheck(): Promise<StaleCheckResult> {
  const { data } = await apiClient.post<StaleCheckResult>('/sbom/stale-check')
  return data
}

export async function fetchIngestionHistory(
  appVersionId: string,
): Promise<IngestionHistoryEntry[]> {
  const { data } = await apiClient.get<IngestionHistoryEntry[]>('/sbom/ingestion-history', {
    params: { app_version_id: appVersionId },
  })
  return data
}
