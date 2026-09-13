export interface ManualSbomUploadResult {
  app_version_id: string
  sbom_format: string
  components_ingested: number
  forwarded_to_sca_platform: boolean
  forward_error: string | null
}

export interface DependencyTrackSyncResult {
  projects_seen: number
  applications_auto_created: number
  components_upserted: number
  findings_created: number
  findings_auto_closed: number
  errors: string[]
}

export interface StaleCheckResult {
  newly_flagged_version_ids: string[]
  total_stale_versions: number
}

export interface IngestionHistoryEntry {
  id: string
  scan_type: string
  scanned_at: string
  result_status: string
  is_manual_upload: boolean
  uploaded_by: string | null
  report_file_url: string | null
  validity_expiry_date: string | null
}
