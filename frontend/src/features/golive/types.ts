export interface GoLiveChecklist {
  app_version_id: string
  sbom_pass: boolean
  sbom_blocking_count: number
  sast_pass: boolean
  sast_blocking_count: number
  pentest_required: boolean
  pentest_pass: boolean
  pentest_blocking_count: number
  ready: boolean
}

export interface GoLiveApproval {
  id: string
  app_version_id: string
  sbom_pass: boolean
  sast_pass: boolean
  pentest_pass: boolean
  approver: string
  is_break_glass: boolean
  created_at: string
}
