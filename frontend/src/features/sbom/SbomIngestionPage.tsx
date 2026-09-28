/**
 * SBOM Ingestion (Requirement.md FR-2, FR-3).
 *
 * Automated CI/CD pushes go straight to the SCA platform (Dependency-Track) and never
 * touch this screen (FR-2.7) — what lives here is everything that *is* this platform's
 * job: the COTS/Vendor manual upload path (FR-2.6), a manual trigger for the pull-sync
 * that normally runs on a schedule (FR-2.5/FR-3.1), the staleness sweep (FR-2.4), and the
 * ingestion history that answers "when was this last scanned" (FR-2.3).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { DragEvent, FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button, ErrorSummary, FormField, SelectBox, TextInput } from '../../components/ui'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { formatDateTime } from '../../lib/format'
import { IconOverdue, IconPackage, IconRefresh, IconUpload, IconWithinSla } from '../../lib/icons'
import { cx } from '../../lib/ui-helpers'
import { listApplications, listAppVersions } from '../inventory/api'
import {
  fetchIngestionHistory,
  triggerDependencyTrackSync,
  triggerStaleCheck,
  uploadManualSbom,
} from './api'

export function SbomIngestionPage() {
  const { t } = useTranslation()

  return (
    <div className="page">
      <div>
        <h1>{t('sbom.title')}</h1>
        <p className="page-sub">{t('sbom.intro')}</p>
      </div>

      <div className="task-grid">
        <SyncSection />
        <StaleCheckSection />
      </div>
      <ManualUploadSection />
      <IngestionHistorySection />
    </div>
  )
}

/** Reusable "Application" select, backed by the FR-1 inventory list. */
function useApplicationOptions() {
  return useQuery({ queryKey: ['applications', 'sbom-picker'], queryFn: () => listApplications(0, 200) })
}

function ManualUploadSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { data: applications } = useApplicationOptions()

  const [applicationId, setApplicationId] = useState('')
  const [versionLabel, setVersionLabel] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: () => uploadManualSbom(applicationId, versionLabel, file!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sbom-ingestion-history'] })
      queryClient.invalidateQueries({ queryKey: ['app-versions'] })
    },
  })

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (!applicationId || !versionLabel.trim() || !file) {
      setValidationError(t('sbom.uploadValidationError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate()
  }

  const message = validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('sbom.uploadFailed')) : null)

  return (
    <section aria-labelledby="manual-upload-heading" className="card card-pad upload-card">
      <h2 id="manual-upload-heading" className="section-title">
        {t('sbom.manualUploadSection')}
      </h2>
      <p className="field-hint">{t('sbom.manualUploadHint')}</p>

      <form className="stack" onSubmit={handleSubmit} noValidate>
        {message && <ErrorSummary ref={errorSummaryRef} title={t('sbom.uploadErrorSummary')} message={message} />}

        <div className="form-grid">
          <FormField label={t('inventory.appName')}>
            <SelectBox
              value={applicationId}
              onChange={setApplicationId}
              placeholder={t('sbom.selectApplication')}
              options={(applications?.items ?? []).map((app) => ({ value: app.id, label: app.app_name }))}
            />
          </FormField>
          <FormField label={t('sbom.versionLabel')}>
            <TextInput placeholder="1.0.0" value={versionLabel} onChange={(event) => setVersionLabel(event.target.value)} />
          </FormField>
        </div>
        <FileDrop file={file} onChange={setFile} />

        <div className="form-actions">
          <Button type="submit" variant="primary" disabled={mutation.isPending}>
            <IconUpload />
            {mutation.isPending ? t('common.saving') : t('sbom.upload')}
          </Button>
          {mutation.isSuccess && (
            <span className="form-success" role="status">
              {t('sbom.uploadSuccess', {
                count: mutation.data.components_ingested,
                format: mutation.data.sbom_format.toUpperCase(),
              })}
              {mutation.data.forwarded_to_sca_platform && ` ${t('sbom.uploadForwarded')}`}
            </span>
          )}
        </div>
      </form>
    </section>
  )
}

function SyncSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: triggerDependencyTrackSync,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['backlog-summary'] })
    },
  })

  const result = mutation.data
  return (
    <section aria-labelledby="sync-heading" className="card task-card">
      <span className="task-icon" aria-hidden="true">
        <IconRefresh />
      </span>
      <div className="task-text">
        <h2 id="sync-heading" className="task-title">
          {t('sbom.syncSection')}
        </h2>
        <p className="task-hint">{t('sbom.syncHint')}</p>
        {mutation.isError && (
          <p className="form-error" role="alert">
            {t('sbom.syncFailed')}
          </p>
        )}
        {result && (
          <p className="task-result" role="status">
            <IconWithinSla />
            {t('sbom.syncSummary', {
              projects: result.projects_seen,
              components: result.components_upserted,
              created: result.findings_created,
              closed: result.findings_auto_closed,
            })}
            {result.applications_auto_created > 0 &&
              ` · ${t('sbom.syncNewApps', { count: result.applications_auto_created })}`}
          </p>
        )}
        {result && result.errors.length > 0 && (
          <ul className="task-errors" role="alert">
            {result.errors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        )}
      </div>
      <Button small onClick={() => mutation.mutate()} disabled={mutation.isPending}>
        {mutation.isPending ? t('sbom.syncing') : t('sbom.syncNow')}
      </Button>
    </section>
  )
}

function StaleCheckSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: triggerStaleCheck,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] })
      queryClient.invalidateQueries({ queryKey: ['app-versions'] })
    },
  })

  return (
    <section aria-labelledby="stale-heading" className="card task-card">
      <span className="task-icon" aria-hidden="true">
        <IconPackage />
      </span>
      <div className="task-text">
        <h2 id="stale-heading" className="task-title">
          {t('sbom.staleSection')}
        </h2>
        <p className="task-hint">{t('sbom.staleHint')}</p>
        {mutation.isSuccess && (
          <p className="task-result" role="status">
            {mutation.data.newly_flagged_version_ids.length > 0 ? <IconOverdue /> : <IconWithinSla />}
            {t('sbom.staleResult', {
              newlyFlagged: mutation.data.newly_flagged_version_ids.length,
              total: mutation.data.total_stale_versions,
            })}
          </p>
        )}
      </div>
      <Button small onClick={() => mutation.mutate()} disabled={mutation.isPending}>
        {mutation.isPending ? t('common.loading') : t('sbom.runStaleCheck')}
      </Button>
    </section>
  )
}

function IngestionHistorySection() {
  const { t } = useTranslation()
  const { data: applications } = useApplicationOptions()
  const [applicationId, setApplicationId] = useState('')
  const [versionId, setVersionId] = useState('')

  const { data: versions } = useQuery({
    queryKey: ['app-versions', applicationId],
    queryFn: () => listAppVersions(applicationId),
    enabled: Boolean(applicationId),
  })

  const { data: history, isLoading } = useQuery({
    queryKey: ['sbom-ingestion-history', versionId],
    queryFn: () => fetchIngestionHistory(versionId),
    enabled: Boolean(versionId),
  })

  return (
    <section aria-labelledby="history-heading">
      <h2 id="history-heading" className="section-title">
        {t('sbom.historySection')}
      </h2>
      <p className="field-hint">{t('sbom.historyHint')}</p>

      <div className="toolbar section-gap">
        <FormField label={t('inventory.appName')}>
          <SelectBox
            value={applicationId}
            onChange={(value) => {
              setApplicationId(value)
              setVersionId('')
            }}
            placeholder={t('sbom.selectApplication')}
            options={(applications?.items ?? []).map((app) => ({ value: app.id, label: app.app_name }))}
          />
        </FormField>
        <FormField label={t('sbom.versionLabel')}>
          <SelectBox
            value={versionId}
            onChange={setVersionId}
            disabled={!applicationId}
            placeholder={t('sbom.selectVersion')}
            options={(versions ?? []).map((version) => ({
              value: version.id,
              label: version.is_stale ? `${version.version_label} (${t('sbom.stale')})` : version.version_label,
            }))}
          />
        </FormField>
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}

      {versionId && history && history.length === 0 && (
        <p className="empty-state">{t('sbom.noHistory')}</p>
      )}

      {history && history.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('sbom.scannedAt')}</th>
                <th scope="col">{t('sbom.scanType')}</th>
                <th scope="col">{t('sbom.resultStatus')}</th>
                <th scope="col">{t('sbom.uploadMethod')}</th>
                <th scope="col">{t('sbom.uploadedBy')}</th>
              </tr>
            </thead>
            <tbody>
              {history.map((entry) => (
                <tr key={entry.id}>
                  <td className="nowrap">{formatDateTime(entry.scanned_at)}</td>
                  <td>{entry.scan_type.toUpperCase()}</td>
                  <td>{entry.result_status}</td>
                  <td>{entry.is_manual_upload ? t('sbom.manual') : t('sbom.automated')}</td>
                  <td>{entry.uploaded_by ?? <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

const MAX_BYTES_LABEL = 1024 * 1024

function formatSize(bytes: number): string {
  return bytes >= MAX_BYTES_LABEL ? `${(bytes / MAX_BYTES_LABEL).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`
}

/**
 * Drop zone replacing the browser's file input: the native control renders a long,
 * unstyled "Choose file / No file chosen" bar that cannot be themed. The real input stays
 * in the DOM (visually hidden) so keyboard and screen-reader users get the native picker.
 */
function FileDrop({ file, onChange }: { file: File | null; onChange: (file: File | null) => void }) {
  const { t } = useTranslation()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault()
    setDragging(false)
    const dropped = event.dataTransfer.files?.[0]
    if (dropped) onChange(dropped)
  }

  function clear() {
    onChange(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  if (file) {
    return (
      <div className="file-chip">
        <span className="file-chip-icon" aria-hidden="true">
          <IconPackage />
        </span>
        <span className="file-chip-text">
          <span className="file-chip-name">{file.name}</span>
          <span className="file-chip-size">{formatSize(file.size)}</span>
        </span>
        <Button small variant="ghost" onClick={clear}>
          {t('sbom.removeFile')}
        </Button>
      </div>
    )
  }

  return (
    <label
      className={cx('dropzone', dragging && 'dragging')}
      onDragOver={(event) => {
        event.preventDefault()
        setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
    >
      <input
        ref={inputRef}
        type="file"
        className="visually-hidden"
        accept="application/json,.json"
        onChange={(event) => onChange(event.target.files?.[0] ?? null)}
      />
      <IconUpload />
      <span>
        {t('sbom.dropPrompt')} <span className="dropzone-link">{t('sbom.browse')}</span>
      </span>
      <span className="dropzone-hint">{t('sbom.fileFormats')}</span>
    </label>
  )
}
