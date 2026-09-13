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
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { IconOverdue, IconRefresh, IconUpload, IconWithinSla } from '../../lib/icons'
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
      <h1>{t('sbom.title')}</h1>
      <p className="field-hint">{t('sbom.intro')}</p>

      <ManualUploadSection />
      <SyncSection />
      <StaleCheckSection />
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

  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('sbom.uploadFailed'))

  return (
    <section aria-labelledby="manual-upload-heading">
      <h2 id="manual-upload-heading" className="section-title">
        {t('sbom.manualUploadSection')}
      </h2>
      <p className="field-hint">{t('sbom.manualUploadHint')}</p>

      <form onSubmit={handleSubmit} noValidate>
        {(validationError || serverErrorMessage) && (
          <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
            <p>{t('sbom.uploadErrorSummary')}</p>
            <ul>
              <li>{validationError || serverErrorMessage}</li>
            </ul>
          </div>
        )}

        <div className="filter-bar">
          <div className="filter-group">
            <label htmlFor="sbom-app">{t('inventory.appName')}</label>
            <select
              id="sbom-app"
              value={applicationId}
              onChange={(event) => setApplicationId(event.target.value)}
            >
              <option value="">{t('sbom.selectApplication')}</option>
              {applications?.items.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.app_name}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label htmlFor="sbom-version">{t('sbom.versionLabel')}</label>
            <input
              id="sbom-version"
              type="text"
              placeholder="1.0.0"
              value={versionLabel}
              onChange={(event) => setVersionLabel(event.target.value)}
            />
          </div>

          <div className="filter-group filter-group-grow">
            <label htmlFor="sbom-file">{t('sbom.file')}</label>
            <input
              id="sbom-file"
              type="file"
              accept="application/json,.json"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
          </div>
        </div>

        <div className="form-actions">
          <button type="submit" disabled={mutation.isPending}>
            <IconUpload />
            {mutation.isPending ? t('common.saving') : t('sbom.upload')}
          </button>
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

  return (
    <section aria-labelledby="sync-heading">
      <h2 id="sync-heading" className="section-title">
        {t('sbom.syncSection')}
      </h2>
      <p className="field-hint">{t('sbom.syncHint')}</p>

      <div className="form-actions">
        <button type="button" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
          <IconRefresh />
          {mutation.isPending ? t('common.saving') : t('sbom.syncNow')}
        </button>
      </div>

      {mutation.isError && (
        <p className="form-error" role="alert">
          {t('sbom.syncFailed')}
        </p>
      )}

      {mutation.isSuccess && (
        <dl className="detail-grid" role="status">
          <div>
            <dt>{t('sbom.projectsSeen')}</dt>
            <dd className="mono">{mutation.data.projects_seen}</dd>
          </div>
          <div>
            <dt>{t('sbom.appsAutoCreated')}</dt>
            <dd className="mono">{mutation.data.applications_auto_created}</dd>
          </div>
          <div>
            <dt>{t('sbom.componentsUpserted')}</dt>
            <dd className="mono">{mutation.data.components_upserted}</dd>
          </div>
          <div>
            <dt>{t('sbom.findingsCreated')}</dt>
            <dd className="mono">{mutation.data.findings_created}</dd>
          </div>
          <div>
            <dt>{t('sbom.findingsAutoClosed')}</dt>
            <dd className="mono">{mutation.data.findings_auto_closed}</dd>
          </div>
          {mutation.data.errors.length > 0 && (
            <div>
              <dt>{t('sbom.syncErrors')}</dt>
              <dd>
                <ul>
                  {mutation.data.errors.map((error) => (
                    <li key={error} className="form-error">
                      {error}
                    </li>
                  ))}
                </ul>
              </dd>
            </div>
          )}
        </dl>
      )}
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
    <section aria-labelledby="stale-heading">
      <h2 id="stale-heading" className="section-title">
        {t('sbom.staleSection')}
      </h2>
      <p className="field-hint">{t('sbom.staleHint')}</p>

      <div className="form-actions">
        <button type="button" onClick={() => mutation.mutate()} disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('sbom.runStaleCheck')}
        </button>
      </div>

      {mutation.isSuccess && (
        <p role="status">
          {mutation.data.newly_flagged_version_ids.length > 0 ? <IconOverdue /> : <IconWithinSla />}
          {t('sbom.staleResult', {
            newlyFlagged: mutation.data.newly_flagged_version_ids.length,
            total: mutation.data.total_stale_versions,
          })}
        </p>
      )}
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

      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="history-app">{t('inventory.appName')}</label>
          <select
            id="history-app"
            value={applicationId}
            onChange={(event) => {
              setApplicationId(event.target.value)
              setVersionId('')
            }}
          >
            <option value="">{t('sbom.selectApplication')}</option>
            {applications?.items.map((app) => (
              <option key={app.id} value={app.id}>
                {app.app_name}
              </option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="history-version">{t('sbom.versionLabel')}</label>
          <select
            id="history-version"
            value={versionId}
            disabled={!applicationId}
            onChange={(event) => setVersionId(event.target.value)}
          >
            <option value="">{t('sbom.selectVersion')}</option>
            {versions?.map((version) => (
              <option key={version.id} value={version.id}>
                {version.version_label}
                {version.is_stale ? ` (${t('sbom.stale')})` : ''}
              </option>
            ))}
          </select>
        </div>
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
                  <td className="mono">{new Date(entry.scanned_at).toLocaleString()}</td>
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
