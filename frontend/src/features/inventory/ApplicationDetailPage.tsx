/**
 * Application detail (Requirement.md FR-6.1, FR-6.5.3): per-Version Go-Live Gate
 * checklist/approval and the Pentest Projects tested against each Version — the home
 * FR-6.5.3 calls for so Dev Team sees their own Application's Pentest state without a
 * separate Pentest-specific screen.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { approveGoLive, getGoLiveChecklist, getGoLiveHistory } from '../golive/api'
import {
  allowedNextStatuses,
  changePentestStatus,
  createPentestProject,
  downloadPentestReportFile,
  ENGAGEMENT_TYPES,
  listPentestProjects,
  uploadPentestReportFile,
} from '../pentest/api'
import type { EngagementType, PentestStatus } from '../pentest/types'
import { IconAlertCircle, IconPlus, IconWithinSla } from '../../lib/icons'
import { can } from '../../lib/rbac'
import { getApplication, listAppVersions } from './api'

function GateStatus({ pass, label }: { pass: boolean; label: string }) {
  return (
    <span className={pass ? 'chip chip-sla-within' : 'chip chip-sla-overdue'}>
      {pass ? <IconWithinSla /> : <IconAlertCircle />}
      {label}
    </span>
  )
}

export function ApplicationDetailPage() {
  const { t } = useTranslation()
  const { appId } = useParams<{ appId: string }>()
  const { user } = useAuth()
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null)

  const { data: application, isLoading: appLoading } = useQuery({
    queryKey: ['application', appId],
    queryFn: () => getApplication(appId!),
    enabled: Boolean(appId),
  })

  const { data: versions, isLoading: versionsLoading } = useQuery({
    queryKey: ['app-versions', appId],
    queryFn: () => listAppVersions(appId!),
    enabled: Boolean(appId),
  })

  const versionId =
    selectedVersionId ??
    versions?.find((v) => v.is_current_production)?.id ??
    versions?.[0]?.id ??
    null

  if (appLoading || versionsLoading) {
    return (
      <div className="page">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }

  if (!application) {
    return (
      <div className="page">
        <p className="form-error" role="alert">
          {t('inventory.notFound')}
        </p>
        <Link to="/applications">{t('inventory.backToApplications')}</Link>
      </div>
    )
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">{application.app_name}</h1>
          <div className="page-sub">
            {t('inventory.ownerTeam')}: {application.owner_team}
          </div>
        </div>
        <Link to={`/findings?application_id=${application.id}`} className="button-secondary">
          {t('inventory.viewBacklog')}
        </Link>
      </div>

      {versions && versions.length > 0 && (
        <div className="filter-group">
          <label htmlFor="version-select">{t('inventory.versionLabel')}</label>
          <select
            id="version-select"
            value={versionId ?? ''}
            onChange={(e) => setSelectedVersionId(e.target.value)}
          >
            {versions.map((v) => (
              <option key={v.id} value={v.id}>
                {v.version_label}
                {v.is_current_production ? ` (${t('inventory.currentProduction')})` : ''}
              </option>
            ))}
          </select>
        </div>
      )}

      {!versionId && <p className="empty-state">{t('inventory.noVersions')}</p>}

      {versionId && can(user?.role, 'viewGoLiveGate') && <GoLiveGateSection versionId={versionId} />}

      {versionId && can(user?.role, 'viewPentestProjects') && (
        <PentestProjectsSection versionId={versionId} />
      )}
    </div>
  )
}

function GoLiveGateSection({ versionId }: { versionId: string }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const canApprove = can(user?.role, 'approveGoLive')

  const { data: checklist, isLoading } = useQuery({
    queryKey: ['go-live-checklist', versionId],
    queryFn: () => getGoLiveChecklist(versionId),
  })
  const { data: history } = useQuery({
    queryKey: ['go-live-history', versionId],
    queryFn: () => getGoLiveHistory(versionId),
  })

  const mutation = useMutation({
    mutationFn: () => approveGoLive(versionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['go-live-history', versionId] })
    },
  })

  return (
    <section aria-labelledby="golive-heading" className="card card-pad">
      <div className="page-head">
        <h2 id="golive-heading" className="section-title">
          {t('golive.sectionTitle')}
        </h2>
        {canApprove && checklist && (
          <button
            type="button"
            disabled={!checklist.ready || mutation.isPending}
            title={!checklist.ready ? t('golive.notReadyTooltip') : undefined}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending ? t('common.saving') : t('golive.approve')}
          </button>
        )}
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {mutation.isError && (
        <p className="form-error" role="alert">
          {(mutation.error as { response?: { data?: { detail?: string } } })?.response?.data
            ?.detail ?? t('golive.approveFailed')}
        </p>
      )}

      {checklist && (
        <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <GateStatus
            pass={checklist.sbom_pass}
            label={`${t('golive.sbom')} (${checklist.sbom_blocking_count})`}
          />
          <GateStatus
            pass={checklist.sast_pass}
            label={`${t('golive.sast')} (${checklist.sast_blocking_count})`}
          />
          {checklist.pentest_required ? (
            <GateStatus
              pass={checklist.pentest_pass}
              label={`${t('golive.pentest')} (${checklist.pentest_blocking_count})`}
            />
          ) : (
            <span className="chip chip-neutral">{t('golive.pentestNotRequired')}</span>
          )}
        </div>
      )}

      {history && history.length > 0 && (
        <div className="table-scroll" style={{ marginTop: 'var(--space-4)' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('golive.approver')}</th>
                <th scope="col">{t('golive.approvedAt')}</th>
                <th scope="col">{t('golive.breakGlass')}</th>
              </tr>
            </thead>
            <tbody>
              {history.map((approval) => (
                <tr key={approval.id}>
                  <td>{approval.approver}</td>
                  <td>{new Date(approval.created_at).toLocaleString()}</td>
                  <td>{approval.is_break_glass ? t('common.yes') : t('common.no')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function PentestProjectsSection({ versionId }: { versionId: string }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [showCreate, setShowCreate] = useState(false)
  const queryClient = useQueryClient()
  const canManage = can(user?.role, 'managePentestProjects')
  const canSeeCost = can(user?.role, 'viewPentestCostReport')

  const { data: projects, isLoading } = useQuery({
    queryKey: ['pentest-projects', versionId],
    queryFn: () => listPentestProjects(versionId),
  })

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ['pentest-projects', versionId] })
  }

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: PentestStatus }) =>
      changePentestStatus(id, status),
    onSuccess: invalidate,
  })

  const uploadMutation = useMutation({
    mutationFn: ({ id, file }: { id: string; file: File }) => uploadPentestReportFile(id, file),
    onSuccess: invalidate,
  })

  async function handleDownload(projectId: string) {
    const blob = await downloadPentestReportFile(projectId)
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `pentest-report-${projectId}.pdf`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <section aria-labelledby="pentest-heading" style={{ marginTop: 'var(--space-5)' }}>
      <div className="page-head">
        <h2 id="pentest-heading" className="section-title">
          {t('pentest.sectionTitle')}
        </h2>
        {canManage && !showCreate && (
          <button type="button" className="button-secondary" onClick={() => setShowCreate(true)}>
            <IconPlus />
            {t('pentest.newProject')}
          </button>
        )}
      </div>

      {showCreate && (
        <CreatePentestProjectForm
          versionId={versionId}
          onDone={() => {
            setShowCreate(false)
            invalidate()
          }}
        />
      )}

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {projects && projects.length === 0 && <p className="empty-state">{t('pentest.empty')}</p>}

      {projects && projects.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('pentest.status')}</th>
                <th scope="col">{t('pentest.engagementType')}</th>
                <th scope="col">{t('pentest.vendorOrTester')}</th>
                {canSeeCost && <th scope="col">{t('pentest.cost')}</th>}
                <th scope="col">{t('pentest.retestOwner')}</th>
                <th scope="col">{t('pentest.report')}</th>
                {canManage && <th scope="col">{t('common.actions')}</th>}
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id}>
                  <td>
                    <span className="chip chip-neutral">
                      {t(`pentest.statusValue.${project.status}`)}
                    </span>
                  </td>
                  <td>{t(`pentest.engagementValue.${project.engagement_type}`)}</td>
                  <td>{project.vendor_name ?? project.tester_name ?? '—'}</td>
                  {canSeeCost && (
                    <td className="mono">
                      {project.cost ? `${project.cost} ${project.currency ?? ''}` : '—'}
                    </td>
                  )}
                  <td>
                    {project.retest_owner ?? '—'}
                    {project.retest_overdue && (
                      <span className="chip chip-sla-overdue" style={{ marginLeft: 'var(--space-2)' }}>
                        <IconAlertCircle />
                        {t('pentest.retestOverdue')}
                      </span>
                    )}
                  </td>
                  <td>
                    {project.report_file_url ? (
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => handleDownload(project.id)}
                      >
                        {t('common.download')}
                      </button>
                    ) : canManage ? (
                      <label className="button-secondary" style={{ cursor: 'pointer' }}>
                        {uploadMutation.isPending ? t('common.saving') : t('pentest.uploadReport')}
                        <input
                          type="file"
                          accept=".pdf,.doc,.docx"
                          style={{ display: 'none' }}
                          onChange={(e) => {
                            const file = e.target.files?.[0]
                            if (file) uploadMutation.mutate({ id: project.id, file })
                          }}
                        />
                      </label>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  {canManage && (
                    <td>
                      {allowedNextStatuses(project.status).length > 0 ? (
                        <select
                          value=""
                          disabled={statusMutation.isPending}
                          onChange={(e) => {
                            if (e.target.value) {
                              statusMutation.mutate({
                                id: project.id,
                                status: e.target.value as PentestStatus,
                              })
                            }
                          }}
                        >
                          <option value="">{t('pentest.changeStatus')}</option>
                          {allowedNextStatuses(project.status).map((s) => (
                            <option key={s} value={s}>
                              {t(`pentest.statusValue.${s}`)}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function CreatePentestProjectForm({
  versionId,
  onDone,
}: {
  versionId: string
  onDone: () => void
}) {
  const { t } = useTranslation()
  const [engagementType, setEngagementType] = useState<EngagementType>('internal')
  const [vendorName, setVendorName] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: () =>
      createPentestProject({
        app_version_id: versionId,
        engagement_type: engagementType,
        vendor_name: engagementType === 'vendor' ? vendorName.trim() : null,
      }),
    onSuccess: onDone,
  })

  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('pentest.createFailed'))

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (engagementType === 'vendor' && !vendorName.trim()) {
      setValidationError(t('pentest.vendorNameRequiredError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate()
  }

  return (
    <form
      className="card card-pad"
      onSubmit={handleSubmit}
      noValidate
      style={{ marginBottom: 'var(--space-4)' }}
    >
      {(validationError || serverErrorMessage) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('pentest.createErrorSummary')}</p>
          <ul>
            <li>{validationError || serverErrorMessage}</li>
          </ul>
        </div>
      )}

      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="engagement-type">{t('pentest.engagementType')}</label>
          <select
            id="engagement-type"
            value={engagementType}
            onChange={(e) => setEngagementType(e.target.value as EngagementType)}
          >
            {ENGAGEMENT_TYPES.map((type) => (
              <option key={type} value={type}>
                {t(`pentest.engagementValue.${type}`)}
              </option>
            ))}
          </select>
        </div>
        {engagementType === 'vendor' && (
          <div className="filter-group">
            <label htmlFor="vendor-name">{t('pentest.vendorName')}</label>
            <input
              id="vendor-name"
              type="text"
              value={vendorName}
              onChange={(e) => setVendorName(e.target.value)}
            />
          </div>
        )}
      </div>

      <div className="form-actions" style={{ marginTop: 'var(--space-3)' }}>
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('pentest.createProject')}
        </button>
        <button type="button" className="button-secondary" onClick={onDone}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}
