/**
 * Application detail (Requirement.md FR-6.1, FR-6.5.3): per-Version Go-Live Gate
 * checklist/approval and the Pentest Projects tested against each Version — the home
 * FR-6.5.3 calls for so Dev Team sees their own Application's Pentest state without a
 * separate Pentest-specific screen.
 */
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { Button, ErrorSummary, FormField, Modal, SelectBox, TextInput } from '../../components/ui'
import { apiErrorMessage, buttonClass } from '../../lib/ui-helpers'
import { formatDateTime } from '../../lib/format'
import { IconAlertCircle, IconChevronDown, IconPlus, IconUpload, IconWithinSla } from '../../lib/icons'
import { can } from '../../lib/rbac'
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
    selectedVersionId ?? versions?.find((v) => v.is_current_production)?.id ?? versions?.[0]?.id ?? null

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
          <h1>{application.app_name}</h1>
          <p className="page-sub">
            {[
              t(`inventory.appTypeValue.${application.app_type}`),
              `${t('inventory.ownerTeam')}: ${application.owner_team}`,
              application.internet_facing ? t('inventory.internetFacing') : t('inventory.internal'),
            ].join(' · ')}
          </p>
        </div>
        <div className="toolbar">
          {versions && versions.length > 0 && (
            <FormField label={t('inventory.versionLabel')}>
              <SelectBox
                value={versionId ?? ''}
                onChange={setSelectedVersionId}
                options={versions.map((v) => ({
                  value: v.id,
                  label: v.is_current_production
                    ? `${v.version_label} (${t('inventory.currentProduction')})`
                    : v.version_label,
                }))}
              />
            </FormField>
          )}
          <Link to={`/findings?application_id=${application.id}`} className={buttonClass('secondary')}>
            {t('inventory.viewBacklog')}
          </Link>
        </div>
      </div>

      {!versionId && <p className="empty-state">{t('inventory.noVersions')}</p>}

      {versionId && can(user?.role, 'viewGoLiveGate') && <GoLiveGateSection versionId={versionId} />}

      {versionId && can(user?.role, 'viewPentestProjects') && <PentestProjectsSection versionId={versionId} />}
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
    <section aria-labelledby="golive-heading" className="card card-pad stack">
      <div className="section-head">
        <h2 id="golive-heading" className="section-title">
          {t('golive.sectionTitle')}
        </h2>
        {canApprove && checklist && (
          <Button
            variant="primary"
            disabled={!checklist.ready || mutation.isPending}
            title={!checklist.ready ? t('golive.notReadyTooltip') : undefined}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending ? t('common.saving') : t('golive.approve')}
          </Button>
        )}
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {mutation.isError && (
        <p className="form-error" role="alert">
          {apiErrorMessage(mutation.error, t('golive.approveFailed'))}
        </p>
      )}

      {checklist && (
        <div className="inline">
          <GateStatus pass={checklist.sbom_pass} label={`${t('golive.sbom')} (${checklist.sbom_blocking_count})`} />
          <GateStatus pass={checklist.sast_pass} label={`${t('golive.sast')} (${checklist.sast_blocking_count})`} />
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
      {checklist && <p className="field-hint">{t('golive.countHint')}</p>}

      {history && history.length > 0 && (
        <div className="table-scroll">
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
                  <td>{formatDateTime(approval.created_at)}</td>
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
    mutationFn: ({ id, status }: { id: string; status: PentestStatus }) => changePentestStatus(id, status),
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
    <section aria-labelledby="pentest-heading">
      <div className="section-head">
        <h2 id="pentest-heading" className="section-title">
          {t('pentest.sectionTitle')}
        </h2>
        {canManage && (
          <Button small onClick={() => setShowCreate(true)}>
            <IconPlus />
            {t('pentest.newProject')}
          </Button>
        )}
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {projects && projects.length === 0 && <p className="empty-state">{t('pentest.empty')}</p>}
      {(statusMutation.isError || uploadMutation.isError) && (
        <p className="form-error" role="alert">
          {apiErrorMessage(statusMutation.error ?? uploadMutation.error, t('pentest.updateFailed'))}
        </p>
      )}

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
              {projects.map((project) => {
                const nextStatuses = allowedNextStatuses(project.status)
                return (
                  <tr key={project.id}>
                    <td>
                      <span className="chip chip-neutral">{t(`pentest.statusValue.${project.status}`)}</span>
                    </td>
                    <td>{t(`pentest.engagementValue.${project.engagement_type}`)}</td>
                    <td>{project.vendor_name ?? project.tester_name ?? '—'}</td>
                    {canSeeCost && (
                      <td className="mono">{project.cost ? `${project.cost} ${project.currency ?? ''}` : '—'}</td>
                    )}
                    <td>
                      {project.retest_owner ?? '—'}
                      {project.retest_overdue && (
                        <span className="chip chip-sla-overdue gap-left">
                          <IconAlertCircle />
                          {t('pentest.retestOverdue')}
                        </span>
                      )}
                    </td>
                    <td>
                      {project.report_file_url ? (
                        <Button small onClick={() => handleDownload(project.id)}>
                          {t('common.download')}
                        </Button>
                      ) : canManage ? (
                        <label className={`${buttonClass('secondary', true)} file-button`}>
                          <IconUpload />
                          {uploadMutation.isPending ? t('common.saving') : t('pentest.uploadReport')}
                          <input
                            type="file"
                            accept=".pdf,.doc,.docx"
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
                        {nextStatuses.length > 0 ? (
                          <Menu>
                            <MenuButton className={buttonClass('secondary', true)} disabled={statusMutation.isPending}>
                              {t('pentest.changeStatus')}
                              <IconChevronDown />
                            </MenuButton>
                            <MenuItems anchor={{ to: 'bottom end', gap: 4 }} transition className="popover-surface menu-items">
                              {nextStatuses.map((status) => (
                                <MenuItem key={status}>
                                  <button
                                    type="button"
                                    className="menu-item"
                                    onClick={() => statusMutation.mutate({ id: project.id, status })}
                                  >
                                    {t(`pentest.statusValue.${status}`)}
                                  </button>
                                </MenuItem>
                              ))}
                            </MenuItems>
                          </Menu>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title={t('pentest.newProject')}>
        <CreatePentestProjectForm
          versionId={versionId}
          onCancel={() => setShowCreate(false)}
          onDone={() => {
            setShowCreate(false)
            invalidate()
          }}
        />
      </Modal>
    </section>
  )
}

function CreatePentestProjectForm({
  versionId,
  onCancel,
  onDone,
}: {
  versionId: string
  onCancel: () => void
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

  const message = validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('pentest.createFailed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorSummaryRef} title={t('pentest.createErrorSummary')} message={message} />}
      <FormField label={t('pentest.engagementType')}>
        <SelectBox
          value={engagementType}
          onChange={setEngagementType}
          options={ENGAGEMENT_TYPES.map((type) => ({ value: type, label: t(`pentest.engagementValue.${type}`) }))}
        />
      </FormField>
      {engagementType === 'vendor' && (
        <FormField label={t('pentest.vendorName')}>
          <TextInput
            value={vendorName}
            onChange={(e) => setVendorName(e.target.value)}
            invalid={Boolean(validationError)}
          />
        </FormField>
      )}
      <div className="modal-actions">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('pentest.createProject')}
        </Button>
      </div>
    </form>
  )
}
