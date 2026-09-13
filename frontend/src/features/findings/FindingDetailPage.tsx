/**
 * Finding detail + remediation plan (Requirement.md FR-10.2, FR-10.5, UXR-5, UXR-7).
 *
 * The breadcrumb spells out the full Application > Version > Component > Finding path
 * required by UXR-5, and "back to backlog" keeps the query string so the user returns to
 * the filtered list they came from rather than a reset one.
 *
 * The plan form follows UXR-7: inline validation, an error summary that takes focus on a
 * failed submit, and a submit button disabled while in flight so a double click cannot
 * write the plan twice.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { SeverityBadge, SlaBadge } from '../../components/SeverityBadge'
import { useAuth } from '../auth/context'
import { IconChevronRight, IconExternal } from '../../lib/icons'
import { can } from '../../lib/rbac'
import { listConnectors } from '../settings/integrationApi'
import {
  approveWaiver,
  createFindingTicket,
  fetchFinding,
  listFindingTickets,
  listWaivers,
  rejectWaiver,
  requestWaiver,
  revokeWaiver,
  updateRemediationPlan,
  updateVexStatus,
} from './api'
import type { VexStatus } from './types'

const VEX_STATUSES: VexStatus[] = ['affected', 'not_affected', 'fixed', 'under_investigation']

const MAX_PLAN_LENGTH = 10_000

function formatDateTime(value: string | null): string {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

export function FindingDetailPage() {
  const { t } = useTranslation()
  const { findingId } = useParams<{ findingId: string }>()
  const navigate = useNavigate()
  const { user } = useAuth()

  const { data: finding, isLoading, isError } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => fetchFinding(findingId!),
    enabled: Boolean(findingId),
  })

  const canEdit = can(user?.role, 'editRemediationPlan')

  if (isLoading) {
    return (
      <div className="page">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }

  if (isError || !finding) {
    return (
      <div className="page">
        <p className="form-error" role="alert">
          {t('findings.notFound')}
        </p>
        <Link to="/findings">{t('findings.backToBacklog')}</Link>
      </div>
    )
  }

  const heading = finding.cve_id ?? finding.title ?? t('findings.untitled')

  return (
    <div className="page">
      {/* UXR-5: full drill-down path, shown whenever the user is more than two levels deep. */}
      <nav className="breadcrumb" aria-label={t('common.breadcrumb')}>
        <Link to="/findings">{t('nav.findings')}</Link>
        <IconChevronRight />
        <Link to={`/findings?application_id=${finding.application_id}`}>
          {finding.application_name}
        </Link>
        <IconChevronRight />
        <span>{finding.version_label}</span>
        {finding.component_name && (
          <>
            <IconChevronRight />
            <span className="mono">{finding.component_name}</span>
          </>
        )}
        <IconChevronRight />
        <span aria-current="page">{heading}</span>
      </nav>

      <div className="detail-header">
        <h1>
          {heading}
          {finding.kev_flag && <span className="chip chip-kev">KEV</span>}
        </h1>
        <div className="detail-header-chips">
          <SeverityBadge tier={finding.severity_tier} />
          <SlaBadge
            isOverdue={finding.is_overdue}
            dueDate={finding.due_date}
            daysUntilDue={finding.days_until_due}
          />
        </div>
      </div>

      {finding.title && finding.cve_id && <p className="detail-subtitle">{finding.title}</p>}
      {finding.description && <p>{finding.description}</p>}

      <section aria-labelledby="detail-facts-heading">
        <h2 id="detail-facts-heading" className="section-title">
          {t('findings.detailsSection')}
        </h2>
        <dl className="detail-grid">
          <div>
            <dt>{t('findings.source')}</dt>
            <dd>{finding.source.toUpperCase()}</dd>
          </div>
          <div>
            <dt>{t('findings.status')}</dt>
            <dd>{t(`findings.statusValue.${finding.status}`)}</dd>
          </div>
          <div>
            <dt>CVSS</dt>
            <dd className="mono">{finding.cvss?.toFixed(1) ?? '—'}</dd>
          </div>
          <div>
            <dt>EPSS</dt>
            <dd className="mono">
              {finding.epss === null ? '—' : `${(finding.epss * 100).toFixed(1)}%`}
            </dd>
          </div>
          <div>
            <dt>{t('findings.component')}</dt>
            <dd className="mono">
              {finding.component_name
                ? `${finding.component_name} ${finding.component_version ?? ''}`
                : '—'}
            </dd>
          </div>
          <div>
            <dt>{t('findings.dependencyScope')}</dt>
            <dd>{finding.component_scope ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('findings.fixedVersion')}</dt>
            <dd className="mono">{finding.fixed_version ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('findings.dueDate')}</dt>
            <dd className="mono">{finding.due_date ?? t('sla.bestEffort')}</dd>
          </div>
          <div>
            <dt>{t('findings.firstDetected')}</dt>
            <dd>{formatDateTime(finding.first_detected_at)}</dd>
          </div>
          <div>
            {/* NFR Auditability: which policy version produced this tier and due date. */}
            <dt>{t('findings.policyVersion')}</dt>
            <dd>{finding.policy_version ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('inventory.ownerTeam')}</dt>
            <dd>{finding.owner_team}</dd>
          </div>
        </dl>

        {finding.reference_url && (
          <p>
            <a href={finding.reference_url} target="_blank" rel="noreferrer noopener">
              {t('findings.advisoryLink')} <IconExternal />
            </a>
          </p>
        )}
      </section>

      <section aria-labelledby="plan-heading">
        <h2 id="plan-heading" className="section-title">
          {t('findings.remediationPlan')}
        </h2>

        {finding.remediation_plan_updated_by && (
          <p className="detail-meta">
            {t('findings.planUpdatedBy', {
              user: finding.remediation_plan_updated_by,
              at: formatDateTime(finding.remediation_plan_updated_at),
            })}
          </p>
        )}

        {canEdit ? (
          // Keyed on the Finding, so moving to another Finding gives a fresh editor while
          // saving this one does not remount it — a remount on save would wipe the draft
          // and the success confirmation. No effect copies server state into the form.
          <RemediationPlanForm
            key={finding.id}
            findingId={finding.id}
            initialPlan={finding.remediation_plan ?? ''}
          />
        ) : (
          <p>{finding.remediation_plan ?? <span className="muted">{t('findings.noPlan')}</span>}</p>
        )}
      </section>

      <VexSection findingId={finding.id} vexStatus={finding.vex_status} vexJustification={finding.vex_justification} />

      <WaiverSection findingId={finding.id} findingStatus={finding.status} />

      <TicketsSection findingId={finding.id} />

      <button type="button" className="button-secondary" onClick={() => navigate(-1)}>
        {t('findings.backToBacklog')}
      </button>
    </div>
  )
}

/**
 * VEX status (FR-8.1/8.2). Read-only for everyone; the edit control is only rendered
 * under `manageVex` — being able to reach it at all *is* the AppSec approval step.
 */
function VexSection({
  findingId,
  vexStatus,
  vexJustification,
}: {
  findingId: string
  vexStatus: VexStatus
  vexJustification: string | null
}) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [editing, setEditing] = useState(false)
  const queryClient = useQueryClient()
  const canManage = can(user?.role, 'manageVex')

  const mutation = useMutation({
    mutationFn: (payload: { vex_status: VexStatus; vex_justification: string | null }) =>
      updateVexStatus(findingId, payload),
    onSuccess: (updated) => {
      queryClient.setQueryData(['finding', findingId], updated)
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      setEditing(false)
    },
  })

  return (
    <section aria-labelledby="vex-heading">
      <div className="page-head">
        <h2 id="vex-heading" className="section-title">
          {t('vex.sectionTitle')}
        </h2>
        {canManage && !editing && (
          <button type="button" className="button-secondary" onClick={() => setEditing(true)}>
            {t('vex.change')}
          </button>
        )}
      </div>

      {!editing && (
        <dl className="detail-grid">
          <div>
            <dt>{t('findings.vexStatus')}</dt>
            <dd>{t(`findings.vexValue.${vexStatus}`)}</dd>
          </div>
          <div>
            <dt>{t('vex.justification')}</dt>
            <dd>{vexJustification ?? <span className="muted">{t('vex.noJustification')}</span>}</dd>
          </div>
        </dl>
      )}

      {editing && (
        <VexEditForm
          initialStatus={vexStatus}
          initialJustification={vexJustification ?? ''}
          isPending={mutation.isPending}
          onCancel={() => setEditing(false)}
          onSubmit={(values) => mutation.mutate(values)}
        />
      )}
    </section>
  )
}

function VexEditForm({
  initialStatus,
  initialJustification,
  isPending,
  onCancel,
  onSubmit,
}: {
  initialStatus: VexStatus
  initialJustification: string
  isPending: boolean
  onCancel: () => void
  onSubmit: (values: { vex_status: VexStatus; vex_justification: string | null }) => void
}) {
  const { t } = useTranslation()
  const [status, setStatus] = useState<VexStatus>(initialStatus)
  const [justification, setJustification] = useState(initialJustification)

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    onSubmit({ vex_status: status, vex_justification: justification.trim() || null })
  }

  return (
    <form className="card card-pad" onSubmit={handleSubmit} noValidate>
      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="vex-status">{t('findings.vexStatus')}</label>
          <select
            id="vex-status"
            value={status}
            onChange={(e) => setStatus(e.target.value as VexStatus)}
          >
            {VEX_STATUSES.map((value) => (
              <option key={value} value={value}>
                {t(`findings.vexValue.${value}`)}
              </option>
            ))}
          </select>
        </div>
        <div className="filter-group filter-group-grow">
          <label htmlFor="vex-justification">{t('vex.justification')}</label>
          <input
            id="vex-justification"
            type="text"
            placeholder={t('vex.justificationPlaceholder')}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
          />
        </div>
      </div>
      <div className="form-actions" style={{ marginTop: 'var(--space-3)' }}>
        <button type="submit" disabled={isPending}>
          {isPending ? t('common.saving') : t('common.save')}
        </button>
        <button type="button" className="button-secondary" onClick={onCancel}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}

/**
 * Exception/Waiver workflow (FR-6.2): Dev/Tech Lead (or AppSec) requests, AppSec/Admin
 * approves, rejects, or revokes an active one. Auto-expiry runs server-side.
 */
function WaiverSection({
  findingId,
  findingStatus,
}: {
  findingId: string
  findingStatus: string
}) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [showRequest, setShowRequest] = useState(false)
  const queryClient = useQueryClient()

  const {
    data: waivers,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ['finding-waivers', findingId],
    queryFn: () => listWaivers(findingId),
  })

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ['finding-waivers', findingId] })
    queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
  }

  const approveMutation = useMutation({ mutationFn: approveWaiver, onSuccess: invalidate })
  const rejectMutation = useMutation({ mutationFn: rejectWaiver, onSuccess: invalidate })
  const revokeMutation = useMutation({ mutationFn: revokeWaiver, onSuccess: invalidate })

  const canRequest = can(user?.role, 'requestWaiver')
  const canApprove = can(user?.role, 'approveWaiver')
  const hasOpenWaiver = waivers?.some((w) => w.status === 'pending' || w.status === 'active')

  return (
    <section aria-labelledby="waiver-heading">
      <div className="page-head">
        <h2 id="waiver-heading" className="section-title">
          {t('waivers.sectionTitle')}
        </h2>
        {canRequest && !showRequest && findingStatus === 'open' && !hasOpenWaiver && (
          <button type="button" className="button-secondary" onClick={() => setShowRequest(true)}>
            {t('waivers.requestWaiver')}
          </button>
        )}
      </div>

      {showRequest && (
        <RequestWaiverForm
          findingId={findingId}
          onDone={() => {
            setShowRequest(false)
            invalidate()
          }}
        />
      )}

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('waivers.loadError')}
        </p>
      )}
      {waivers && waivers.length === 0 && <p className="empty-state">{t('waivers.empty')}</p>}

      {waivers && waivers.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('waivers.status')}</th>
                <th scope="col">{t('waivers.reason')}</th>
                <th scope="col">{t('waivers.expiryDate')}</th>
                <th scope="col">{t('waivers.requestedBy')}</th>
                <th scope="col">{t('waivers.approvedBy')}</th>
                {canApprove && <th scope="col">{t('common.actions')}</th>}
              </tr>
            </thead>
            <tbody>
              {waivers.map((waiver) => (
                <tr key={waiver.id}>
                  <td>
                    <span className="chip chip-neutral">{t(`waivers.statusValue.${waiver.status}`)}</span>
                  </td>
                  <td>{waiver.reason}</td>
                  <td className="mono">{waiver.expiry_date}</td>
                  <td>{waiver.requested_by}</td>
                  <td>{waiver.approved_by ?? '—'}</td>
                  {canApprove && (
                    <td>
                      {waiver.status === 'pending' && (
                        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                          <button
                            type="button"
                            disabled={approveMutation.isPending}
                            onClick={() => approveMutation.mutate(waiver.id)}
                          >
                            {t('waivers.approve')}
                          </button>
                          <button
                            type="button"
                            className="button-secondary"
                            disabled={rejectMutation.isPending}
                            onClick={() => rejectMutation.mutate(waiver.id)}
                          >
                            {t('waivers.reject')}
                          </button>
                        </div>
                      )}
                      {waiver.status === 'active' && (
                        <button
                          type="button"
                          className="button-secondary"
                          disabled={revokeMutation.isPending}
                          onClick={() => revokeMutation.mutate(waiver.id)}
                        >
                          {t('waivers.revoke')}
                        </button>
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

function RequestWaiverForm({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const [expiryDate, setExpiryDate] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: () => requestWaiver(findingId, { reason: reason.trim(), expiry_date: expiryDate }),
    onSuccess: onDone,
  })

  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('waivers.createFailed'))

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (!reason.trim() || !expiryDate) {
      setValidationError(t('waivers.createValidationError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate()
  }

  return (
    <form className="card card-pad" onSubmit={handleSubmit} noValidate style={{ marginBottom: 'var(--space-4)' }}>
      {(validationError || serverErrorMessage) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('waivers.createErrorSummary')}</p>
          <ul>
            <li>{validationError || serverErrorMessage}</li>
          </ul>
        </div>
      )}

      <label htmlFor="waiver-reason">{t('waivers.reason')}</label>
      <textarea
        id="waiver-reason"
        rows={3}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />

      <div className="filter-group" style={{ marginTop: 'var(--space-3)' }}>
        <label htmlFor="waiver-expiry">{t('waivers.expiryDate')}</label>
        <input
          id="waiver-expiry"
          type="date"
          value={expiryDate}
          onChange={(e) => setExpiryDate(e.target.value)}
        />
      </div>

      <div className="form-actions" style={{ marginTop: 'var(--space-3)' }}>
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('waivers.requestWaiver')}
        </button>
        <button type="button" className="button-secondary" onClick={onDone}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}

/**
 * ITSM tickets cross-reference (FR-7.4) plus a manual "Create Ticket" action (FR-7.8)
 * for the edge cases automatic routing doesn't cover — an AppSec/Admin-only escape
 * hatch, gated by the same roles as the backend's `POST /findings/{id}/tickets`.
 */
function TicketsSection({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [showCreate, setShowCreate] = useState(false)
  const queryClient = useQueryClient()

  const {
    data: tickets,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ['finding-tickets', findingId],
    queryFn: () => listFindingTickets(findingId),
  })

  const canCreate = can(user?.role, 'createTicket')

  return (
    <section aria-labelledby="tickets-heading">
      <div className="page-head">
        <h2 id="tickets-heading" className="section-title">
          {t('tickets.sectionTitle')}
        </h2>
        {canCreate && !showCreate && (
          <button type="button" className="button-secondary" onClick={() => setShowCreate(true)}>
            {t('tickets.createTicket')}
          </button>
        )}
      </div>

      {showCreate && (
        <CreateTicketForm
          findingId={findingId}
          onDone={() => {
            setShowCreate(false)
            queryClient.invalidateQueries({ queryKey: ['finding-tickets', findingId] })
          }}
        />
      )}

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('tickets.loadError')}
        </p>
      )}

      {tickets && tickets.length === 0 && <p className="empty-state">{t('tickets.empty')}</p>}

      {tickets && tickets.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('tickets.externalId')}</th>
                <th scope="col">{t('tickets.connector')}</th>
                <th scope="col">{t('tickets.status')}</th>
                <th scope="col">{t('tickets.lastError')}</th>
                <th scope="col">{t('tickets.createdAt')}</th>
              </tr>
            </thead>
            <tbody>
              {tickets.map((ticket) => (
                <tr key={ticket.id}>
                  <td className="mono">{ticket.external_id}</td>
                  <td>{ticket.external_system}</td>
                  <td>
                    <span className="chip chip-neutral">{ticket.status}</span>
                  </td>
                  <td>{ticket.last_error ?? '—'}</td>
                  <td>{formatDateTime(ticket.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function CreateTicketForm({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const { t } = useTranslation()
  const [connectorId, setConnectorId] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const { data: connectors, isLoading } = useQuery({
    queryKey: ['integration-connectors'],
    queryFn: listConnectors,
  })

  const mutation = useMutation({
    mutationFn: () => createFindingTicket(findingId, connectorId),
    onSuccess: onDone,
  })

  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('tickets.createFailed'))

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (!connectorId) {
      setValidationError(t('tickets.createValidationError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate()
  }

  return (
    <form className="card card-pad" onSubmit={handleSubmit} noValidate style={{ marginBottom: 'var(--space-4)' }}>
      {(validationError || serverErrorMessage) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('tickets.createErrorSummary')}</p>
          <ul>
            <li>{validationError || serverErrorMessage}</li>
          </ul>
        </div>
      )}

      <div className="filter-group">
        <label htmlFor="ticket-connector">{t('integrations.name')}</label>
        <select
          id="ticket-connector"
          value={connectorId}
          onChange={(e) => setConnectorId(e.target.value)}
          disabled={isLoading}
        >
          <option value="">{t('tickets.selectConnector')}</option>
          {connectors?.map((connector) => (
            <option key={connector.id} value={connector.id}>
              {connector.name}
            </option>
          ))}
        </select>
      </div>

      <div className="form-actions" style={{ marginTop: 'var(--space-3)' }}>
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('tickets.createTicket')}
        </button>
        <button type="button" className="button-secondary" onClick={onDone}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}

/**
 * Remediation plan editor (FR-10.2, UXR-7).
 *
 * Owns only its draft text. The parent remounts it whenever the saved plan changes, so
 * server state stays the single source of truth without an effect copying it down.
 */
function RemediationPlanForm({
  findingId,
  initialPlan,
}: {
  findingId: string
  initialPlan: string
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [plan, setPlan] = useState(initialPlan)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: (value: string) => updateRemediationPlan(findingId, value),
    onSuccess: (updated) => {
      queryClient.setQueryData(['finding', findingId], updated)
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      setSaved(true)
    },
  })

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setSaved(false)
    const trimmed = plan.trim()
    if (trimmed.length === 0) {
      setValidationError(t('findings.planRequired'))
      // UXR-7: move focus to the error summary so the failure is announced, not just shown.
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate(trimmed)
  }

  return (
    <form className="plan-form" onSubmit={handleSubmit} noValidate>
      {(validationError || mutation.isError) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('findings.planErrorSummary')}</p>
          <ul>
            <li>
              <a href="#remediation-plan">{validationError ?? t('findings.planSaveFailed')}</a>
            </li>
          </ul>
        </div>
      )}

      <label htmlFor="remediation-plan">{t('findings.planLabel')}</label>
      <textarea
        id="remediation-plan"
        value={plan}
        rows={5}
        maxLength={MAX_PLAN_LENGTH}
        aria-invalid={validationError ? true : undefined}
        aria-describedby="remediation-plan-hint"
        onChange={(event) => {
          setPlan(event.target.value)
          setValidationError(null)
          setSaved(false)
        }}
      />
      <p id="remediation-plan-hint" className="field-hint">
        {t('findings.planHint')}
      </p>

      <div className="form-actions">
        {/* UXR-7: disabled while in flight, so a second click cannot duplicate the write. */}
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('common.save')}
        </button>
        {saved && (
          <span className="form-success" role="status">
            {t('findings.planSaved')}
          </span>
        )}
      </div>
    </form>
  )
}
