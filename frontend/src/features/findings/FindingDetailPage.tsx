/**
 * Finding detail + remediation plan (Requirement.md FR-10.2, FR-10.5, UXR-5, UXR-7).
 *
 * The page leads with what the owning team needs to act — severity, due date, how to fix
 * and the remediation plan — and folds the AppSec-oriented detail (scores, risk exceptions,
 * tickets) into disclosure rows, each with a one-line summary so nothing is hidden
 * without a hint of what is inside.
 *
 * The breadcrumb spells out the full Application > Version > Component > Finding path
 * required by UXR-5, and "back" keeps the query string so the user returns to the
 * filtered list they came from. Forms follow UXR-7: inline error summary that takes focus,
 * submit disabled while in flight, and dialogs that return focus to their trigger.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { SeverityBadge, SlaBadge } from '../../components/SeverityBadge'
import { Button, DisclosureRow, ErrorSummary, FormField, InfoTip, Modal, SelectBox, TextArea } from '../../components/ui'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { formatDate, formatDateTime } from '../../lib/format'
import { IconChevronRight, IconExternal, IconPlus } from '../../lib/icons'
import { can } from '../../lib/rbac'
import { useAuth } from '../auth/context'
import { listConnectors } from '../settings/integrationApi'
import { listExceptions } from '../exceptions/api'
import { ExceptionStatusBadge } from '../exceptions/ExceptionBadges'
import { RequestExceptionForm } from '../exceptions/RequestExceptionForm'
import { createFindingTicket, fetchFinding, listFindingTickets, updateRemediationPlan } from './api'
import { findingLabel, SEVERITY_LABEL } from './labels'
import type { Finding } from './types'
const MAX_PLAN_LENGTH = 10_000

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

  if (isLoading) {
    return (
      <div className="page page-narrow">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }

  if (isError || !finding) {
    return (
      <div className="page page-narrow">
        <p className="form-error" role="alert">
          {t('findings.notFound')}
        </p>
        <Link to="/findings">{t('findings.backToBacklog')}</Link>
      </div>
    )
  }

  const heading = finding.cve_id ?? finding.title ?? t('findings.untitled')
  const canEdit = can(user?.role, 'editRemediationPlan')

  return (
    <div className="page page-narrow">
      {/* UXR-5: full drill-down path, shown whenever the user is more than two levels deep. */}
      <nav className="breadcrumb" aria-label={t('common.breadcrumb')}>
        <Link to="/findings">{t('nav.findings')}</Link>
        <IconChevronRight />
        <Link to={`/findings?application_id=${finding.application_id}`}>{finding.application_name}</Link>
        <IconChevronRight />
        <span>{finding.version_label}</span>
        {finding.component_name && (
          <>
            <IconChevronRight />
            <span className="mono">{finding.component_name}</span>
          </>
        )}
        <IconChevronRight />
        <span aria-current="page">{findingLabel(finding)}</span>
      </nav>

      <header className="detail-header">
        <div className="inline">
          <SeverityBadge tier={finding.effective_severity_tier} />
          {finding.residual_severity_tier && (
            <span className="chip chip-neutral" title={t('findings.residualTooltip')}>
              {t('findings.reducedFrom', { tier: SEVERITY_LABEL[finding.severity_tier] })}
            </span>
          )}
          <SlaBadge isOverdue={finding.is_overdue} dueDate={finding.due_date} daysUntilDue={finding.days_until_due} />
          {finding.kev_flag && (
            <span className="chip chip-kev" title={t('findings.kevTooltip')}>
              {t('findings.kevChip')}
            </span>
          )}
          <span className="chip chip-neutral">{t(`findings.statusValue.${finding.status}`)}</span>
        </div>
        <h1>{heading}</h1>
        <p className="detail-subtitle">
          {[finding.cve_id ? finding.title : null, `${finding.application_name} ${finding.version_label}`, finding.owner_team]
            .filter(Boolean)
            .join(' · ')}
        </p>
      </header>

      <FixCallout finding={finding} />

      {finding.description && <p>{finding.description}</p>}

      <section aria-labelledby="plan-heading" className="stack">
        <div>
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
        </div>
        {canEdit ? (
          // Keyed on the Finding, so moving to another Finding gives a fresh editor while
          // saving this one does not remount it (which would wipe the draft and the
          // success confirmation).
          <RemediationPlanForm key={finding.id} findingId={finding.id} initialPlan={finding.remediation_plan ?? ''} />
        ) : (
          <p>{finding.remediation_plan ?? <span className="muted">{t('findings.noPlan')}</span>}</p>
        )}
      </section>

      <div className="disclosure-group">
        <TechnicalDetails finding={finding} />
        <ExceptionsSection finding={finding} />
        <TicketsSection findingId={finding.id} />
      </div>

      <div>
        <Button onClick={() => navigate(-1)}>{t('findings.backToBacklog')}</Button>
      </div>
    </div>
  )
}

/**
 * One plain sentence on how to fix, when the data supports one: a known fixed version for
 * an SBOM component, else the vendor advisory. Pentest/SAST findings without either get
 * nothing rather than a guess.
 */
function FixCallout({ finding }: { finding: Finding }) {
  const { t } = useTranslation()

  if (finding.fixed_version) {
    return (
      <section className="fix-callout" aria-label={t('findings.howToFix')}>
        <span className="fix-callout-label">{t('findings.howToFix')}</span>
        <span>
          {finding.component_name
            ? t('findings.fixUpgrade', {
                component: finding.component_name,
                from: finding.component_version ?? '?',
                to: finding.fixed_version,
              })
            : t('findings.fixUpgradeGeneric', { to: finding.fixed_version })}
          {finding.reference_url && (
            <>
              {' · '}
              <a href={finding.reference_url} target="_blank" rel="noreferrer noopener">
                {t('findings.advisoryLink')} <IconExternal />
              </a>
            </>
          )}
        </span>
      </section>
    )
  }

  if (finding.reference_url) {
    return (
      <section className="fix-callout" aria-label={t('findings.howToFix')}>
        <span className="fix-callout-label">{t('findings.howToFix')}</span>
        <a href={finding.reference_url} target="_blank" rel="noreferrer noopener">
          {t('findings.advisoryLink')} <IconExternal />
        </a>
      </section>
    )
  }

  return null
}

function TechnicalDetails({ finding }: { finding: Finding }) {
  const { t } = useTranslation()
  const scores = [
    finding.cvss !== null ? `CVSS ${finding.cvss.toFixed(1)}` : null,
    finding.epss !== null ? `EPSS ${(finding.epss * 100).toFixed(1)}%` : null,
  ]
    .filter(Boolean)
    .join(' · ')

  return (
    <DisclosureRow title={t('findings.detailsSection')} summary={<span className="mono">{scores || finding.source.toUpperCase()}</span>}>
      <dl className="detail-grid">
        <div>
          <dt>{t('findings.source')}</dt>
          <dd>{finding.source.toUpperCase()}</dd>
        </div>
        <div>
          <dt>
            CVSS
            <InfoTip label={t('glossary.cvssLabel')}>{t('glossary.cvss')}</InfoTip>
          </dt>
          <dd className="mono">{finding.cvss?.toFixed(1) ?? '—'}</dd>
        </div>
        <div>
          <dt>
            EPSS
            <InfoTip label={t('glossary.epssLabel')}>{t('glossary.epss')}</InfoTip>
          </dt>
          <dd className="mono">{finding.epss === null ? '—' : `${(finding.epss * 100).toFixed(1)}%`}</dd>
        </div>
        <div>
          <dt>Component</dt>
          <dd className="mono">
            {finding.component_name ? `${finding.component_name} ${finding.component_version ?? ''}` : '—'}
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
          <dd>{finding.due_date ? formatDate(finding.due_date) : t('sla.bestEffort')}</dd>
        </div>
        <div>
          <dt>{t('findings.slaStartedOn')}</dt>
          <dd>{formatDate(finding.sla_started_on)}</dd>
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
        <div>
          <dt>{t('findings.vexStatus')}</dt>
          <dd className="mono">
            {finding.vex_status}
            {finding.vex_justification && <span className="cell-sub">{finding.vex_justification}</span>}
          </dd>
        </div>
        <div className="field-wide">
          <dt>{t('findings.issueKey')}</dt>
          <dd className="mono break">{finding.issue_key}</dd>
        </div>
      </dl>
    </DisclosureRow>
  )
}

/**
 * Risk exceptions covering this Finding (docs/workflows.md W3/W4). Requests are made here;
 * the Maker-Checker decision happens on the exception page so every approver sees the
 * same record. Opens by default while a request covering this Finding is pending.
 */
function ExceptionsSection({ finding }: { finding: Finding }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const navigate = useNavigate()
  const [showRequest, setShowRequest] = useState(false)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['exceptions', { finding_id: finding.id }],
    queryFn: () => listExceptions({ finding_id: finding.id, limit: 50 }),
  })

  const exceptions = data?.items ?? []
  const hasOpen = exceptions.some((e) => e.status === 'pending' || e.status === 'approved')
  const canRequest = can(user?.role, 'requestException') && finding.status === 'open' && !hasOpen
  const latest = exceptions[0]

  if (isLoading) {
    return (
      <DisclosureRow title={t('exceptions.sectionTitle')} summary={t('common.loading')}>
        <p role="status">{t('common.loading')}</p>
      </DisclosureRow>
    )
  }

  return (
    <DisclosureRow
      title={t('exceptions.sectionTitle')}
      summary={latest ? <ExceptionStatusBadge status={latest.status} /> : t('exceptions.none')}
      defaultOpen={exceptions.some((e) => e.status === 'pending')}
    >
      <p className="field-hint">{t('exceptions.sectionHint')}</p>
      {isError && (
        <p className="form-error" role="alert">
          {t('exceptions.loadError')}
        </p>
      )}

      {exceptions.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">{t('exceptions.reference')}</th>
                <th scope="col">{t('exceptions.statusLabel')}</th>
                <th scope="col">{t('exceptions.approvals')}</th>
                <th scope="col">{t('exceptions.expiresOn')}</th>
                <th scope="col">{t('exceptions.requestedBy')}</th>
              </tr>
            </thead>
            <tbody>
              {exceptions.map((exception) => (
                <tr key={exception.id}>
                  <td>
                    <Link to={`/exceptions/${exception.id}`} className="mono">
                      {exception.reference}
                    </Link>
                    <span className="cell-sub">{t(`exceptions.type.${exception.exception_type}`)}</span>
                  </td>
                  <td>
                    <ExceptionStatusBadge status={exception.status} />
                  </td>
                  <td className="mono">
                    {exception.approvals.filter((a) => a.decision === 'approve').length}/
                    {exception.required_approvals}
                  </td>
                  <td className="nowrap">{formatDate(exception.expires_on)}</td>
                  <td>{exception.requested_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {canRequest && (
        <div>
          <Button small onClick={() => setShowRequest(true)}>
            <IconPlus />
            {t('exceptions.request')}
          </Button>
        </div>
      )}

      <Modal
        open={showRequest}
        onClose={() => setShowRequest(false)}
        title={t('exceptions.request')}
        description={t('exceptions.requestHint')}
      >
        <RequestExceptionForm
          finding={finding}
          onCancel={() => setShowRequest(false)}
          onDone={(created) => navigate(`/exceptions/${created.id}`)}
        />
      </Modal>
    </DisclosureRow>
  )
}

/**
 * ITSM tickets cross-reference (FR-7.4) plus a manual "Create Ticket" action (FR-7.8)
 * for the edge cases automatic routing doesn't cover — AppSec/Admin only, matching the
 * backend's `POST /findings/{id}/tickets`.
 */
function TicketsSection({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const [showCreate, setShowCreate] = useState(false)
  const queryClient = useQueryClient()

  const { data: tickets, isLoading, isError } = useQuery({
    queryKey: ['finding-tickets', findingId],
    queryFn: () => listFindingTickets(findingId),
  })

  const canCreate = can(user?.role, 'createTicket')
  const first = tickets?.[0]

  return (
    <DisclosureRow
      title={t('tickets.sectionTitle')}
      summary={
        first ? (
          <span className="mono">{[first.external_id, first.status].filter(Boolean).join(' · ')}</span>
        ) : (
          t('tickets.none')
        )
      }
    >
      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('tickets.loadError')}
        </p>
      )}
      {tickets && tickets.length === 0 && <p className="field-hint">{t('tickets.empty')}</p>}

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
                  <td className="nowrap">{formatDateTime(ticket.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {canCreate && (
        <div>
          <Button small onClick={() => setShowCreate(true)}>
            <IconPlus />
            {t('tickets.createTicket')}
          </Button>
        </div>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title={t('tickets.createTicket')}>
        <CreateTicketForm
          findingId={findingId}
          onCancel={() => setShowCreate(false)}
          onDone={() => {
            setShowCreate(false)
            queryClient.invalidateQueries({ queryKey: ['finding-tickets', findingId] })
          }}
        />
      </Modal>
    </DisclosureRow>
  )
}

function CreateTicketForm({
  findingId,
  onCancel,
  onDone,
}: {
  findingId: string
  onCancel: () => void
  onDone: () => void
}) {
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

  const message = validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('tickets.createFailed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorSummaryRef} title={t('tickets.createErrorSummary')} message={message} />}
      <FormField label={t('tickets.connector')}>
        <SelectBox
          value={connectorId}
          onChange={setConnectorId}
          disabled={isLoading}
          placeholder={t('tickets.selectConnector')}
          options={(connectors ?? []).map((connector) => ({ value: connector.id, label: connector.name }))}
        />
      </FormField>
      <div className="modal-actions">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('tickets.createTicket')}
        </Button>
      </div>
    </form>
  )
}

/**
 * Remediation plan editor (FR-10.2, UXR-7).
 *
 * Owns only its draft text. The parent remounts it when the Finding changes, so server
 * state stays the single source of truth without an effect copying it down.
 */
function RemediationPlanForm({ findingId, initialPlan }: { findingId: string; initialPlan: string }) {
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
    <form className="stack" onSubmit={handleSubmit} noValidate>
      {(validationError || mutation.isError) && (
        <ErrorSummary
          ref={errorSummaryRef}
          title={t('findings.planErrorSummary')}
          message={<a href="#remediation-plan">{validationError ?? t('findings.planSaveFailed')}</a>}
        />
      )}
      <FormField label={t('findings.planLabel')} hint={t('findings.planHint')}>
        <TextArea
          id="remediation-plan"
          value={plan}
          rows={4}
          maxLength={MAX_PLAN_LENGTH}
          invalid={Boolean(validationError)}
          onChange={(event) => {
            setPlan(event.target.value)
            setValidationError(null)
            setSaved(false)
          }}
        />
      </FormField>
      <div className="form-actions">
        {/* UXR-7: disabled while in flight, so a second click cannot duplicate the write. */}
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('findings.savePlan')}
        </Button>
        {saved && (
          <span className="form-success" role="status">
            {t('findings.planSaved')}
          </span>
        )}
      </div>
    </form>
  )
}
