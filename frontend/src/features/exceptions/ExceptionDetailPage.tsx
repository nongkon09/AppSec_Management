/**
 * One exception, end to end (docs/workflows.md W3-W6): what it covers, why, who approved,
 * and every bypass DevOps recorded against it. The action panel shows only what the
 * current user may do; the server re-checks each step.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { SeverityBadge } from '../../components/SeverityBadge'
import { Button, FormField, Modal, SelectBox, TextArea, TextInput } from '../../components/ui'
import { formatDate, formatDateTime } from '../../lib/format'
import { IconChevronRight } from '../../lib/icons'
import { can } from '../../lib/rbac'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { useAuth } from '../auth/context'
import { decideException, endException, fetchException, recordBypass } from './api'
import { ExceptionStatusBadge } from './ExceptionBadges'
import { BYPASS_TOOLS } from './types'
import type { BypassTool, RiskException } from './types'

export function ExceptionDetailPage() {
  const { t } = useTranslation()
  const { exceptionId } = useParams<{ exceptionId: string }>()
  const { data: exception, isLoading, isError } = useQuery({
    queryKey: ['exception', exceptionId],
    queryFn: () => fetchException(exceptionId!),
    enabled: Boolean(exceptionId),
  })

  if (isLoading) {
    return (
      <div className="page page-narrow">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }
  if (isError || !exception) {
    return (
      <div className="page page-narrow">
        <p className="form-error" role="alert">
          {t('exceptions.notFound')}
        </p>
        <Link to="/exceptions">{t('exceptions.backToList')}</Link>
      </div>
    )
  }

  const approvals = exception.approvals.filter((a) => a.decision === 'approve')
  const remaining = Math.max(exception.required_approvals - approvals.length, 0)

  return (
    <div className="page page-narrow">
      <nav className="breadcrumb" aria-label={t('common.breadcrumb')}>
        <Link to="/exceptions">{t('exceptions.title')}</Link>
        <IconChevronRight />
        <span aria-current="page" className="mono">
          {exception.reference}
        </span>
      </nav>

      <header className="detail-header">
        <div className="inline">
          <ExceptionStatusBadge status={exception.status} />
          <span className="chip chip-neutral">{t(`exceptions.type.${exception.exception_type}`)}</span>
          {exception.needs_review && (
            <span className="chip chip-sla-overdue">{t('exceptions.needsReview')}</span>
          )}
          {exception.is_legacy && (
            <span className="chip chip-neutral" title={t('exceptions.legacyHint')}>
              legacy
            </span>
          )}
        </div>
        <h1 className="mono">{exception.reference}</h1>
        <p className="detail-subtitle">
          {t('exceptions.requestedByOn', {
            user: exception.requested_by,
            at: formatDateTime(exception.created_at),
          })}
        </p>
      </header>

      <ActionPanel exception={exception} />

      <section className="card card-pad stack">
        <dl className="detail-grid">
          <div>
            <dt>{t('exceptions.originalSeverity')}</dt>
            <dd className="inline">
              <SeverityBadge tier={exception.original_severity_tier} />
              {exception.kev_involved && <span className="chip chip-kev">KEV</span>}
            </dd>
          </div>
          <div>
            <dt>{t('exceptions.residualSeverity')}</dt>
            <dd>
              {exception.residual_severity_tier ? (
                <SeverityBadge tier={exception.residual_severity_tier} />
              ) : (
                <span className="muted">{t('exceptions.noResidual')}</span>
              )}
            </dd>
          </div>
          <div>
            <dt>
              {exception.exception_type === 'risk_acceptance'
                ? t('exceptions.expiresOn')
                : t('exceptions.reviewOn')}
            </dt>
            <dd>{formatDate(exception.expires_on)}</dd>
          </div>
          <div>
            <dt>{t('exceptions.requirement')}</dt>
            <dd>
              {t(exception.required_approvals === 1 ? 'exceptions.requirementSingle' : 'exceptions.requirementMulti', {
                count: exception.required_approvals,
                min: exception.required_min_level.toUpperCase(),
                top: exception.required_top_level.toUpperCase(),
              })}
            </dd>
          </div>
          {exception.vex_justification && (
            <div>
              <dt>VEX justification</dt>
              <dd className="mono">{exception.vex_justification}</dd>
            </div>
          )}
        </dl>
        <div>
          <h2 className="section-title">{t('exceptions.reason')}</h2>
          <p className="prewrap">{exception.reason}</p>
        </div>
        {exception.evidence && (
          <div>
            <h2 className="section-title">{t('exceptions.evidence')}</h2>
            <p className="prewrap">{exception.evidence}</p>
          </div>
        )}
        {(exception.controls.length > 0 || exception.compensating_measures) && (
          <div>
            <h2 className="section-title">{t('exceptions.controls')}</h2>
            <div className="cell-chips">
              {exception.controls.map((control) => (
                <span key={control.id} className="chip chip-neutral">
                  {control.name} · {t(`controls.effectiveness.${control.effectiveness}`)}
                </span>
              ))}
            </div>
            {exception.compensating_measures && <p className="prewrap">{exception.compensating_measures}</p>}
          </div>
        )}
      </section>

      <section>
        <h2 className="section-title">{t('exceptions.covers')}</h2>
        <div className="list">
          {exception.items.map((item) => (
            <div key={`${item.application_id}:${item.issue_key}`} className="list-row">
              <span className="list-row-main">
                {item.origin_finding_id ? (
                  <Link to={`/findings/${item.origin_finding_id}`} className="list-row-title">
                    {item.label}
                  </Link>
                ) : (
                  <span className="list-row-title">{item.label}</span>
                )}
                <span className="list-row-sub">
                  {item.application_name} · <span className="mono">{item.issue_key}</span>
                </span>
              </span>
            </div>
          ))}
        </div>
        <p className="field-hint">{t('exceptions.coversHint')}</p>
      </section>

      <section>
        <h2 className="section-title">{t('exceptions.approvals')}</h2>
        {exception.approvals.length === 0 ? (
          <p className="field-hint">{t('exceptions.noDecisions')}</p>
        ) : (
          <div className="list">
            {exception.approvals.map((approval) => (
              <div key={approval.approver} className="list-row">
                <span
                  className={approval.decision === 'approve' ? 'chip chip-sla-within' : 'chip chip-sla-overdue'}
                >
                  {t(`exceptions.decision.${approval.decision}`)}
                </span>
                <span className="list-row-main">
                  <span className="list-row-title">
                    {approval.approver}{' '}
                    <span className="muted mono">{approval.approver_level.toUpperCase()}</span>
                  </span>
                  {approval.comment && <span className="list-row-sub">{approval.comment}</span>}
                </span>
                <span className="muted nowrap">{formatDateTime(approval.decided_at)}</span>
              </div>
            ))}
          </div>
        )}
        {exception.status === 'pending' && remaining > 0 && (
          <p className="field-hint">{t('exceptions.remaining', { count: remaining })}</p>
        )}
        {exception.ended_reason && (
          <p className="detail-meta">
            {t('exceptions.endedBy', { user: exception.ended_by, reason: exception.ended_reason })}
          </p>
        )}
      </section>

      <section>
        <h2 className="section-title">{t('exceptions.bypasses')}</h2>
        {exception.bypasses.length === 0 ? (
          <p className="field-hint">{t('exceptions.noBypasses')}</p>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">{t('exceptions.bypassTool')}</th>
                  <th scope="col">{t('exceptions.bypassBy')}</th>
                  <th scope="col">{t('exceptions.bypassAt')}</th>
                  <th scope="col">{t('exceptions.bypassRef')}</th>
                </tr>
              </thead>
              <tbody>
                {exception.bypasses.map((bypass) => (
                  <tr key={`${bypass.recorded_by}-${bypass.bypassed_at}`}>
                    <td className="mono">{bypass.tool}</td>
                    <td>{bypass.recorded_by}</td>
                    <td className="nowrap">{formatDateTime(bypass.bypassed_at)}</td>
                    <td>
                      {bypass.reference_url ? (
                        <a href={bypass.reference_url} target="_blank" rel="noreferrer noopener">
                          {bypass.reference_url}
                        </a>
                      ) : (
                        <span className="muted">—</span>
                      )}
                      {bypass.note && <span className="cell-sub">{bypass.note}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

function ActionPanel({ exception }: { exception: RiskException }) {
  const { t } = useTranslation()
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [comment, setComment] = useState('')
  const [dialog, setDialog] = useState<'withdraw' | 'revoke' | 'bypass' | null>(null)

  function refresh(updated: RiskException) {
    queryClient.setQueryData(['exception', exception.id], updated)
    queryClient.invalidateQueries({ queryKey: ['exceptions'] })
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    queryClient.invalidateQueries({ queryKey: ['finding'] })
    queryClient.invalidateQueries({ queryKey: ['backlog-summary'] })
  }

  const decision = useMutation({
    mutationFn: (action: 'approve' | 'reject') =>
      decideException(exception.id, action, comment.trim() || null),
    onSuccess: (updated) => {
      setComment('')
      refresh(updated)
    },
  })

  const isPending = exception.status === 'pending'
  const isApproved = exception.status === 'approved'
  const isMaker = user?.username === exception.requested_by
  const mayDecide = can(user?.role, 'decideException')

  const panels = []
  if (isPending && mayDecide) {
    panels.push(
      exception.can_approve ? (
        <form
          key="decide"
          className="stack"
          onSubmit={(event: FormEvent) => {
            event.preventDefault()
            decision.mutate('approve')
          }}
        >
          <FormField label={t('exceptions.comment')} hint={t('exceptions.commentHint')}>
            <TextArea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} />
          </FormField>
          {decision.isError && (
            <p className="form-error" role="alert">
              {apiErrorMessage(decision.error, t('exceptions.decideFailed'))}
            </p>
          )}
          <div className="form-actions">
            <Button type="submit" variant="primary" disabled={decision.isPending}>
              {t('exceptions.approve')}
            </Button>
            <Button
              disabled={decision.isPending || !comment.trim()}
              title={!comment.trim() ? t('exceptions.rejectNeedsReason') : undefined}
              onClick={() => decision.mutate('reject')}
            >
              {t('exceptions.reject')}
            </Button>
          </div>
        </form>
      ) : (
        <p key="refusal" className="field-hint">
          {t('exceptions.cannotDecide')}: {exception.approve_refusal}
        </p>
      ),
    )
  }
  const buttons = []
  if (isPending && isMaker) {
    buttons.push(
      <Button key="withdraw" small onClick={() => setDialog('withdraw')}>
        {t('exceptions.withdraw')}
      </Button>,
    )
  }
  if (isApproved && can(user?.role, 'recordBypass')) {
    buttons.push(
      <Button key="bypass" small variant="primary" onClick={() => setDialog('bypass')}>
        {t('exceptions.recordBypass')}
      </Button>,
    )
  }
  if (isApproved && can(user?.role, 'revokeException') && user?.approval_level !== 'none') {
    buttons.push(
      <Button key="revoke" small onClick={() => setDialog('revoke')}>
        {t('exceptions.revoke')}
      </Button>,
    )
  }
  if (panels.length === 0 && buttons.length === 0) return null

  return (
    <section className="card card-pad stack" aria-label={t('exceptions.actions')}>
      {panels}
      {buttons.length > 0 && <div className="form-actions">{buttons}</div>}

      <Modal
        open={dialog === 'withdraw' || dialog === 'revoke'}
        onClose={() => setDialog(null)}
        title={dialog === 'revoke' ? t('exceptions.revoke') : t('exceptions.withdraw')}
        description={dialog === 'revoke' ? t('exceptions.revokeHint') : t('exceptions.withdrawHint')}
      >
        <EndForm
          action={dialog === 'revoke' ? 'revoke' : 'withdraw'}
          exceptionId={exception.id}
          onCancel={() => setDialog(null)}
          onDone={(updated) => {
            setDialog(null)
            refresh(updated)
          }}
        />
      </Modal>
      <Modal
        open={dialog === 'bypass'}
        onClose={() => setDialog(null)}
        title={t('exceptions.recordBypass')}
        description={t('exceptions.bypassHint', { reference: exception.reference })}
      >
        <BypassForm
          exceptionId={exception.id}
          onCancel={() => setDialog(null)}
          onDone={(updated) => {
            setDialog(null)
            refresh(updated)
          }}
        />
      </Modal>
    </section>
  )
}

function EndForm({
  action,
  exceptionId,
  onCancel,
  onDone,
}: {
  action: 'withdraw' | 'revoke'
  exceptionId: string
  onCancel: () => void
  onDone: (updated: RiskException) => void
}) {
  const { t } = useTranslation()
  const [reason, setReason] = useState('')
  const mutation = useMutation({
    mutationFn: () => endException(exceptionId, action, reason.trim()),
    onSuccess: onDone,
  })
  return (
    <form
      onSubmit={(event: FormEvent) => {
        event.preventDefault()
        mutation.mutate()
      }}
      noValidate
    >
      <FormField label={t('exceptions.endReason')}>
        <TextArea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
      </FormField>
      {mutation.isError && (
        <p className="form-error" role="alert">
          {apiErrorMessage(mutation.error, t('exceptions.decideFailed'))}
        </p>
      )}
      <div className="modal-actions">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button
          type="submit"
          variant={action === 'revoke' ? 'danger' : 'primary'}
          disabled={mutation.isPending || reason.trim().length < 5}
        >
          {action === 'revoke' ? t('exceptions.revoke') : t('exceptions.withdraw')}
        </Button>
      </div>
    </form>
  )
}

function BypassForm({
  exceptionId,
  onCancel,
  onDone,
}: {
  exceptionId: string
  onCancel: () => void
  onDone: (updated: RiskException) => void
}) {
  const { t } = useTranslation()
  const [tool, setTool] = useState<BypassTool>('harbor')
  const [url, setUrl] = useState('')
  const [note, setNote] = useState('')
  const mutation = useMutation({
    mutationFn: () =>
      recordBypass(exceptionId, { tool, reference_url: url.trim() || null, note: note.trim() || null }),
    onSuccess: onDone,
  })
  return (
    <form
      onSubmit={(event: FormEvent) => {
        event.preventDefault()
        mutation.mutate()
      }}
      noValidate
    >
      <FormField label={t('exceptions.bypassTool')}>
        <SelectBox
          value={tool}
          onChange={setTool}
          options={BYPASS_TOOLS.map((value) => ({ value, label: t(`exceptions.tool.${value}`) }))}
        />
      </FormField>
      <FormField label={t('exceptions.bypassRef')}>
        <TextInput
          value={url}
          placeholder="https://ci.example.com/pipelines/1432"
          onChange={(e) => setUrl(e.target.value)}
        />
      </FormField>
      <FormField label={t('exceptions.bypassNote')}>
        <TextArea rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
      </FormField>
      {mutation.isError && (
        <p className="form-error" role="alert">
          {apiErrorMessage(mutation.error, t('exceptions.decideFailed'))}
        </p>
      )}
      <div className="modal-actions">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {t('exceptions.recordBypass')}
        </Button>
      </div>
    </form>
  )
}
