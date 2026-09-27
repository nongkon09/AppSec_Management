/**
 * Exception register (docs/workflows.md W3). Checkers land on "awaiting me"; DevOps looks
 * a reference up before a manual bypass.
 */
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Field, Label } from '@headlessui/react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { SeverityBadge } from '../../components/SeverityBadge'
import { Button, FormField, PillGroup, SelectBox, TextInput } from '../../components/ui'
import { formatDate } from '../../lib/format'
import { can } from '../../lib/rbac'
import { useAuth } from '../auth/context'
import { fetchExceptionByReference, listExceptions } from './api'
import { ExceptionStatusBadge } from './ExceptionBadges'
import type { ExceptionStatus } from './types'

type View = 'awaiting' | 'mine' | 'all'
const STATUSES: ExceptionStatus[] = [
  'pending',
  'approved',
  'rejected',
  'withdrawn',
  'expired',
  'revoked',
  'closed',
]

export function ExceptionsPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const canDecide = can(user?.role, 'decideException')
  const view = (searchParams.get('view') as View | null) ?? (canDecide ? 'awaiting' : 'all')
  const status = (searchParams.get('status') ?? '') as ExceptionStatus | ''
  const [reference, setReference] = useState('')
  const [lookupError, setLookupError] = useState<string | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['exceptions', { view, status }],
    queryFn: () =>
      listExceptions({
        awaiting_me: view === 'awaiting',
        mine: view === 'mine',
        status: view !== 'awaiting' && status ? [status] : undefined,
        limit: 200,
      }),
  })

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(searchParams)
    if (value) next.set(key, value)
    else next.delete(key)
    setSearchParams(next, { replace: true })
  }

  async function lookup(event: FormEvent) {
    event.preventDefault()
    setLookupError(null)
    if (!reference.trim()) return
    try {
      const found = await fetchExceptionByReference(reference)
      navigate(`/exceptions/${found.id}`)
    } catch {
      setLookupError(t('exceptions.lookupNotFound', { reference: reference.trim().toUpperCase() }))
    }
  }

  const views: { value: View; label: string }[] = [
    ...(canDecide ? [{ value: 'awaiting' as View, label: t('exceptions.view.awaiting') }] : []),
    { value: 'mine', label: t('exceptions.view.mine') },
    { value: 'all', label: t('exceptions.view.all') },
  ]

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>
            {t('exceptions.title')}
            {data && <span className="count">{data.total}</span>}
          </h1>
          <p className="page-sub">{t('exceptions.subtitle')}</p>
        </div>
        <form className="toolbar" onSubmit={lookup}>
          <Field className="field">
            <Label className="visually-hidden">{t('exceptions.lookupLabel')}</Label>
            <TextInput
              value={reference}
              placeholder="EXC-2026-0001"
              onChange={(e) => setReference(e.target.value)}
              className="mono"
            />
          </Field>
          <Button type="submit">{t('exceptions.lookup')}</Button>
        </form>
      </div>
      {lookupError && (
        <p className="form-error" role="alert">
          {lookupError}
        </p>
      )}

      <div className="toolbar">
        <PillGroup
          ariaLabel={t('exceptions.viewLabel')}
          value={view}
          onChange={(value) => setParam('view', value)}
          options={views}
        />
        {view !== 'awaiting' && (
          <FormField label={t('exceptions.statusLabel')}>
            <SelectBox
              value={status}
              onChange={(value) => setParam('status', value)}
              options={[
                { value: '' as const, label: t('exceptions.allStatuses') },
                ...STATUSES.map((s) => ({ value: s, label: t(`exceptions.status.${s}`) })),
              ]}
            />
          </FormField>
        )}
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('exceptions.loadError')}
        </p>
      )}
      {data && data.items.length === 0 && (
        <p className="empty-state">
          {view === 'awaiting' ? t('exceptions.emptyAwaiting') : t('exceptions.empty')}
        </p>
      )}

      {data && data.items.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="sticky-column">
                  {t('exceptions.reference')}
                </th>
                <th scope="col">{t('exceptions.covers')}</th>
                <th scope="col">Severity</th>
                <th scope="col">{t('exceptions.statusLabel')}</th>
                <th scope="col">{t('exceptions.approvals')}</th>
                <th scope="col">{t('exceptions.expiresOn')}</th>
                <th scope="col">{t('exceptions.requestedBy')}</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((exception) => {
                const approvals = exception.approvals.filter((a) => a.decision === 'approve').length
                const first = exception.items[0]
                return (
                  <tr key={exception.id}>
                    <th scope="row" className="sticky-column">
                      <Link to={`/exceptions/${exception.id}`} className="mono">
                        {exception.reference}
                      </Link>
                      <span className="cell-sub">{t(`exceptions.type.${exception.exception_type}`)}</span>
                    </th>
                    <td>
                      {first?.label}
                      <span className="cell-sub">
                        {first?.application_name}
                        {exception.items.length > 1 &&
                          ` · ${t('exceptions.moreItems', { count: exception.items.length - 1 })}`}
                      </span>
                    </td>
                    <td>
                      <div className="cell-chips">
                        <SeverityBadge tier={exception.original_severity_tier} />
                        {exception.residual_severity_tier && (
                          <>
                            <span className="muted">→</span>
                            <SeverityBadge tier={exception.residual_severity_tier} />
                          </>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="cell-chips">
                        <ExceptionStatusBadge status={exception.status} />
                        {exception.needs_review && (
                          <span className="chip chip-sla-overdue">{t('exceptions.needsReview')}</span>
                        )}
                        {exception.is_legacy && <span className="chip chip-neutral">legacy</span>}
                      </div>
                    </td>
                    <td className="mono">
                      {approvals}/{exception.required_approvals}
                    </td>
                    <td className="nowrap">{formatDate(exception.expires_on)}</td>
                    <td>{exception.requested_by}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
