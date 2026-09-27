/**
 * Audit Trail view + export (Requirement.md FR-10.4, FR-11.1, FR-11.2).
 *
 * Read-only on purpose: an immutable trail is what Internal Audit and the regulator rely on,
 * so there is no edit affordance anywhere on this screen. Before/after values are shown
 * inline so a policy or plan change can be reviewed without a second lookup.
 */
import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button, FormField, SelectBox, TextInput } from '../../components/ui'
import { formatDateTime } from '../../lib/format'
import { IconDownload } from '../../lib/icons'
import { downloadAuditExport, listAuditLogs } from './api'
import type { AuditFilters } from './api'

const PAGE_SIZE = 100

function formatValue(value: Record<string, unknown> | null): string {
  if (!value) return '—'
  return Object.entries(value)
    .map(([key, item]) => `${key}: ${typeof item === 'object' ? JSON.stringify(item) : String(item)}`)
    .join('\n')
}

export function AuditTrailPage() {
  const { t } = useTranslation()
  const [filters, setFilters] = useState<AuditFilters>({})

  const { data, isLoading, isError } = useQuery({
    queryKey: ['audit-logs', filters],
    queryFn: () => listAuditLogs({ ...filters, limit: PAGE_SIZE }),
  })

  const exportMutation = useMutation({
    mutationFn: () => downloadAuditExport(filters),
  })

  function updateFilter(key: keyof AuditFilters, value: string) {
    setFilters((previous) => {
      const next = { ...previous }
      if (value) {
        next[key] = value as never
      } else {
        delete next[key]
      }
      return next
    })
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>{t('audit.title')}</h1>
          <p className="page-sub">{t('audit.immutabilityNote')}</p>
        </div>
        <Button onClick={() => exportMutation.mutate()} disabled={exportMutation.isPending}>
          <IconDownload />
          {exportMutation.isPending ? t('common.saving') : t('audit.exportCsv')}
        </Button>
      </div>

      <section className="toolbar" aria-label={t('audit.filtersLabel')}>
        <FormField label={t('audit.dateFrom')}>
          <TextInput
            type="date"
            value={filters.date_from ?? ''}
            onChange={(event) => updateFilter('date_from', event.target.value)}
          />
        </FormField>
        <FormField label={t('audit.dateTo')}>
          <TextInput
            type="date"
            value={filters.date_to ?? ''}
            onChange={(event) => updateFilter('date_to', event.target.value)}
          />
        </FormField>
        <FormField label={t('audit.entityType')}>
          <SelectBox
            value={filters.entity_type ?? ''}
            onChange={(value) => updateFilter('entity_type', value)}
            options={[
              { value: '', label: t('audit.allEntities') },
              { value: 'policy_set', label: 'policy_set' },
              { value: 'finding', label: 'finding' },
              { value: 'application', label: 'application' },
            ]}
          />
        </FormField>
        <FormField label={t('audit.actor')} className="toolbar-grow">
          <TextInput
            type="search"
            value={filters.actor ?? ''}
            onChange={(event) => updateFilter('actor', event.target.value)}
          />
        </FormField>
      </section>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('audit.loadError')}
        </p>
      )}
      {exportMutation.isError && (
        <p className="form-error" role="alert">
          {t('audit.exportFailed')}
        </p>
      )}

      {data && (
        <>
          <p className="result-count" role="status">
            {t('audit.resultCount', { count: data.total })}
          </p>
          {data.items.length === 0 ? (
            <p className="empty-state">{t('audit.empty')}</p>
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">{t('audit.timestamp')}</th>
                    <th scope="col">{t('audit.actor')}</th>
                    <th scope="col">{t('audit.action')}</th>
                    <th scope="col">{t('audit.entity')}</th>
                    <th scope="col">{t('audit.before')}</th>
                    <th scope="col">{t('audit.after')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((entry) => (
                    <tr key={entry.id}>
                      <td className="nowrap">{formatDateTime(entry.timestamp)}</td>
                      <td>{entry.actor}</td>
                      <td className="mono">{entry.action}</td>
                      <td className="mono">
                        {entry.entity_type}
                        <span className="cell-sub mono">{entry.entity_id.slice(0, 8)}</span>
                      </td>
                      <td className="mono audit-value">{formatValue(entry.before_value)}</td>
                      <td className="mono audit-value">{formatValue(entry.after_value)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {data.total > PAGE_SIZE && (
            <p className="field-hint">{t('audit.truncatedNote', { shown: PAGE_SIZE })}</p>
          )}
        </>
      )}
    </div>
  )
}
