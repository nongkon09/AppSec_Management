/**
 * Vulnerability backlog (Requirement.md FR-5.4, FR-10.2).
 *
 * Filter state lives in the URL query string rather than in component state. That is what
 * makes UXR-5 work: returning from a Finding detail page restores the exact filtered list
 * the user drilled down from, and a filtered backlog can be shared or bookmarked.
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'
import { SeverityBadge, SeverityLegend, SlaBadge } from '../../components/SeverityBadge'
import { IconCode, IconPackage, IconTarget } from '../../lib/icons'
import { listFindings } from './api'
import type { Finding, FindingSource, FindingStatus, SeverityTier, SlaStatusFilter } from './types'

const PAGE_SIZE = 50
const SEVERITY_TIERS: SeverityTier[] = ['critical', 'high', 'medium', 'low']
const SOURCES: FindingSource[] = ['sbom', 'sast', 'pentest']
const STATUSES: FindingStatus[] = ['open', 'fixed', 'risk_accepted', 'suppressed']

const SOURCE_ICON = {
  sbom: IconPackage,
  sast: IconCode,
  pentest: IconTarget,
} as const

function SourceChip({ source }: { source: FindingSource }) {
  const IconComponent = SOURCE_ICON[source]
  return (
    <span className="chip chip-source">
      <IconComponent />
      {source.toUpperCase()}
    </span>
  )
}

/** Identifies a Finding: a CVE where there is one, otherwise its title (FR-6.5.5). */
function findingLabel(finding: Finding): string {
  return finding.cve_id ?? finding.title ?? finding.id
}

export function FindingsBacklogPage() {
  const { t } = useTranslation()
  const [searchParams, setSearchParams] = useSearchParams()

  const severity = searchParams.getAll('severity') as SeverityTier[]
  const status = searchParams.getAll('finding_status') as FindingStatus[]
  const source = (searchParams.get('source') ?? undefined) as FindingSource | undefined
  const slaStatus = (searchParams.get('sla_status') ?? undefined) as SlaStatusFilter | undefined
  const applicationId = searchParams.get('application_id') ?? undefined
  const search = searchParams.get('search') ?? ''
  const page = Number(searchParams.get('page') ?? '1')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['findings', { severity, status, source, slaStatus, applicationId, search, page }],
    queryFn: () =>
      listFindings({
        severity: severity.length > 0 ? severity : undefined,
        finding_status: status.length > 0 ? status : undefined,
        source,
        sla_status: slaStatus,
        application_id: applicationId,
        search: search || undefined,
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
      }),
  })

  /** Writes one filter into the URL, resetting pagination. */
  function updateParam(key: string, value: string | string[] | undefined) {
    const next = new URLSearchParams(searchParams)
    next.delete(key)
    next.delete('page')
    if (Array.isArray(value)) {
      value.forEach((item) => next.append(key, item))
    } else if (value) {
      next.set(key, value)
    }
    setSearchParams(next, { replace: true })
  }

  function toggleSeverity(tier: SeverityTier) {
    updateParam(
      'severity',
      severity.includes(tier) ? severity.filter((item) => item !== tier) : [...severity, tier],
    )
  }

  const activeFilterCount =
    severity.length +
    status.length +
    (source ? 1 : 0) +
    (slaStatus ? 1 : 0) +
    (applicationId ? 1 : 0)
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <div className="page">
      <h1>{t('findings.title')}</h1>

      <section className="filter-bar" aria-label={t('findings.filtersLabel')}>
        <fieldset className="filter-group">
          <legend>{t('findings.severity')}</legend>
          {SEVERITY_TIERS.map((tier) => (
            // Checkboxes rather than a multi-select: the state of every option is visible
            // at once and each is individually keyboard-reachable (UXR-9).
            <label key={tier} className="filter-chip">
              <input
                type="checkbox"
                checked={severity.includes(tier)}
                onChange={() => toggleSeverity(tier)}
              />
              <SeverityBadge tier={tier} />
            </label>
          ))}
        </fieldset>

        <div className="filter-group">
          <label htmlFor="filter-sla">{t('findings.slaStatus')}</label>
          <select
            id="filter-sla"
            value={slaStatus ?? ''}
            onChange={(event) => updateParam('sla_status', event.target.value || undefined)}
          >
            <option value="">{t('findings.allStatuses')}</option>
            <option value="overdue">{t('sla.overdue')}</option>
            <option value="within_sla">{t('sla.withinSla')}</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="filter-status">{t('findings.status')}</label>
          <select
            id="filter-status"
            value={status[0] ?? ''}
            onChange={(event) =>
              updateParam('finding_status', event.target.value ? [event.target.value] : undefined)
            }
          >
            <option value="">{t('findings.allStatuses')}</option>
            {STATUSES.map((item) => (
              <option key={item} value={item}>
                {t(`findings.statusValue.${item}`)}
              </option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="filter-source">{t('findings.source')}</label>
          <select
            id="filter-source"
            value={source ?? ''}
            onChange={(event) => updateParam('source', event.target.value || undefined)}
          >
            <option value="">{t('findings.allSources')}</option>
            {SOURCES.map((item) => (
              <option key={item} value={item}>
                {item.toUpperCase()}
              </option>
            ))}
          </select>
        </div>

        <div className="filter-group filter-group-grow">
          <label htmlFor="filter-search">{t('findings.search')}</label>
          <input
            id="filter-search"
            type="search"
            value={search}
            placeholder={t('findings.searchPlaceholder')}
            onChange={(event) => updateParam('search', event.target.value || undefined)}
          />
        </div>

        {activeFilterCount > 0 && (
          <button type="button" className="button-secondary" onClick={() => setSearchParams({})}>
            {t('findings.clearFilters', { count: activeFilterCount })}
          </button>
        )}
      </section>

      <SeverityLegend />

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('findings.loadError')}
        </p>
      )}

      {data && (
        <>
          <p className="result-count" role="status">
            {t('findings.resultCount', { count: data.total })}
          </p>

          {data.items.length === 0 ? (
            <p className="empty-state">{t('findings.empty')}</p>
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col" className="sticky-column">
                      {t('findings.vulnerability')}
                    </th>
                    <th scope="col">{t('findings.severity')}</th>
                    <th scope="col">{t('findings.status')}</th>
                    <th scope="col">{t('findings.slaStatus')}</th>
                    <th scope="col">{t('inventory.appName')}</th>
                    <th scope="col">{t('findings.component')}</th>
                    <th scope="col" className="numeric">
                      CVSS
                    </th>
                    <th scope="col" className="numeric">
                      EPSS
                    </th>
                    <th scope="col">{t('findings.source')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((finding) => (
                    <tr key={finding.id}>
                      <th scope="row" className="sticky-column">
                        <Link to={`/findings/${finding.id}`}>{findingLabel(finding)}</Link>
                        {finding.kev_flag && (
                          // FR-4.1: KEV means confirmed exploitation in the wild — the
                          // single most important signal on the row.
                          <span className="chip chip-kev" title={t('findings.kevTooltip')}>
                            KEV
                          </span>
                        )}
                      </th>
                      <td>
                        <SeverityBadge tier={finding.severity_tier} />
                      </td>
                      <td>
                        <span className="chip chip-neutral">
                          {t(`findings.statusValue.${finding.status}`)}
                        </span>
                      </td>
                      <td>
                        <SlaBadge
                          isOverdue={finding.is_overdue}
                          dueDate={finding.due_date}
                          daysUntilDue={finding.days_until_due}
                        />
                      </td>
                      <td>
                        {finding.application_name}
                        <span className="cell-sub">{finding.version_label}</span>
                      </td>
                      <td>
                        {finding.component_name ? (
                          <>
                            <span className="mono">{finding.component_name}</span>
                            <span className="cell-sub mono">{finding.component_version}</span>
                          </>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="numeric mono">{finding.cvss?.toFixed(1) ?? '—'}</td>
                      <td className="numeric mono">
                        {finding.epss === null ? '—' : `${(finding.epss * 100).toFixed(1)}%`}
                      </td>
                      <td>
                        <SourceChip source={finding.source} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {totalPages > 1 && (
            <nav className="pagination" aria-label={t('common.pagination')}>
              <button
                type="button"
                className="button-secondary"
                disabled={page <= 1}
                onClick={() => updateParam('page', String(page - 1))}
              >
                {t('common.previous')}
              </button>
              <span>{t('common.pageOf', { page, totalPages })}</span>
              <button
                type="button"
                className="button-secondary"
                disabled={page >= totalPages}
                onClick={() => updateParam('page', String(page + 1))}
              >
                {t('common.next')}
              </button>
            </nav>
          )}
        </>
      )}
    </div>
  )
}
