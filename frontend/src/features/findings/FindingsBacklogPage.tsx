/**
 * Vulnerability backlog (Requirement.md FR-5.4, FR-10.2).
 *
 * Filter state — including the "technical details" switch — lives in the URL query
 * string rather than in component state. That is what makes UXR-5 work: returning from a
 * Finding detail page restores the exact list the user drilled down from, and a filtered
 * backlog can be shared or bookmarked.
 *
 * By default the table shows what anyone needs to act (what, how severe, when due, where);
 * CVSS/EPSS/component/source are one switch away for the AppSec reader.
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Field, Label } from '@headlessui/react'
import { Link, useSearchParams } from 'react-router-dom'
import { SeverityBadge, SeverityIcon, SeverityLegend, SlaBadge } from '../../components/SeverityBadge'
import {
  Button,
  FormField,
  InfoTip,
  PillGroup,
  SelectBox,
  SwitchField,
  TextInput,
  TogglePill,
} from '../../components/ui'
import { IconCode, IconPackage, IconTarget } from '../../lib/icons'
import { listFindings } from './api'
import { findingLabel, SEVERITY_LABEL } from './labels'
import type { FindingSource, FindingStatus, SeverityTier } from './types'

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

export function FindingsBacklogPage() {
  const { t } = useTranslation()
  const [searchParams, setSearchParams] = useSearchParams()

  const severity = searchParams.getAll('severity') as SeverityTier[]
  const status = (searchParams.get('finding_status') ?? '') as FindingStatus | ''
  const source = (searchParams.get('source') ?? '') as FindingSource | ''
  const slaStatus = searchParams.get('sla_status') ?? ''
  const applicationId = searchParams.get('application_id') ?? undefined
  const search = searchParams.get('search') ?? ''
  const showTechnical = searchParams.get('tech') === '1'
  const page = Number(searchParams.get('page') ?? '1')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['findings', { severity, status, source, slaStatus, applicationId, search, page }],
    queryFn: () =>
      listFindings({
        severity: severity.length > 0 ? severity : undefined,
        finding_status: status ? [status] : undefined,
        source: source || undefined,
        sla_status: slaStatus === 'overdue' || slaStatus === 'within_sla' ? slaStatus : undefined,
        application_id: applicationId,
        search: search || undefined,
        skip: (page - 1) * PAGE_SIZE,
        limit: PAGE_SIZE,
      }),
  })

  /** Writes one parameter into the URL. Filter changes reset pagination; view changes don't. */
  function updateParam(key: string, value: string | string[] | undefined, resetPage = true) {
    const next = new URLSearchParams(searchParams)
    next.delete(key)
    if (resetPage) next.delete('page')
    if (Array.isArray(value)) {
      value.forEach((item) => next.append(key, item))
    } else if (value) {
      next.set(key, value)
    }
    setSearchParams(next, { replace: true })
  }

  function toggleSeverity(tier: SeverityTier, on: boolean) {
    updateParam('severity', on ? [...severity, tier] : severity.filter((item) => item !== tier))
  }

  function clearFilters() {
    setSearchParams(showTechnical ? { tech: '1' } : {})
  }

  const activeFilterCount =
    severity.length + (status ? 1 : 0) + (source ? 1 : 0) + (slaStatus ? 1 : 0) + (applicationId ? 1 : 0) + (search ? 1 : 0)
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <div className="page">
      <div className="page-head">
        <h1>
          {t('findings.title')}
          {data && <span className="count">{data.total}</span>}
        </h1>
        <SwitchField checked={showTechnical} onChange={(on) => updateParam('tech', on ? '1' : undefined, false)}>
          {t('findings.showTechnical')}
        </SwitchField>
      </div>

      <section className="stack" aria-label={t('findings.filtersLabel')}>
        <div className="toolbar">
          <Field className="field toolbar-grow">
            <Label className="visually-hidden">{t('findings.search')}</Label>
            <TextInput
              type="search"
              value={search}
              placeholder={t('findings.searchPlaceholder')}
              onChange={(event) => updateParam('search', event.target.value || undefined)}
            />
          </Field>
          <FormField label={t('findings.status')}>
            <SelectBox
              value={status}
              onChange={(value) => updateParam('finding_status', value || undefined)}
              options={[
                { value: '', label: t('findings.allStatuses') },
                ...STATUSES.map((item) => ({ value: item, label: t(`findings.statusValue.${item}`) })),
              ]}
            />
          </FormField>
          <FormField label={t('findings.source')}>
            <SelectBox
              value={source}
              onChange={(value) => updateParam('source', value || undefined)}
              options={[
                { value: '', label: t('findings.allSources') },
                ...SOURCES.map((item) => ({ value: item, label: item.toUpperCase() })),
              ]}
            />
          </FormField>
        </div>

        <div className="toolbar">
          <PillGroup
            ariaLabel={t('findings.slaStatus')}
            value={slaStatus}
            onChange={(value) => updateParam('sla_status', value || undefined)}
            options={[
              { value: '', label: t('findings.allDue') },
              { value: 'overdue', label: t('sla.overdue') },
              { value: 'within_sla', label: t('sla.withinSla') },
            ]}
          />
          <div className="pill-row" role="group" aria-label={t('findings.severity')}>
            {SEVERITY_TIERS.map((tier) => (
              <TogglePill key={tier} checked={severity.includes(tier)} onChange={(on) => toggleSeverity(tier, on)}>
                <SeverityIcon tier={tier} />
                {SEVERITY_LABEL[tier]}
              </TogglePill>
            ))}
          </div>
          {activeFilterCount > 0 && (
            <Button variant="ghost" small onClick={clearFilters}>
              {t('findings.clearFilters', { count: activeFilterCount })}
            </Button>
          )}
        </div>
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
          <p className="visually-hidden" role="status">
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
                    <th scope="col">Severity</th>
                    <th scope="col">{t('findings.dueDate')}</th>
                    <th scope="col">{t('findings.status')}</th>
                    <th scope="col">{t('inventory.appName')}</th>
                    {showTechnical && (
                      <>
                        <th scope="col">Component</th>
                        <th scope="col" className="numeric">
                          CVSS
                          <InfoTip label={t('glossary.cvssLabel')}>{t('glossary.cvss')}</InfoTip>
                        </th>
                        <th scope="col" className="numeric">
                          EPSS
                          <InfoTip label={t('glossary.epssLabel')}>{t('glossary.epss')}</InfoTip>
                        </th>
                        <th scope="col">{t('findings.source')}</th>
                      </>
                    )}
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
                          <span className="chip chip-kev gap-left" title={t('findings.kevTooltip')}>
                            KEV
                          </span>
                        )}
                        {finding.cve_id && finding.title && <span className="cell-sub">{finding.title}</span>}
                      </th>
                      <td>
                        <SeverityBadge tier={finding.effective_severity_tier} />
                        {finding.residual_severity_tier && (
                          <span className="cell-sub">
                            {t('findings.reducedFrom', { tier: SEVERITY_LABEL[finding.severity_tier] })}
                          </span>
                        )}
                      </td>
                      <td>
                        <SlaBadge
                          isOverdue={finding.is_overdue}
                          dueDate={finding.due_date}
                          daysUntilDue={finding.days_until_due}
                        />
                      </td>
                      <td>
                        <span className="chip chip-neutral">{t(`findings.statusValue.${finding.status}`)}</span>
                      </td>
                      <td className="nowrap">
                        {finding.application_name}
                        <span className="cell-sub">{finding.version_label}</span>
                      </td>
                      {showTechnical && (
                        <>
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
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {totalPages > 1 && (
            <nav className="pagination" aria-label={t('common.pagination')}>
              <Button small disabled={page <= 1} onClick={() => updateParam('page', String(page - 1), false)}>
                {t('common.previous')}
              </Button>
              <span>{t('common.pageOf', { page, totalPages })}</span>
              <Button
                small
                disabled={page >= totalPages}
                onClick={() => updateParam('page', String(page + 1), false)}
              >
                {t('common.next')}
              </Button>
            </nav>
          )}
        </>
      )}
    </div>
  )
}
