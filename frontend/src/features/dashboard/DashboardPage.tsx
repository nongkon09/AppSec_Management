/**
 * Security Team / Dev Team dashboard (Requirement.md FR-10.1, FR-10.2, FR-5.4).
 *
 * Data is scoped server-side, so the same screen serves AppSec (whole organisation) and a
 * Dev Team (their own Applications only) — the scope badge in the top bar says which.
 *
 * Reading order is "how bad → what first → where": headline figures, the overdue items to
 * act on, then the per-application grid. Per UXR-3 the SLA figure prints its value and
 * target as text, and the application grid prints a number in every cell.
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { SeverityBadge, SeverityLegend, SlaBadge } from '../../components/SeverityBadge'
import { InfoTip } from '../../components/ui'
import { IconOverdue, IconWithinSla } from '../../lib/icons'
import { fetchBacklogSummary, listFindings } from '../findings/api'
import { findingLabel } from '../findings/labels'
import type { SeverityTier } from '../findings/types'

const SLA_COMPLIANCE_TARGET = 95
const TIERS: SeverityTier[] = ['critical', 'high', 'medium', 'low']

/** Buckets a count into the 5-step heat ramp; the cell always prints the number too. */
function heatLevel(count: number): number {
  if (count === 0) return 0
  if (count <= 2) return 1
  if (count <= 5) return 2
  if (count <= 10) return 3
  return 4
}

export function DashboardPage() {
  const { t } = useTranslation()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['backlog-summary'],
    queryFn: () => fetchBacklogSummary(),
  })

  const compliance = data?.sla_compliance_percent ?? null
  const meetsTarget = compliance !== null && compliance >= SLA_COMPLIANCE_TARGET

  return (
    <div className="page">
      <div>
        <h1>{t('dashboard.title')}</h1>
        <p className="page-sub">{t('dashboard.subtitle')}</p>
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('dashboard.loadError')}
        </p>
      )}

      {data && (
        <>
          {/* UXR-8: a summary announced to screen readers without stealing focus. */}
          <p className="visually-hidden" role="status">
            {t('dashboard.summaryAnnouncement', { open: data.total_open, overdue: data.total_overdue })}
          </p>

          <section className="stats" aria-label={t('dashboard.kpiSectionLabel')}>
            <Link className="stat" to="/findings">
              <h2 className="stat-label">{t('dashboard.openBacklog')}</h2>
              <p className="stat-value">{data.total_open}</p>
              <p className="stat-meta">{t('dashboard.openBacklogMeta')}</p>
            </Link>

            <Link className="stat" to="/findings?sla_status=overdue">
              <h2 className="stat-label">{t('dashboard.overdue')}</h2>
              <p className={data.total_overdue > 0 ? 'stat-value stat-value-alert' : 'stat-value'}>
                {data.total_overdue}
              </p>
              <p className="stat-meta">
                {data.total_overdue > 0 ? t('dashboard.viewOverdue') : t('dashboard.noneOverdue')}
              </p>
            </Link>

            <div className="stat">
              <h2 className="stat-label">
                {t('dashboard.slaCompliance')}
                <InfoTip label={t('glossary.slaComplianceLabel')}>{t('glossary.slaCompliance')}</InfoTip>
              </h2>
              <p className="stat-value">{compliance === null ? '—' : `${compliance}%`}</p>
              <div
                className="gauge"
                role="meter"
                aria-valuenow={compliance ?? 0}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={t('dashboard.slaCompliance')}
              >
                <div
                  className={meetsTarget ? 'gauge-fill' : 'gauge-fill gauge-fill-below'}
                  style={{ width: `${compliance ?? 0}%` }}
                />
                <div className="gauge-target" style={{ left: `${SLA_COMPLIANCE_TARGET}%` }} />
              </div>
              <p className="stat-meta">
                {meetsTarget ? <IconWithinSla /> : <IconOverdue />}
                {t('dashboard.targetLabel', { target: SLA_COMPLIANCE_TARGET })}
              </p>
            </div>
          </section>

          <section className="severity-strip" aria-label={t('dashboard.bySeverity')}>
            {TIERS.map((tier) => {
              const row = data.by_severity.find((item) => item.severity_tier === tier)
              const overdue = row?.overdue ?? 0
              return (
                <Link key={tier} className="severity-tile" to={`/findings?severity=${tier}`}>
                  <SeverityBadge tier={tier} />
                  <span className="severity-tile-value">{row?.total ?? 0}</span>
                  <span className={overdue > 0 ? 'severity-tile-meta numeric-alert' : 'severity-tile-meta'}>
                    {t('dashboard.tierOverdue', { count: overdue })}
                  </span>
                </Link>
              )
            })}
          </section>

          <OverdueFirst />

          <section aria-labelledby="by-app-heading">
            <div className="section-head">
              <h2 id="by-app-heading" className="section-title">
                {t('dashboard.byApplication')}
              </h2>
              <SeverityLegend />
            </div>
            {data.by_application.length === 0 ? (
              <p className="empty-state">{t('dashboard.noBacklog')}</p>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <caption className="visually-hidden">{t('dashboard.byApplicationCaption')}</caption>
                  <thead>
                    <tr>
                      <th scope="col" className="sticky-column">
                        {t('inventory.appName')}
                      </th>
                      <th scope="col">{t('inventory.ownerTeam')}</th>
                      {TIERS.map((tier) => (
                        <th key={tier} scope="col" className="numeric">
                          {tier[0].toUpperCase() + tier.slice(1)}
                        </th>
                      ))}
                      <th scope="col" className="numeric">
                        {t('sla.overdue')}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.by_application.map((row) => (
                      <tr key={row.application_id}>
                        <th scope="row" className="sticky-column">
                          <Link to={`/findings?application_id=${row.application_id}`}>
                            {row.application_name}
                          </Link>
                        </th>
                        <td>{row.owner_team}</td>
                        {TIERS.map((tier) => (
                          <td key={tier} className="heat-cell" data-heat={heatLevel(row[tier])}>
                            {row[tier] === 0 ? (
                              <span className="heat-value muted">—</span>
                            ) : (
                              <Link
                                className="heat-value"
                                to={`/findings?application_id=${row.application_id}&severity=${tier}`}
                              >
                                {row[tier]}
                              </Link>
                            )}
                          </td>
                        ))}
                        <td className={row.overdue > 0 ? 'numeric numeric-alert' : 'numeric'}>{row.overdue}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}

/** The few overdue items to act on first, in the backend's urgency order (severity, then due date). */
function OverdueFirst() {
  const { t } = useTranslation()
  const { data } = useQuery({
    queryKey: ['findings', { slaStatus: 'overdue', limit: 5 }],
    queryFn: () => listFindings({ sla_status: 'overdue', limit: 5 }),
  })

  if (!data || data.items.length === 0) return null

  return (
    <section aria-labelledby="overdue-first-heading">
      <div className="section-head">
        <h2 id="overdue-first-heading" className="section-title">
          {t('dashboard.actFirst')}
        </h2>
        <Link to="/findings?sla_status=overdue">{t('dashboard.viewAll', { count: data.total })}</Link>
      </div>
      <div className="list">
        {data.items.map((finding) => (
          <Link key={finding.id} className="list-row" to={`/findings/${finding.id}`}>
            <SeverityBadge tier={finding.severity_tier} />
            <span className="list-row-main">
              <span className="list-row-title">{findingLabel(finding)}</span>
              {finding.kev_flag && <span className="chip chip-kev gap-left">KEV</span>}
              <span className="list-row-sub">
                {finding.application_name} · {finding.version_label}
              </span>
            </span>
            <SlaBadge isOverdue={finding.is_overdue} dueDate={finding.due_date} daysUntilDue={finding.days_until_due} />
          </Link>
        ))}
      </div>
    </section>
  )
}
