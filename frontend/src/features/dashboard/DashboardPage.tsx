/**
 * Security Team / Dev Team dashboard (Requirement.md FR-10.1, FR-10.2, FR-5.4).
 *
 * Data is scoped server-side, so the same screen serves AppSec (whole organisation) and a
 * Dev Team (their own Applications only) — the scope badge in the header says which view
 * the user is looking at (UXR-6).
 *
 * Per UXR-3 the KPI tiles print their value and their target as text, and the
 * severity-by-application grid is a real data table rather than a colour-only heatmap, so
 * it is reachable by keyboard and readable by a screen reader.
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { SeverityBadge, SeverityLegend } from '../../components/SeverityBadge'
import { IconOverdue, IconWithinSla } from '../../lib/icons'
import { fetchBacklogSummary } from '../findings/api'
import type { ApplicationBacklog, SeverityTier } from '../findings/types'

const SLA_COMPLIANCE_TARGET = 95

/** Buckets a count into the 5-step heat ramp; the cell always prints the number too. */
function heatLevel(count: number): number {
  if (count === 0) return 0
  if (count <= 2) return 1
  if (count <= 5) return 2
  if (count <= 10) return 3
  return 4
}

function BacklogCell({
  count,
  tier,
  applicationId,
}: {
  count: number
  tier: SeverityTier
  applicationId: string
}) {
  if (count === 0) {
    // A dash reads as "none" without the user having to interpret an empty cell.
    return (
      <td className="heat-cell" data-heat="0">
        <span className="heat-value muted">—</span>
      </td>
    )
  }
  return (
    <td className="heat-cell" data-heat={heatLevel(count)}>
      <Link
        className="heat-value"
        to={`/findings?application_id=${applicationId}&severity=${tier}`}
      >
        {count}
      </Link>
    </td>
  )
}

export function DashboardPage() {
  const { t } = useTranslation()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['backlog-summary'],
    queryFn: () => fetchBacklogSummary(),
  })

  const tiers: SeverityTier[] = ['critical', 'high', 'medium', 'low']
  const compliance = data?.sla_compliance_percent
  const meetsTarget = compliance !== null && compliance !== undefined && compliance >= SLA_COMPLIANCE_TARGET

  return (
    <div className="page">
      <h1>{t('dashboard.title')}</h1>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('dashboard.loadError')}
        </p>
      )}

      {data && (
        <>
          {/* UXR-8: a summary counter announced to screen readers without stealing focus. */}
          <p className="visually-hidden" role="status">
            {t('dashboard.summaryAnnouncement', {
              open: data.total_open,
              overdue: data.total_overdue,
            })}
          </p>

          <section className="kpi-row" aria-label={t('dashboard.kpiSectionLabel')}>
            <article className="kpi-card">
              <h2 className="kpi-label">{t('dashboard.openBacklog')}</h2>
              <p className="kpi-value">{data.total_open}</p>
              <p className="kpi-meta">{t('dashboard.openBacklogMeta')}</p>
            </article>

            <article className="kpi-card">
              <h2 className="kpi-label">{t('dashboard.overdue')}</h2>
              <p className={`kpi-value ${data.total_overdue > 0 ? 'kpi-value-alert' : ''}`}>
                {data.total_overdue}
              </p>
              <p className="kpi-meta">
                {data.total_overdue > 0 ? (
                  <Link to="/findings?sla_status=overdue">{t('dashboard.viewOverdue')}</Link>
                ) : (
                  t('dashboard.noneOverdue')
                )}
              </p>
            </article>

            <article className="kpi-card">
              <h2 className="kpi-label">{t('dashboard.slaCompliance')}</h2>
              <p className="kpi-value">
                {compliance === null || compliance === undefined ? '—' : `${compliance}%`}
              </p>
              {/* UXR-3: a bullet gauge that states value and target in text, not colour alone. */}
              <div
                className="gauge"
                role="meter"
                aria-valuenow={compliance ?? 0}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={t('dashboard.slaCompliance')}
              >
                <div className="gauge-fill" style={{ width: `${compliance ?? 0}%` }} />
                <div className="gauge-target" style={{ left: `${SLA_COMPLIANCE_TARGET}%` }} />
              </div>
              <p className="kpi-meta">
                {meetsTarget ? <IconWithinSla /> : <IconOverdue />}
                {t('dashboard.targetLabel', { target: SLA_COMPLIANCE_TARGET })}
              </p>
            </article>
          </section>

          <SeverityLegend />

          <section aria-labelledby="severity-heading">
            <h2 id="severity-heading" className="section-title">
              {t('dashboard.bySeverity')}
            </h2>
            <div className="table-scroll">
              <table className="data-table">
                <caption className="visually-hidden">{t('dashboard.bySeverityCaption')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('findings.severity')}</th>
                    <th scope="col" className="numeric">
                      {t('dashboard.open')}
                    </th>
                    <th scope="col" className="numeric">
                      {t('sla.withinSla')}
                    </th>
                    <th scope="col" className="numeric">
                      {t('sla.overdue')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.by_severity.map((row) => (
                    <tr key={row.severity_tier}>
                      <th scope="row">
                        <SeverityBadge tier={row.severity_tier} />
                      </th>
                      <td className="numeric">
                        {row.total > 0 ? (
                          <Link to={`/findings?severity=${row.severity_tier}`}>{row.total}</Link>
                        ) : (
                          <span className="muted">0</span>
                        )}
                      </td>
                      <td className="numeric">{row.within_sla}</td>
                      <td className={`numeric ${row.overdue > 0 ? 'numeric-alert' : ''}`}>
                        {row.overdue}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section aria-labelledby="heatmap-heading">
            <h2 id="heatmap-heading" className="section-title">
              {t('dashboard.byApplication')}
            </h2>
            {data.by_application.length === 0 ? (
              <p className="empty-state">{t('dashboard.noBacklog')}</p>
            ) : (
              <div className="table-scroll">
                <table className="data-table heatmap-table">
                  <caption className="visually-hidden">
                    {t('dashboard.byApplicationCaption')}
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col" className="sticky-column">
                        {t('inventory.appName')}
                      </th>
                      <th scope="col">{t('inventory.ownerTeam')}</th>
                      {tiers.map((tier) => (
                        <th key={tier} scope="col" className="numeric">
                          <SeverityBadge tier={tier} />
                        </th>
                      ))}
                      <th scope="col" className="numeric">
                        {t('sla.overdue')}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.by_application.map((row: ApplicationBacklog) => (
                      <tr key={row.application_id}>
                        <th scope="row" className="sticky-column">
                          <Link to={`/findings?application_id=${row.application_id}`}>
                            {row.application_name}
                          </Link>
                        </th>
                        <td>{row.owner_team}</td>
                        {tiers.map((tier) => (
                          <BacklogCell
                            key={tier}
                            tier={tier}
                            count={row[tier]}
                            applicationId={row.application_id}
                          />
                        ))}
                        <td className={`numeric ${row.overdue > 0 ? 'numeric-alert' : ''}`}>
                          {row.overdue}
                        </td>
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
