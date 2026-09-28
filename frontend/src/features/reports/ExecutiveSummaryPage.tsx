/**
 * Monthly executive summary: one printable page leadership can read in a minute.
 *
 * Pick a month, read it on screen, then Print / Save as PDF to send it on. Print styles
 * drop the app chrome and controls and keep sections from splitting across pages.
 * The figures come from GET /reports/executive-summary; the key messages are composed
 * here so they follow the reader's language.
 */
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { SeverityBadge } from '../../components/SeverityBadge'
import { Button, FormField, TextInput } from '../../components/ui'
import { formatDate, formatDateTime } from '../../lib/format'
import i18n from '../../lib/i18n'
import { IconDownload } from '../../lib/icons'
import { SEVERITY_LABEL } from '../findings/labels'
import { fetchExecutiveSummary } from './api'
import type { ExecutiveSummary, MonthFigures } from './types'

type Translate = (key: string, options?: Record<string, unknown>) => string

/** The month a monthly report is usually about: the one that just ended. */
function previousMonth(): string {
  const date = new Date()
  date.setDate(1)
  date.setMonth(date.getMonth() - 1)
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
}

function thisMonth(): string {
  const date = new Date()
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
}

function monthLabel(month: string, style: 'long' | 'short' = 'long'): string {
  const [year, value] = month.split('-').map(Number)
  return new Date(year, value - 1, 1).toLocaleDateString(i18n.language, {
    month: style,
    year: 'numeric',
  })
}

/** Change against last month, with whether the direction is good news. */
function Delta({ now, before, higherIsBetter }: { now: number; before: number; higherIsBetter: boolean }) {
  const { t } = useTranslation()
  const diff = now - before
  if (diff === 0) return <span className="delta">{t('reports.noChange')}</span>
  const good = diff > 0 === higherIsBetter
  return (
    <span className={good ? 'delta delta-good' : 'delta delta-bad'}>
      <span aria-hidden="true">{diff > 0 ? '▲' : '▼'}</span> {t('reports.vsLastMonth', { count: Math.abs(diff) })}
    </span>
  )
}

function keyMessages(report: ExecutiveSummary, t: Translate): string[] {
  const { current: now, previous: before, exceptions } = report
  const messages: string[] = []
  const change = now.open_at_end - before.open_at_end
  const when = report.is_partial ? t('reports.whenDate', { date: formatDate(report.as_of) }) : t('reports.whenEnd')
  messages.push(
    change === 0
      ? t('reports.msgOpenSame', { count: now.open_at_end, when })
      : t(change < 0 ? 'reports.msgOpenDown' : 'reports.msgOpenUp', {
          count: now.open_at_end,
          change: Math.abs(change),
          when,
        }),
  )
  messages.push(t('reports.msgFlow', { found: now.new, fixed: now.fixed }))
  if (now.on_time_percent !== null) {
    messages.push(t('reports.msgOnTime', { percent: now.on_time_percent }))
  }
  if (now.overdue_at_end > 0 || report.kev_open_at_end > 0) {
    messages.push(t('reports.msgAttention', { overdue: now.overdue_at_end, kev: report.kev_open_at_end }))
  }
  if (exceptions.active_at_end > 0 || exceptions.approved_in_month > 0) {
    messages.push(
      t('reports.msgExceptions', {
        approved: exceptions.approved_in_month,
        active: exceptions.active_at_end,
        expiring: exceptions.expiring_next_30_days,
      }),
    )
  }
  return messages
}

/** Found vs fixed per month: grouped bars, one axis, legend plus the latest values labelled. */
function TrendChart({ trend }: { trend: MonthFigures[] }) {
  const { t } = useTranslation()
  const width = 560
  const height = 180
  const top = 20
  const bottom = 28
  const plot = height - top - bottom
  const max = Math.max(1, ...trend.flatMap((m) => [m.new, m.fixed]))
  const slot = width / trend.length
  const bar = Math.min(18, slot / 4)
  const y = (value: number) => top + plot - (value / max) * plot

  return (
    <figure className="trend">
      <div className="trend-legend">
        <span>
          <i className="legend-swatch series-found" /> {t('reports.found')}
        </span>
        <span>
          <i className="legend-swatch series-fixed" /> {t('reports.fixed')}
        </span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={t('reports.trendTitle')}>
        <line className="trend-baseline" x1={0} x2={width} y1={top + plot} y2={top + plot} />
        {trend.map((month, index) => {
          const center = slot * index + slot / 2
          const last = index === trend.length - 1
          return (
            <g key={month.month}>
              {(
                [
                  ['series-found', month.new, center - bar - 1],
                  ['series-fixed', month.fixed, center + 1],
                ] as const
              ).map(([series, value, x]) => (
                <g key={series}>
                  <rect
                    className={series}
                    x={x}
                    y={y(value)}
                    width={bar}
                    height={Math.max(value > 0 ? 2 : 0, top + plot - y(value))}
                    rx={2}
                  >
                    <title>
                      {monthLabel(month.month, 'short')} · {series === 'series-found' ? t('reports.found') : t('reports.fixed')}: {value}
                    </title>
                  </rect>
                  {last && (
                    <text className="trend-value" x={x + bar / 2} y={y(value) - 5} textAnchor="middle">
                      {value}
                    </text>
                  )}
                </g>
              ))}
              <text className="trend-axis" x={center} y={height - 8} textAnchor="middle">
                {monthLabel(month.month, 'short')}
              </text>
            </g>
          )
        })}
      </svg>
      <table className="visually-hidden">
        <caption>{t('reports.trendTitle')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('reports.month')}</th>
            <th scope="col">{t('reports.found')}</th>
            <th scope="col">{t('reports.fixed')}</th>
            <th scope="col">{t('reports.openAtEnd')}</th>
          </tr>
        </thead>
        <tbody>
          {trend.map((month) => (
            <tr key={month.month}>
              <th scope="row">{monthLabel(month.month)}</th>
              <td>{month.new}</td>
              <td>{month.fixed}</td>
              <td>{month.open_at_end}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  )
}

export function ExecutiveSummaryPage() {
  const { t } = useTranslation()
  const [month, setMonth] = useState(previousMonth)

  const { data: report, isLoading, isError } = useQuery({
    queryKey: ['executive-summary', month],
    queryFn: () => fetchExecutiveSummary(month),
    enabled: /^\d{4}-\d{2}$/.test(month),
  })

  /** "Open at month end", or "open as of <today>" while the month is still running. */
  function stateLabel(key: string): string {
    return report?.is_partial
      ? t(`${key}Date`, { date: formatDate(report.as_of) })
      : t(`${key}End`)
  }

  return (
    <div className="page report">
      <div className="page-head no-print">
        <div>
          <h1>{t('reports.title')}</h1>
          <p className="page-sub">{t('reports.subtitle')}</p>
        </div>
        <div className="toolbar">
          <FormField label={t('reports.month')}>
            <TextInput type="month" value={month} max={thisMonth()} onChange={(e) => setMonth(e.target.value)} />
          </FormField>
          <Button variant="primary" onClick={() => window.print()} disabled={!report}>
            <IconDownload />
            {t('reports.print')}
          </Button>
        </div>
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('reports.loadError')}
        </p>
      )}

      {report && (
        <article className="report-sheet">
          <header className="report-header">
            <p className="report-kicker">{t('reports.kicker')}</p>
            <h2 className="report-title">{t('reports.heading', { month: monthLabel(report.current.month) })}</h2>
            {report.is_partial && (
              <p className="report-partial">{t('reports.partialNote', { date: formatDate(report.as_of) })}</p>
            )}
            <p className="report-meta">
              {[
                report.scope_team ? t('reports.scopeTeam', { team: report.scope_team }) : t('reports.scopeOrg'),
                t('reports.period', { from: formatDate(report.period_start), to: formatDate(report.period_end) }),
                t('reports.generated', { at: formatDateTime(report.generated_at), by: report.generated_by }),
              ].join(' · ')}
            </p>
          </header>

          <section className="report-section">
            <h3 className="report-section-title">{t('reports.keyMessages')}</h3>
            <ul className="key-messages">
              {keyMessages(report, t).map((message) => (
                <li key={message}>{message}</li>
              ))}
            </ul>
          </section>

          <section className="stats stats-5 report-kpis" aria-label={t('reports.kpis')}>
            <div className="stat">
              <p className="stat-label">{stateLabel('reports.openAt')}</p>
              <p className="stat-value">{report.current.open_at_end}</p>
              <p className="stat-meta">
                <Delta now={report.current.open_at_end} before={report.previous.open_at_end} higherIsBetter={false} />
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">{t('reports.found')}</p>
              <p className="stat-value">{report.current.new}</p>
              <p className="stat-meta">
                <Delta now={report.current.new} before={report.previous.new} higherIsBetter={false} />
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">{t('reports.fixed')}</p>
              <p className="stat-value">{report.current.fixed}</p>
              <p className="stat-meta">
                <Delta now={report.current.fixed} before={report.previous.fixed} higherIsBetter />
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">{t('reports.onTime')}</p>
              <p className="stat-value">
                {report.current.on_time_percent === null ? '—' : `${report.current.on_time_percent}%`}
              </p>
              <p className="stat-meta">
                {report.current.fixed === 0
                  ? t('reports.noFixes')
                  : t('reports.onTimeMeta', { onTime: report.current.fixed_on_time, fixed: report.current.fixed })}
              </p>
            </div>
            <div className="stat">
              <p className="stat-label">{stateLabel('reports.overdueAt')}</p>
              <p className={report.current.overdue_at_end > 0 ? 'stat-value stat-value-alert' : 'stat-value'}>
                {report.current.overdue_at_end}
              </p>
              <p className="stat-meta">
                <Delta
                  now={report.current.overdue_at_end}
                  before={report.previous.overdue_at_end}
                  higherIsBetter={false}
                />
              </p>
            </div>
          </section>

          <div className="report-columns">
            <section className="report-section card card-pad">
              <h3 className="report-section-title">{t('reports.trendTitle')}</h3>
              <TrendChart trend={report.trend} />
            </section>

            <section className="report-section card card-pad">
              <h3 className="report-section-title">{t('reports.bySeverity')}</h3>
              <table className="report-table">
                <thead>
                  <tr>
                    <th scope="col">{t('findings.severity')}</th>
                    <th scope="col" className="numeric">
                      {t('reports.openShort')}
                    </th>
                    <th scope="col" className="numeric">
                      {t('reports.overdueShort')}
                    </th>
                    <th scope="col" className="numeric">
                      {t('reports.found')}
                    </th>
                    <th scope="col" className="numeric">
                      {t('reports.fixed')}
                    </th>
                    <th scope="col" className="numeric">
                      {t('reports.medianDays')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {report.by_severity.map((row) => (
                    <tr key={row.severity_tier}>
                      <th scope="row">
                        <SeverityBadge tier={row.severity_tier} />
                      </th>
                      <td className="numeric mono">{row.open_at_end}</td>
                      <td className="numeric mono">{row.overdue_at_end}</td>
                      <td className="numeric mono">{row.new}</td>
                      <td className="numeric mono">{row.fixed}</td>
                      <td className="numeric mono">{row.median_days_to_fix ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="field-hint">{t('reports.medianHint')}</p>
            </section>
          </div>

          <section className="report-section">
            <h3 className="report-section-title">{t('reports.topRisks')}</h3>
            {report.top_risks.length === 0 ? (
              <p className="empty-state">{t('reports.noTopRisks')}</p>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">{t('reports.issue')}</th>
                      <th scope="col">{t('findings.severity')}</th>
                      <th scope="col">{t('reports.dueDate')}</th>
                      <th scope="col">{t('reports.planTarget')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.top_risks.map((risk) => (
                      <tr key={risk.finding_id}>
                        <td>
                          <Link to={`/findings/${risk.finding_id}`}>{risk.label}</Link>
                          {risk.kev && <span className="chip chip-kev gap-left">KEV</span>}
                          <span className="cell-sub">
                            {risk.application_name} · {risk.owner_team}
                          </span>
                        </td>
                        <td>
                          <SeverityBadge tier={risk.severity_tier} />
                        </td>
                        <td className="nowrap">
                          {risk.due_date ? formatDate(risk.due_date) : '—'}
                          {risk.days_overdue > 0 && (
                            <span className="cell-sub delta-bad">
                              {t('reports.daysOverdue', { count: risk.days_overdue })}
                            </span>
                          )}
                        </td>
                        <td className="nowrap">
                          {risk.plan_target_date ? (
                            formatDate(risk.plan_target_date)
                          ) : (
                            <span className="muted">{t('reports.noPlan')}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <div className="report-columns">
            <section className="report-section card card-pad">
              <h3 className="report-section-title">{t('reports.applications')}</h3>
              {report.applications.length === 0 ? (
                <p className="field-hint">{t('reports.noApplications')}</p>
              ) : (
                <table className="report-table">
                  <thead>
                    <tr>
                      <th scope="col">{t('nav.inventory')}</th>
                      <th scope="col" className="numeric">
                        {SEVERITY_LABEL.critical}
                      </th>
                      <th scope="col" className="numeric">
                        {SEVERITY_LABEL.high}
                      </th>
                      <th scope="col" className="numeric">
                        {t('reports.overdueShort')}
                      </th>
                      <th scope="col" className="numeric">
                        {t('reports.openShort')}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.applications.map((app) => (
                      <tr key={app.application_id}>
                        <th scope="row">
                          {app.application_name}
                          <span className="cell-sub">{app.owner_team}</span>
                        </th>
                        <td className="numeric mono">{app.critical}</td>
                        <td className="numeric mono">{app.high}</td>
                        <td className="numeric mono">{app.overdue_at_end}</td>
                        <td className="numeric mono">{app.open_at_end}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>

            <section className="report-section card card-pad">
              <h3 className="report-section-title">{t('reports.governance')}</h3>
              <dl className="report-facts">
                <div>
                  <dt>{t('reports.exApproved')}</dt>
                  <dd>{report.exceptions.approved_in_month}</dd>
                </div>
                <div>
                  <dt>{t('reports.exActive')}</dt>
                  <dd>{report.exceptions.active_at_end}</dd>
                </div>
                <div>
                  <dt>{t('reports.exExpiring')}</dt>
                  <dd>{report.exceptions.expiring_next_30_days}</dd>
                </div>
                <div>
                  <dt>{t('reports.exPending')}</dt>
                  <dd>{report.exceptions.pending_now}</dd>
                </div>
                <div>
                  <dt>{t('reports.kevOpen')}</dt>
                  <dd>{report.kev_open_at_end}</dd>
                </div>
                <div>
                  <dt>{t('reports.staleSbom')}</dt>
                  <dd>{report.stale_sbom_versions}</dd>
                </div>
              </dl>
            </section>
          </div>

          <footer className="report-notes">
            <p>{t('reports.noteCounting')}</p>
            <p>{t('reports.noteHistory')}</p>
          </footer>
        </article>
      )}
    </div>
  )
}
