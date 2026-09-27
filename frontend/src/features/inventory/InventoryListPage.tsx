/**
 * Application Inventory (Requirement.md FR-1, FR-10.5 entry point).
 *
 * Each row carries the Application's open/overdue Finding counts, so risk is visible
 * without opening the backlog. The inventory endpoint does not return counts; they come
 * from the same backlog summary the dashboard uses (already scoped per role server-side)
 * and are joined here by Application id. An Application with nothing open is absent from
 * that summary and shows zero.
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { fetchBacklogSummary } from '../findings/api'
import { listApplications } from './api'

export function InventoryListPage() {
  const { t } = useTranslation()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['applications'],
    queryFn: () => listApplications(),
  })
  const { data: summary } = useQuery({
    queryKey: ['backlog-summary'],
    queryFn: () => fetchBacklogSummary(),
  })

  const backlogByApp = new Map(summary?.by_application.map((row) => [row.application_id, row]))

  return (
    <div className="page">
      <h1>
        {t('inventory.title')}
        {data && <span className="count">{data.total}</span>}
      </h1>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('inventory.loadError')}
        </p>
      )}

      {data && data.items.length === 0 && <p className="empty-state">{t('inventory.empty')}</p>}

      {data && data.items.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="sticky-column">
                  {t('inventory.appName')}
                </th>
                <th scope="col">{t('inventory.ownerTeam')}</th>
                <th scope="col">{t('inventory.criticality')}</th>
                <th scope="col">{t('inventory.exposure')}</th>
                <th scope="col" className="numeric">
                  {t('inventory.openFindings')}
                </th>
                <th scope="col" className="numeric">
                  {t('sla.overdue')}
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((application) => {
                const backlog = backlogByApp.get(application.id)
                return (
                  <tr key={application.id}>
                    <th scope="row" className="sticky-column">
                      <Link to={`/applications/${application.id}`}>{application.app_name}</Link>
                      {!application.ownership_confirmed && (
                        // FR-1.5: auto-created from an SBOM push; AppSec still has to
                        // confirm who owns it.
                        <span className="chip chip-source gap-left">{t('inventory.ownershipUnconfirmed')}</span>
                      )}
                      <span className="cell-sub">
                        {[
                          t(`inventory.appTypeValue.${application.app_type}`),
                          application.environment,
                          application.business_unit,
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                      </span>
                    </th>
                    <td>{application.owner_team}</td>
                    <td>
                      <span className="chip chip-neutral">
                        {t(`inventory.criticalityValue.${application.criticality}`)}
                      </span>
                    </td>
                    <td>{application.internet_facing ? t('inventory.internetFacing') : t('inventory.internal')}</td>
                    <td className="numeric mono">
                      {backlog && backlog.total > 0 ? (
                        <Link to={`/findings?application_id=${application.id}`}>{backlog.total}</Link>
                      ) : (
                        <span className="muted">0</span>
                      )}
                    </td>
                    <td className={backlog && backlog.overdue > 0 ? 'numeric mono numeric-alert' : 'numeric mono'}>
                      {backlog && backlog.overdue > 0 ? (
                        <Link to={`/findings?application_id=${application.id}&sla_status=overdue`}>
                          {backlog.overdue}
                        </Link>
                      ) : (
                        <span className="muted">0</span>
                      )}
                    </td>
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
