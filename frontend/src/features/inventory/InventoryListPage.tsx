/**
 * Application Inventory (Requirement.md FR-1, FR-10.5 entry point).
 *
 * Each row links into the backlog filtered to that Application, which is the first hop of
 * the Application > Version > Component > Finding drill-down (FR-10.5).
 */
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { listApplications } from './api'

export function InventoryListPage() {
  const { t } = useTranslation()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['applications'],
    queryFn: () => listApplications(),
  })

  return (
    <div className="page">
      <h1>{t('inventory.title')}</h1>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('inventory.loadError')}
        </p>
      )}

      {data && data.items.length === 0 && <p className="empty-state">{t('inventory.empty')}</p>}

      {data && data.items.length > 0 && (
        <>
          <p className="result-count" role="status">
            {t('inventory.resultCount', { count: data.total })}
          </p>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col" className="sticky-column">
                    {t('inventory.appName')}
                  </th>
                  <th scope="col">{t('inventory.appType')}</th>
                  <th scope="col">{t('inventory.ownerTeam')}</th>
                  <th scope="col">{t('inventory.businessUnit')}</th>
                  <th scope="col">{t('inventory.criticality')}</th>
                  <th scope="col">{t('inventory.environment')}</th>
                  <th scope="col">{t('inventory.exposure')}</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((application) => (
                  <tr key={application.id}>
                    <th scope="row" className="sticky-column">
                      <Link to={`/applications/${application.id}`}>{application.app_name}</Link>
                      {!application.ownership_confirmed && (
                        // FR-1.5: auto-created from an SBOM push; AppSec still has to
                        // confirm who owns it.
                        <span className="chip chip-source">
                          {t('inventory.ownershipUnconfirmed')}
                        </span>
                      )}
                    </th>
                    <td>{t(`inventory.appTypeValue.${application.app_type}`)}</td>
                    <td>{application.owner_team}</td>
                    <td>{application.business_unit ?? <span className="muted">—</span>}</td>
                    <td>{t(`inventory.criticalityValue.${application.criticality}`)}</td>
                    <td>{application.environment}</td>
                    <td>
                      {application.internet_facing
                        ? t('inventory.internetFacing')
                        : t('inventory.internal')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
