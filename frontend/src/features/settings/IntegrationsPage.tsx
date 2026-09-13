/**
 * Integration Connector Configuration (Requirement.md FR-7, Section 4: System Admin
 * manages Integration Connector Configuration).
 *
 * Jira is the one connector type with a real, working implementation on the backend —
 * ManageEngine ServiceDesk Plus and a generic webhook can be registered as configuration
 * (FR-7's "pluggable, add a destination without touching Core") but calling one is not
 * wired up yet, which this page says plainly rather than pretending otherwise.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { SeverityBadge } from '../../components/SeverityBadge'
import { IconPlus } from '../../lib/icons'
import type { SeverityTier } from '../findings/types'
import { createConnector, deleteConnector, listConnectors, updateConnector } from './integrationApi'
import type { ConnectorType } from './integrationTypes'
import { SettingsTabs } from './SettingsTabs'

const CONNECTOR_TYPES: ConnectorType[] = ['jira', 'service_desk_plus', 'generic_webhook']
const SEVERITIES: SeverityTier[] = ['critical', 'high', 'medium', 'low']

export function IntegrationsPage() {
  const { t } = useTranslation()
  const [showCreate, setShowCreate] = useState(false)
  const queryClient = useQueryClient()
  const { data: connectors, isLoading, isError } = useQuery({
    queryKey: ['integration-connectors'],
    queryFn: listConnectors,
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, isEnabled }: { id: string; isEnabled: boolean }) =>
      updateConnector(id, { is_enabled: isEnabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integration-connectors'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteConnector,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integration-connectors'] }),
  })

  return (
    <div className="page">
      <SettingsTabs />
      <div className="page-head">
        <div>
          <h1 className="page-title">{t('integrations.title')}</h1>
          <div className="page-sub">{t('integrations.subtitle')}</div>
        </div>
        {!showCreate && (
          <button type="button" onClick={() => setShowCreate(true)}>
            <IconPlus />
            {t('integrations.addConnector')}
          </button>
        )}
      </div>

      {showCreate && <CreateConnectorForm onDone={() => setShowCreate(false)} />}

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('integrations.loadError')}
        </p>
      )}

      {connectors && connectors.length === 0 && (
        <p className="empty-state">{t('integrations.empty')}</p>
      )}

      {connectors && connectors.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="sticky-column">
                  {t('integrations.name')}
                </th>
                <th scope="col">{t('integrations.type')}</th>
                <th scope="col">{t('integrations.baseUrl')}</th>
                <th scope="col">{t('integrations.routing')}</th>
                <th scope="col">{t('integrations.status')}</th>
                <th scope="col">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {connectors.map((connector) => (
                <tr key={connector.id}>
                  <th scope="row" className="sticky-column">
                    {connector.name}
                    {connector.connector_type !== 'jira' && (
                      <span className="cell-sub">{t('integrations.notImplementedYet')}</span>
                    )}
                  </th>
                  <td>
                    <span className="chip chip-neutral">{connector.connector_type}</span>
                  </td>
                  <td className="mono">{connector.base_url}</td>
                  <td>
                    {connector.routing_severities.length === 0 ? (
                      <span className="muted">{t('integrations.manualOnly')}</span>
                    ) : (
                      <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                        {connector.routing_severities.map((tier) => (
                          <SeverityBadge key={tier} tier={tier} />
                        ))}
                      </div>
                    )}
                  </td>
                  <td>
                    <label className="checkbox-row">
                      <input
                        type="checkbox"
                        checked={connector.is_enabled}
                        onChange={(e) =>
                          toggleMutation.mutate({ id: connector.id, isEnabled: e.target.checked })
                        }
                      />
                      {connector.is_enabled ? t('integrations.enabled') : t('integrations.disabled')}
                    </label>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="button-secondary"
                      onClick={() => {
                        if (window.confirm(t('integrations.confirmDelete', { name: connector.name }))) {
                          deleteMutation.mutate(connector.id)
                        }
                      }}
                    >
                      {t('common.delete')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function CreateConnectorForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [connectorType, setConnectorType] = useState<ConnectorType>('jira')
  const [baseUrl, setBaseUrl] = useState('')
  const [authToken, setAuthToken] = useState('')
  const [projectKey, setProjectKey] = useState('')
  const [severities, setSeverities] = useState<SeverityTier[]>([])
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: createConnector,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integration-connectors'] })
      onDone()
    },
  })

  function toggleSeverity(tier: SeverityTier) {
    setSeverities((prev) => (prev.includes(tier) ? prev.filter((t) => t !== tier) : [...prev, tier]))
  }

  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('integrations.createFailed'))

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (!name.trim() || !baseUrl.trim() || !authToken.trim()) {
      setValidationError(t('integrations.createValidationError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    if (connectorType === 'jira' && !projectKey.trim()) {
      setValidationError(t('integrations.projectKeyRequiredError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate({
      name: name.trim(),
      connector_type: connectorType,
      base_url: baseUrl.trim(),
      auth_token: authToken,
      config: connectorType === 'jira' ? { project_key: projectKey.trim() } : {},
      routing_severities: severities,
      is_enabled: true,
    })
  }

  return (
    <form
      className="card card-pad"
      onSubmit={handleSubmit}
      noValidate
      style={{ marginBottom: 'var(--space-5)' }}
    >
      {(validationError || serverErrorMessage) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('integrations.createErrorSummary')}</p>
          <ul>
            <li>{validationError || serverErrorMessage}</li>
          </ul>
        </div>
      )}

      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="conn-name">{t('integrations.name')}</label>
          <input id="conn-name" type="text" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="filter-group">
          <label htmlFor="conn-type">{t('integrations.type')}</label>
          <select
            id="conn-type"
            value={connectorType}
            onChange={(e) => setConnectorType(e.target.value as ConnectorType)}
          >
            {CONNECTOR_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>
        <div className="filter-group filter-group-grow">
          <label htmlFor="conn-url">{t('integrations.baseUrl')}</label>
          <input
            id="conn-url"
            type="text"
            placeholder="https://example.atlassian.net"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <label htmlFor="conn-token">{t('integrations.authToken')}</label>
          <input
            id="conn-token"
            type="password"
            placeholder={t('integrations.authTokenPlaceholder')}
            value={authToken}
            onChange={(e) => setAuthToken(e.target.value)}
          />
        </div>
        {connectorType === 'jira' && (
          <div className="filter-group">
            <label htmlFor="conn-project">{t('integrations.projectKey')}</label>
            <input
              id="conn-project"
              type="text"
              placeholder="SEC"
              value={projectKey}
              onChange={(e) => setProjectKey(e.target.value)}
            />
          </div>
        )}
      </div>

      <fieldset className="filter-group" style={{ marginTop: 'var(--space-4)' }}>
        <legend>{t('integrations.routingLegend')}</legend>
        {SEVERITIES.map((tier) => (
          <label key={tier} className="filter-chip">
            <input
              type="checkbox"
              checked={severities.includes(tier)}
              onChange={() => toggleSeverity(tier)}
            />
            <SeverityBadge tier={tier} />
          </label>
        ))}
      </fieldset>
      <p className="field-hint">{t('integrations.routingHint')}</p>

      <div className="form-actions" style={{ marginTop: 'var(--space-4)' }}>
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('integrations.createConnector')}
        </button>
        <button type="button" className="button-secondary" onClick={onDone}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}
