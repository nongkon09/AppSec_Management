/**
 * Integration Connector Configuration (Requirement.md FR-7, Section 4: System Admin
 * manages Integration Connector Configuration).
 *
 * Jira is the one connector type with a real, working implementation on the backend —
 * ManageEngine ServiceDesk Plus and a generic webhook can be registered as configuration
 * (FR-7's "pluggable, add a destination without touching Core") but calling one is not
 * wired up yet, which this page says plainly rather than pretending otherwise.
 */
import { Switch } from '@headlessui/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { SeverityBadge, SeverityIcon } from '../../components/SeverityBadge'
import { Button, ConfirmDialog, ErrorSummary, FormField, Modal, SelectBox, TextInput, TogglePill } from '../../components/ui'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { IconPlus } from '../../lib/icons'
import { SEVERITY_LABEL } from '../findings/labels'
import type { SeverityTier } from '../findings/types'
import { createConnector, deleteConnector, listConnectors, updateConnector } from './integrationApi'
import type { ConnectorType, IntegrationConnector } from './integrationTypes'
import { SettingsTabs } from './SettingsTabs'

const CONNECTOR_TYPES: ConnectorType[] = ['jira', 'service_desk_plus', 'generic_webhook']
const SEVERITIES: SeverityTier[] = ['critical', 'high', 'medium', 'low']

export function IntegrationsPage() {
  const { t } = useTranslation()
  const [showCreate, setShowCreate] = useState(false)
  const [deleting, setDeleting] = useState<IntegrationConnector | null>(null)
  const queryClient = useQueryClient()
  const { data: connectors, isLoading, isError } = useQuery({
    queryKey: ['integration-connectors'],
    queryFn: listConnectors,
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, isEnabled }: { id: string; isEnabled: boolean }) => updateConnector(id, { is_enabled: isEnabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integration-connectors'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteConnector,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integration-connectors'] })
      setDeleting(null)
    },
  })

  return (
    <div className="page">
      <SettingsTabs />
      <div className="page-head">
        <div>
          <h1>{t('integrations.title')}</h1>
          <p className="page-sub">{t('integrations.subtitle')}</p>
        </div>
        <Button variant="primary" onClick={() => setShowCreate(true)}>
          <IconPlus />
          {t('integrations.addConnector')}
        </Button>
      </div>

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title={t('integrations.addConnector')}>
        <CreateConnectorForm onDone={() => setShowCreate(false)} />
      </Modal>

      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        title={t('integrations.confirmDeleteTitle', { name: deleting?.name ?? '' })}
        description={t('integrations.confirmDeleteBody')}
        confirmLabel={t('common.delete')}
        pending={deleteMutation.isPending}
      />

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('integrations.loadError')}
        </p>
      )}
      {(toggleMutation.isError || deleteMutation.isError) && (
        <p className="form-error" role="alert">
          {apiErrorMessage(toggleMutation.error ?? deleteMutation.error, t('integrations.updateFailed'))}
        </p>
      )}

      {connectors && connectors.length === 0 && <p className="empty-state">{t('integrations.empty')}</p>}

      {connectors && connectors.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="sticky-column">
                  {t('integrations.name')}
                </th>
                <th scope="col">{t('integrations.routing')}</th>
                <th scope="col">{t('integrations.status')}</th>
                <th scope="col">
                  <span className="visually-hidden">{t('common.actions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {connectors.map((connector) => (
                <tr key={connector.id}>
                  <th scope="row" className="sticky-column">
                    {connector.name}
                    <span className="cell-sub">
                      <span className="mono">{connector.connector_type}</span> · <span className="mono">{connector.base_url}</span>
                    </span>
                    {connector.connector_type !== 'jira' && (
                      <span className="cell-sub">{t('integrations.notImplementedYet')}</span>
                    )}
                  </th>
                  <td>
                    {connector.routing_severities.length === 0 ? (
                      <span className="muted">{t('integrations.manualOnly')}</span>
                    ) : (
                      <div className="cell-chips">
                        {connector.routing_severities.map((tier) => (
                          <SeverityBadge key={tier} tier={tier} />
                        ))}
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="inline">
                      <Switch
                        checked={connector.is_enabled}
                        onChange={(on) => toggleMutation.mutate({ id: connector.id, isEnabled: on })}
                        disabled={toggleMutation.isPending}
                        className="switch"
                        aria-label={t('integrations.enableLabel', { name: connector.name })}
                      >
                        <span className="switch-thumb" />
                      </Switch>
                      <span>{connector.is_enabled ? t('integrations.enabled') : t('integrations.disabled')}</span>
                    </div>
                  </td>
                  <td className="numeric">
                    <Button small variant="ghost" onClick={() => setDeleting(connector)}>
                      {t('common.delete')}
                    </Button>
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

  function toggleSeverity(tier: SeverityTier, on: boolean) {
    setSeverities((prev) => (on ? [...prev, tier] : prev.filter((item) => item !== tier)))
  }

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

  const message =
    validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('integrations.createFailed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorSummaryRef} title={t('integrations.createErrorSummary')} message={message} />}
      <div className="form-grid">
        <FormField label={t('integrations.name')}>
          <TextInput value={name} onChange={(e) => setName(e.target.value)} />
        </FormField>
        <FormField label={t('integrations.type')}>
          <SelectBox
            value={connectorType}
            onChange={setConnectorType}
            options={CONNECTOR_TYPES.map((type) => ({ value: type, label: <span className="mono">{type}</span> }))}
          />
        </FormField>
        <FormField label={t('integrations.baseUrl')} className="field-wide">
          <TextInput placeholder="https://example.atlassian.net" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
        </FormField>
        <FormField label={t('integrations.authToken')}>
          <TextInput
            type="password"
            autoComplete="off"
            placeholder={t('integrations.authTokenPlaceholder')}
            value={authToken}
            onChange={(e) => setAuthToken(e.target.value)}
          />
        </FormField>
        {connectorType === 'jira' && (
          <FormField label={t('integrations.projectKey')}>
            <TextInput placeholder="SEC" value={projectKey} onChange={(e) => setProjectKey(e.target.value)} />
          </FormField>
        )}
      </div>

      <div className="field">
        <span className="field-label" id="routing-label">
          {t('integrations.routingLegend')}
        </span>
        <div className="pill-row" role="group" aria-labelledby="routing-label">
          {SEVERITIES.map((tier) => (
            <TogglePill key={tier} checked={severities.includes(tier)} onChange={(on) => toggleSeverity(tier, on)}>
              <SeverityIcon tier={tier} />
              {SEVERITY_LABEL[tier]}
            </TogglePill>
          ))}
        </div>
        <p className="field-hint">{t('integrations.routingHint')}</p>
      </div>

      <div className="modal-actions">
        <Button onClick={onDone}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('integrations.createConnector')}
        </Button>
      </div>
    </form>
  )
}
