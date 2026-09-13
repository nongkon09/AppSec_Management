import { apiClient } from '../../lib/api'
import type { ConnectorCreateInput, ConnectorUpdateInput, IntegrationConnector } from './integrationTypes'

export async function listConnectors(): Promise<IntegrationConnector[]> {
  const { data } = await apiClient.get<IntegrationConnector[]>('/integrations/connectors')
  return data
}

export async function createConnector(
  payload: ConnectorCreateInput,
): Promise<IntegrationConnector> {
  const { data } = await apiClient.post<IntegrationConnector>('/integrations/connectors', payload)
  return data
}

export async function updateConnector(
  connectorId: string,
  payload: ConnectorUpdateInput,
): Promise<IntegrationConnector> {
  const { data } = await apiClient.patch<IntegrationConnector>(
    `/integrations/connectors/${connectorId}`,
    payload,
  )
  return data
}

export async function deleteConnector(connectorId: string): Promise<void> {
  await apiClient.delete(`/integrations/connectors/${connectorId}`)
}
