import { apiClient } from '../../lib/api'
import type { ControlInput, ControlUpdateInput, SecurityControl } from './types'

export async function listControls(): Promise<SecurityControl[]> {
  const { data } = await apiClient.get<SecurityControl[]>('/controls')
  return data
}

export async function createControl(payload: ControlInput): Promise<SecurityControl> {
  const { data } = await apiClient.post<SecurityControl>('/controls', payload)
  return data
}

export async function updateControl(id: string, payload: ControlUpdateInput): Promise<SecurityControl> {
  const { data } = await apiClient.patch<SecurityControl>(`/controls/${id}`, payload)
  return data
}
