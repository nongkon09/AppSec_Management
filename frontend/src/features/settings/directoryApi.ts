import { apiClient } from '../../lib/api'
import type {
  DirectoryAccount,
  DirectoryGroup,
  DirectoryStatus,
  RoleMapping,
  RoleMappingInput,
  RoleMappingSaved,
} from './directoryTypes'

export async function fetchDirectoryStatus(): Promise<DirectoryStatus> {
  const { data } = await apiClient.get<DirectoryStatus>('/directory/status')
  return data
}

export async function listRoleMappings(): Promise<RoleMapping[]> {
  const { data } = await apiClient.get<RoleMapping[]>('/directory/mappings')
  return data
}

export async function createRoleMapping(payload: RoleMappingInput): Promise<RoleMappingSaved> {
  const { data } = await apiClient.post<RoleMappingSaved>('/directory/mappings', payload)
  return data
}

export async function updateRoleMapping(id: string, payload: RoleMappingInput): Promise<RoleMappingSaved> {
  const { data } = await apiClient.put<RoleMappingSaved>(`/directory/mappings/${id}`, payload)
  return data
}

export async function deleteRoleMapping(id: string): Promise<RoleMappingSaved> {
  const { data } = await apiClient.delete<RoleMappingSaved>(`/directory/mappings/${id}`)
  return data
}

export async function listDirectoryGroups(): Promise<DirectoryGroup[]> {
  const { data } = await apiClient.get<DirectoryGroup[]>('/directory/groups')
  return data
}

export async function fetchDirectoryAccount(userId: string): Promise<DirectoryAccount> {
  const { data } = await apiClient.get<DirectoryAccount>(`/directory/users/${userId}`)
  return data
}
