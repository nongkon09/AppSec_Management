import { apiClient } from '../../lib/api'
import type { PaginatedUsers, PlatformUser, UserCreateInput, UserUpdateInput } from './types'

export async function listUsers(skip = 0, limit = 50): Promise<PaginatedUsers> {
  const { data } = await apiClient.get<PaginatedUsers>('/users', { params: { skip, limit } })
  return data
}

export async function fetchUser(userId: string): Promise<PlatformUser> {
  const { data } = await apiClient.get<PlatformUser>(`/users/${userId}`)
  return data
}

export async function createUser(payload: UserCreateInput): Promise<PlatformUser> {
  const { data } = await apiClient.post<PlatformUser>('/users', payload)
  return data
}

export async function updateUser(
  userId: string,
  payload: UserUpdateInput,
): Promise<PlatformUser> {
  const { data } = await apiClient.patch<PlatformUser>(`/users/${userId}`, payload)
  return data
}

export async function resetPassword(userId: string, newPassword: string): Promise<PlatformUser> {
  const { data } = await apiClient.post<PlatformUser>(`/users/${userId}/reset-password`, {
    new_password: newPassword,
  })
  return data
}
