import { apiClient } from '../../lib/api'
import type { CurrentUser, LoginResponse } from './types'

export async function login(username: string, password: string): Promise<LoginResponse> {
  const form = new URLSearchParams()
  form.set('username', username)
  form.set('password', password)
  const { data } = await apiClient.post<LoginResponse>('/auth/login', form, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function fetchCurrentUser(): Promise<CurrentUser> {
  const { data } = await apiClient.get<CurrentUser>('/auth/me')
  return data
}
