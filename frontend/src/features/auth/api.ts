import { API_BASE_URL, apiClient } from '../../lib/api'
import type { CurrentUser, LoginResponse, SsoConfig } from './types'

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

export async function fetchSsoConfig(): Promise<SsoConfig> {
  const { data } = await apiClient.get<SsoConfig>('/auth/sso/config')
  return data
}

/** A full-page navigation, not an API call: the backend redirects on to Microsoft. */
export function ssoLoginUrl(): string {
  return `${API_BASE_URL}/auth/sso/login`
}
