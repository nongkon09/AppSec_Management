import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { fetchCurrentUser, login as loginRequest } from './api'
import { AuthContext } from './context'
import type { CurrentUser } from './types'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [isLoading, setIsLoading] = useState(() => Boolean(localStorage.getItem('access_token')))

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    if (!token) {
      return
    }
    fetchCurrentUser()
      .then(setUser)
      .catch(() => localStorage.removeItem('access_token'))
      .finally(() => setIsLoading(false))
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const { access_token } = await loginRequest(username, password)
    localStorage.setItem('access_token', access_token)
    const currentUser = await fetchCurrentUser()
    setUser(currentUser)
  }, [])

  const acceptToken = useCallback(async (token: string) => {
    localStorage.setItem('access_token', token)
    try {
      setUser(await fetchCurrentUser())
    } catch (error) {
      localStorage.removeItem('access_token')
      throw error
    }
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem('access_token')
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({ user, isLoading, login, acceptToken, logout }),
    [user, isLoading, login, acceptToken, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
