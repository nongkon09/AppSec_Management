/**
 * Where the backend sends the browser after Microsoft sign-in. The platform token (or a
 * refusal reason) arrives in the URL fragment, which never reaches a server or its logs;
 * it is removed from the address bar straight away.
 */
import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { useAuth } from './context'

export function SsoCallbackPage() {
  const { t } = useTranslation()
  const { acceptToken } = useAuth()
  const navigate = useNavigate()
  const handled = useRef(false)

  useEffect(() => {
    if (handled.current) return
    handled.current = true
    const params = new URLSearchParams(window.location.hash.slice(1))
    window.history.replaceState(null, '', window.location.pathname)
    const token = params.get('token')
    if (!token) {
      navigate('/login', { replace: true, state: { ssoError: params.get('error') ?? 'sso_failed' } })
      return
    }
    acceptToken(token)
      .then(() => navigate('/', { replace: true }))
      .catch(() => navigate('/login', { replace: true, state: { ssoError: 'sso_failed' } }))
  }, [acceptToken, navigate])

  return (
    <div className="auth-page">
      <p role="status">{t('login.sso.completing')}</p>
    </div>
  )
}
