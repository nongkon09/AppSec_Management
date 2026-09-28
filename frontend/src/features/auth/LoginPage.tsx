import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate } from 'react-router-dom'
import { Button, FormField, TextInput } from '../../components/ui'
import { IconShieldCheck } from '../../lib/icons'
import { buttonClass } from '../../lib/ui-helpers'
import { fetchSsoConfig, ssoLoginUrl } from './api'
import { useAuth } from './context'

/** Reasons the Microsoft sign-in can come back refused (backend SignInRefused codes). */
const SSO_ERRORS = ['not_assigned', 'inactive', 'local_conflict', 'not_provisioned', 'cancelled', 'sso_failed']

export function LoginPage() {
  const { t } = useTranslation()
  const location = useLocation()
  const { data: sso } = useQuery({ queryKey: ['sso-config'], queryFn: fetchSsoConfig, retry: false })
  const ssoError = (location.state as { ssoError?: string } | null)?.ssoError
  const [showLocal, setShowLocal] = useState(false)

  const ssoEnabled = sso?.enabled ?? false
  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <span className="brand-mark">
            <IconShieldCheck />
          </span>
          {t('appName')}
        </div>
        <h1>{t('login.title')}</h1>
        {ssoError && (
          <p className="form-error" role="alert">
            {t(`login.sso.${SSO_ERRORS.includes(ssoError) ? ssoError : 'sso_failed'}`)}
          </p>
        )}
        {ssoEnabled && (
          <a className={buttonClass('primary') + ' auth-sso'} href={ssoLoginUrl()}>
            <MicrosoftLogo />
            {t('login.sso.button')}
          </a>
        )}
        {ssoEnabled && !showLocal ? (
          <button type="button" className="auth-switch" onClick={() => setShowLocal(true)}>
            {t('login.sso.useLocal')}
          </button>
        ) : (
          <LocalLoginForm
            secondary={ssoEnabled}
            hint={ssoEnabled && !sso?.local_login_enabled ? t('login.sso.localAdminsOnly') : undefined}
          />
        )}
      </div>
    </div>
  )
}

function LocalLoginForm({ hint, secondary = false }: { hint?: string; secondary?: boolean }) {
  const { t } = useTranslation()
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setIsSubmitting(true)
    try {
      await login(username, password)
      navigate('/', { replace: true })
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status
      setError(status === 403 ? t('login.sso.useMicrosoft') : t('login.error'))
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      {hint && <p className="field-hint">{hint}</p>}
      <FormField label={t('login.username')}>
        <TextInput value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
      </FormField>
      <FormField label={t('login.password')}>
        <TextInput
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          required
        />
      </FormField>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <Button type="submit" variant={secondary ? 'secondary' : 'primary'} disabled={isSubmitting}>
        {isSubmitting ? t('login.submitting') : t('login.submit')}
      </Button>
    </form>
  )
}

/** The four-square Microsoft mark, as Microsoft's sign-in button guidance asks for. */
function MicrosoftLogo() {
  return (
    <svg width="16" height="16" viewBox="0 0 21 21" aria-hidden="true">
      <rect x="1" y="1" width="9" height="9" fill="#f25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
      <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
      <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
    </svg>
  )
}
