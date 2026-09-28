import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Button, FormField, TextInput } from '../../components/ui'
import { IconShieldCheck } from '../../lib/icons'
import { useAuth } from './context'

export function LoginPage() {
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
    } catch {
      setError(t('login.error'))
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={handleSubmit}>
        <div className="auth-brand">
          <span className="brand-mark">
            <IconShieldCheck />
          </span>
          {t('appName')}
        </div>
        <h1>{t('login.title')}</h1>
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
        <Button type="submit" variant="primary" disabled={isSubmitting}>
          {isSubmitting ? t('login.submitting') : t('login.submit')}
        </Button>
      </form>
    </div>
  )
}
