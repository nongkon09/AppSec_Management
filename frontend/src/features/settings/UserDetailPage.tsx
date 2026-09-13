/**
 * User detail: edit role/team/status, reset password (Requirement.md Section 4).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { IconChevronRight } from '../../lib/icons'
import type { Role } from '../auth/types'
import { fetchUser, resetPassword, updateUser } from './api'

const ROLES: Role[] = ['appsec', 'dev_team', 'legal', 'management', 'audit', 'admin']

export function UserDetailPage() {
  const { t } = useTranslation()
  const { userId } = useParams<{ userId: string }>()

  const { data: user, isLoading, isError } = useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetchUser(userId!),
    enabled: Boolean(userId),
  })

  if (isLoading) {
    return (
      <div className="page">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }

  if (isError || !user) {
    return (
      <div className="page">
        <p className="form-error" role="alert">
          {t('users.notFound')}
        </p>
        <Link to="/settings/users">{t('users.backToUsers')}</Link>
      </div>
    )
  }

  return (
    <div className="page">
      <nav className="breadcrumb" aria-label={t('common.breadcrumb')}>
        <Link to="/settings/users">{t('users.title')}</Link>
        <IconChevronRight />
        <span aria-current="page">{user.username}</span>
      </nav>

      <div className="detail-header">
        <h1>{user.full_name}</h1>
        <div className="detail-header-chips">
          {user.is_active ? (
            <span className="chip chip-sla-within">{t('users.active')}</span>
          ) : (
            <span className="chip chip-sla-none">{t('users.inactive')}</span>
          )}
        </div>
      </div>
      <p className="detail-meta">
        {user.username} &middot; {user.email}
      </p>

      {/* Keyed on the user id: navigating to a different user gives a fresh form; an
          update on this one does not remount it (which would wipe the "saved"
          confirmation) since the key does not change. */}
      <EditUserForm key={user.id} user={user} />
      <ResetPasswordForm userId={user.id} />
    </div>
  )
}

function EditUserForm({
  user,
}: {
  user: { id: string; full_name: string; email: string; role: Role; owner_team: string | null; is_active: boolean }
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [fullName, setFullName] = useState(user.full_name)
  const [email, setEmail] = useState(user.email)
  const [role, setRole] = useState<Role>(user.role)
  const [ownerTeam, setOwnerTeam] = useState(user.owner_team ?? '')
  const [isActive, setIsActive] = useState(user.is_active)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: () =>
      updateUser(user.id, {
        full_name: fullName.trim(),
        email: email.trim(),
        role,
        owner_team: role === 'dev_team' ? ownerTeam.trim() : null,
        is_active: isActive,
      }),
    onSuccess: (updated) => {
      queryClient.setQueryData(['user', user.id], updated)
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setSaved(true)
    },
  })

  const needsOwnerTeam = role === 'dev_team'
  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('users.updateFailed'))

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setSaved(false)
    if (needsOwnerTeam && !ownerTeam.trim()) {
      setValidationError(t('users.ownerTeamRequiredError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate()
  }

  return (
    <section aria-labelledby="edit-user-heading">
      <h2 id="edit-user-heading" className="section-title">
        {t('users.editSection')}
      </h2>
      <form onSubmit={handleSubmit} noValidate>
        {(validationError || serverErrorMessage) && (
          <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
            <p>{t('users.updateErrorSummary')}</p>
            <ul>
              <li>{validationError || serverErrorMessage}</li>
            </ul>
          </div>
        )}

        <div className="filter-bar">
          <div className="filter-group">
            <label htmlFor="edit-fullname">{t('users.fullName')}</label>
            <input
              id="edit-fullname"
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
            />
          </div>
          <div className="filter-group">
            <label htmlFor="edit-email">{t('users.email')}</label>
            <input
              id="edit-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="filter-group">
            <label htmlFor="edit-role">{t('users.role')}</label>
            <select id="edit-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {t(`roles.${r}`)}
                </option>
              ))}
            </select>
          </div>
          {needsOwnerTeam && (
            <div className="filter-group">
              <label htmlFor="edit-team">{t('inventory.ownerTeam')}</label>
              <input
                id="edit-team"
                type="text"
                value={ownerTeam}
                onChange={(e) => setOwnerTeam(e.target.value)}
                required
              />
            </div>
          )}
          <div className="filter-group">
            <label className="checkbox-row" htmlFor="edit-active">
              <input
                id="edit-active"
                type="checkbox"
                checked={isActive}
                onChange={(e) => setIsActive(e.target.checked)}
              />
              {t('users.active')}
            </label>
          </div>
        </div>

        <div className="form-actions" style={{ marginTop: 'var(--space-4)' }}>
          <button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? t('common.saving') : t('common.save')}
          </button>
          {saved && (
            <span className="form-success" role="status">
              {t('users.updateSaved')}
            </span>
          )}
        </div>
      </form>
    </section>
  )
}

function ResetPasswordForm({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const [newPassword, setNewPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: (password: string) => resetPassword(userId, password),
    onSuccess: () => setNewPassword(''),
  })

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (newPassword.length < 8) {
      setValidationError(t('users.passwordTooShortError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate(newPassword)
  }

  return (
    <section aria-labelledby="reset-password-heading">
      <h2 id="reset-password-heading" className="section-title">
        {t('users.resetPasswordSection')}
      </h2>
      <p className="field-hint">{t('users.resetPasswordHint')}</p>
      <form onSubmit={handleSubmit} noValidate>
        {(validationError || mutation.isError) && (
          <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
            <p>{t('users.resetPasswordErrorSummary')}</p>
            <ul>
              <li>{validationError ?? t('users.resetPasswordFailed')}</li>
            </ul>
          </div>
        )}
        <div className="field-row">
          <label htmlFor="new-password-reset">{t('users.newPassword')}</label>
          <input
            id="new-password-reset"
            type="password"
            value={newPassword}
            onChange={(e) => {
              setNewPassword(e.target.value)
              setValidationError(null)
            }}
          />
        </div>
        <div className="form-actions">
          <button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? t('common.saving') : t('users.resetPassword')}
          </button>
          {mutation.isSuccess && (
            <span className="form-success" role="status">
              {t('users.resetPasswordSuccess')}
            </span>
          )}
        </div>
      </form>
    </section>
  )
}
