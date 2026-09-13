/**
 * User & Role Management (Requirement.md Section 4: System Admin — "จัดการ User/Role").
 *
 * Local username/password administration: the auth stub this platform ships until SSO
 * (SAML2/OIDC, Section 7) replaces it. Admin-only — distinct from AppSec's Policy/Waiver
 * ownership (Section 4's RACI splits these across two different roles).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { IconPlus, IconTeam } from '../../lib/icons'
import type { Role } from '../auth/types'
import { createUser, listUsers } from './api'
import { SettingsTabs } from './SettingsTabs'

const ROLES: Role[] = ['appsec', 'dev_team', 'legal', 'management', 'audit', 'admin']

export function UsersListPage() {
  const { t } = useTranslation()
  const [showCreate, setShowCreate] = useState(false)
  const { data, isLoading, isError } = useQuery({
    queryKey: ['users'],
    queryFn: () => listUsers(),
  })

  return (
    <div className="page">
      <SettingsTabs />
      <div className="page-head">
        <div>
          <h1 className="page-title">{t('users.title')}</h1>
          <div className="page-sub">{t('users.subtitle')}</div>
        </div>
        {!showCreate && (
          <button type="button" onClick={() => setShowCreate(true)}>
            <IconPlus />
            {t('users.addUser')}
          </button>
        )}
      </div>

      {showCreate && <CreateUserForm onDone={() => setShowCreate(false)} />}

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('users.loadError')}
        </p>
      )}

      {data && (
        <>
          <p className="result-count" role="status">
            {t('users.resultCount', { count: data.total })}
          </p>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col" className="sticky-column">
                    {t('users.username')}
                  </th>
                  <th scope="col">{t('users.fullName')}</th>
                  <th scope="col">{t('users.email')}</th>
                  <th scope="col">{t('users.role')}</th>
                  <th scope="col">{t('inventory.ownerTeam')}</th>
                  <th scope="col">{t('users.status')}</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((user) => (
                  <tr key={user.id}>
                    <th scope="row" className="sticky-column">
                      <Link to={`/settings/users/${user.id}`}>{user.username}</Link>
                    </th>
                    <td>{user.full_name}</td>
                    <td className="mono">{user.email}</td>
                    <td>{t(`roles.${user.role}`)}</td>
                    <td>
                      {user.owner_team ?? <span className="muted">—</span>}
                    </td>
                    <td>
                      {user.is_active ? (
                        <span className="chip chip-sla-within">{t('users.active')}</span>
                      ) : (
                        <span className="chip chip-sla-none">{t('users.inactive')}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

function CreateUserForm({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [role, setRole] = useState<Role>('dev_team')
  const [ownerTeam, setOwnerTeam] = useState('')
  const [password, setPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      onDone()
    },
  })

  const needsOwnerTeam = role === 'dev_team'

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (!username.trim() || !email.trim() || !fullName.trim() || password.length < 8) {
      setValidationError(t('users.createValidationError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    if (needsOwnerTeam && !ownerTeam.trim()) {
      // Section 4 fail-closed rule: a Dev Team account with no OwnerTeam sees nothing.
      setValidationError(t('users.ownerTeamRequiredError'))
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate({
      username: username.trim(),
      email: email.trim(),
      full_name: fullName.trim(),
      role,
      owner_team: needsOwnerTeam ? ownerTeam.trim() : null,
      password,
    })
  }

  const serverErrorMessage =
    mutation.isError &&
    ((mutation.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
      t('users.createFailed'))

  return (
    <form className="card card-pad" onSubmit={handleSubmit} noValidate style={{ marginBottom: 'var(--space-5)' }}>
      {(validationError || serverErrorMessage) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('users.createErrorSummary')}</p>
          <ul>
            <li>{validationError || serverErrorMessage}</li>
          </ul>
        </div>
      )}

      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="new-username">{t('users.username')}</label>
          <input
            id="new-username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="filter-group">
          <label htmlFor="new-email">{t('users.email')}</label>
          <input
            id="new-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="filter-group">
          <label htmlFor="new-fullname">{t('users.fullName')}</label>
          <input
            id="new-fullname"
            type="text"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            required
          />
        </div>
        <div className="filter-group">
          <label htmlFor="new-role">{t('users.role')}</label>
          <select id="new-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {t(`roles.${r}`)}
              </option>
            ))}
          </select>
        </div>
        {needsOwnerTeam && (
          <div className="filter-group">
            <label htmlFor="new-team">
              <IconTeam /> {t('inventory.ownerTeam')}
            </label>
            <input
              id="new-team"
              type="text"
              value={ownerTeam}
              onChange={(e) => setOwnerTeam(e.target.value)}
              required
            />
          </div>
        )}
        <div className="filter-group">
          <label htmlFor="new-password">{t('users.initialPassword')}</label>
          <input
            id="new-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
      </div>

      <div className="form-actions" style={{ marginTop: 'var(--space-4)' }}>
        <button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('users.createUser')}
        </button>
        <button type="button" className="button-secondary" onClick={onDone}>
          {t('common.cancel')}
        </button>
      </div>
    </form>
  )
}
