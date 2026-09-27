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
import { Button, ErrorSummary, FormField, Modal, SelectBox, TextInput } from '../../components/ui'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { IconPlus } from '../../lib/icons'
import { APPROVAL_LEVELS, ROLES } from '../auth/roles'
import type { ApprovalLevel, Role } from '../auth/types'
import { createUser, listUsers } from './api'
import { SettingsTabs } from './SettingsTabs'

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
          <h1>
            {t('users.title')}
            {data && <span className="count">{data.total}</span>}
          </h1>
          <p className="page-sub">{t('users.subtitle')}</p>
        </div>
        <Button variant="primary" onClick={() => setShowCreate(true)}>
          <IconPlus />
          {t('users.addUser')}
        </Button>
      </div>

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title={t('users.addUser')}>
        <CreateUserForm onDone={() => setShowCreate(false)} />
      </Modal>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('users.loadError')}
        </p>
      )}

      {data && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="sticky-column">
                  {t('users.fullName')}
                </th>
                <th scope="col">{t('users.email')}</th>
                <th scope="col">{t('users.role')}</th>
                <th scope="col">{t('users.approvalLevel')}</th>
                <th scope="col">{t('inventory.ownerTeam')}</th>
                <th scope="col">{t('users.status')}</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((user) => (
                <tr key={user.id}>
                  <th scope="row" className="sticky-column">
                    <Link to={`/settings/users/${user.id}`}>{user.full_name}</Link>
                    <span className="cell-sub mono">{user.username}</span>
                  </th>
                  <td className="mono">{user.email}</td>
                  <td>{t(`roles.${user.role}`)}</td>
                  <td>
                    {user.approval_level === 'none' ? (
                      <span className="muted">—</span>
                    ) : (
                      t(`approvalLevel.${user.approval_level}`)
                    )}
                  </td>
                  <td>{user.owner_team ?? <span className="muted">—</span>}</td>
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
  const [approvalLevel, setApprovalLevel] = useState<ApprovalLevel>('none')
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
  // Only AppSec and Management act as Checkers (docs/risk-exception-design.md 3.5).
  const canHoldLevel = role === 'appsec' || role === 'management'

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
      approval_level: canHoldLevel ? approvalLevel : 'none',
      password,
    })
  }

  const message = validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('users.createFailed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorSummaryRef} title={t('users.createErrorSummary')} message={message} />}
      <div className="form-grid">
        <FormField label={t('users.fullName')}>
          <TextInput value={fullName} onChange={(e) => setFullName(e.target.value)} required />
        </FormField>
        <FormField label={t('users.username')}>
          <TextInput value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" required />
        </FormField>
        <FormField label={t('users.email')} className="field-wide">
          <TextInput type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </FormField>
        <FormField label={t('users.role')}>
          <SelectBox value={role} onChange={setRole} options={ROLES.map((r) => ({ value: r, label: t(`roles.${r}`) }))} />
        </FormField>
        {needsOwnerTeam && (
          <FormField label={t('inventory.ownerTeam')}>
            <TextInput value={ownerTeam} onChange={(e) => setOwnerTeam(e.target.value)} required />
          </FormField>
        )}
        {canHoldLevel && (
          <FormField label={t('users.approvalLevel')} hint={t('users.approvalLevelHint')}>
          <SelectBox
            value={approvalLevel}
            onChange={setApprovalLevel}
            options={APPROVAL_LEVELS.map((l) => ({ value: l, label: t(`approvalLevel.${l}`) }))}
          />
        </FormField>
        )}
        <FormField label={t('users.initialPassword')} hint={t('users.passwordHint')} className="field-wide">
          <TextInput
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            required
          />
        </FormField>
      </div>
      <div className="modal-actions">
        <Button onClick={onDone}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('users.createUser')}
        </Button>
      </div>
    </form>
  )
}
