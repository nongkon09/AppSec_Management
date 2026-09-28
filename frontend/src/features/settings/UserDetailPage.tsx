/**
 * User detail: edit role/team/status, reset password (Requirement.md Section 4).
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import { Button, ErrorSummary, FormField, SelectBox, SwitchField, TextInput } from '../../components/ui'
import { formatDateTime } from '../../lib/format'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { IconChevronRight } from '../../lib/icons'
import type { ApprovalLevel, Role } from '../auth/types'
import { fetchUser, resetPassword, updateUser } from './api'
import { fetchDirectoryAccount } from './directoryApi'
import type { PlatformUser } from './types'
import { APPROVAL_LEVELS, ROLES } from '../auth/roles'

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
      <div className="page page-narrow">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }

  if (isError || !user) {
    return (
      <div className="page page-narrow">
        <p className="form-error" role="alert">
          {t('users.notFound')}
        </p>
        <Link to="/settings/users">{t('users.backToUsers')}</Link>
      </div>
    )
  }

  return (
    <div className="page page-narrow">
      <nav className="breadcrumb" aria-label={t('common.breadcrumb')}>
        <Link to="/settings/users">{t('users.title')}</Link>
        <IconChevronRight />
        <span aria-current="page">{user.username}</span>
      </nav>

      <header className="detail-header">
        <div className="inline">
          {user.is_active ? (
            <span className="chip chip-sla-within">{t('users.active')}</span>
          ) : (
            <span className="chip chip-sla-none">{t('users.inactive')}</span>
          )}
          {user.auth_source === 'entra' && <span className="chip">{t('users.sourceEntra')}</span>}
        </div>
        <h1>{user.full_name}</h1>
        <p className="detail-subtitle">
          {user.username} · {user.email}
        </p>
      </header>

      {/* Keyed on the user id: navigating to a different user gives a fresh form; an
          update on this one does not remount it (which would wipe the "saved"
          confirmation) since the key does not change. */}
      {user.auth_source === 'entra' ? (
        <EntraAccount key={user.id} user={user} />
      ) : (
        <>
          <EditUserForm key={user.id} user={user} />
          <ResetPasswordForm userId={user.id} />
        </>
      )}
    </div>
  )
}

function EditUserForm({
  user,
}: {
  user: {
    id: string
    full_name: string
    email: string
    role: Role | null
    owner_team: string | null
    is_active: boolean
    approval_level: ApprovalLevel
  }
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [fullName, setFullName] = useState(user.full_name)
  const [email, setEmail] = useState(user.email)
  const [role, setRole] = useState<Role>(user.role ?? 'dev_team')
  const [ownerTeam, setOwnerTeam] = useState(user.owner_team ?? '')
  const [isActive, setIsActive] = useState(user.is_active)
  const [approvalLevel, setApprovalLevel] = useState<ApprovalLevel>(user.approval_level)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  // Only AppSec and Management act as Checkers (docs/risk-exception-design.md 3.5).
  const canHoldLevel = role === 'appsec' || role === 'management'

  const mutation = useMutation({
    mutationFn: () =>
      updateUser(user.id, {
        full_name: fullName.trim(),
        email: email.trim(),
        role,
        owner_team: role === 'dev_team' ? ownerTeam.trim() : null,
        is_active: isActive,
        approval_level: canHoldLevel ? approvalLevel : 'none',
      }),
    onSuccess: (updated) => {
      queryClient.setQueryData(['user', user.id], updated)
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setSaved(true)
    },
  })

  const needsOwnerTeam = role === 'dev_team'

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

  const message = validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('users.updateFailed')) : null)

  return (
    <section aria-labelledby="edit-user-heading" className="card card-pad">
      <h2 id="edit-user-heading" className="section-title">
        {t('users.editSection')}
      </h2>
      <form className="stack" onSubmit={handleSubmit} noValidate>
        {message && <ErrorSummary ref={errorSummaryRef} title={t('users.updateErrorSummary')} message={message} />}
        <div className="form-grid">
          <FormField label={t('users.fullName')}>
            <TextInput value={fullName} onChange={(e) => setFullName(e.target.value)} required />
          </FormField>
          <FormField label={t('users.email')}>
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
        </div>
        <SwitchField checked={isActive} onChange={setIsActive}>
          {t('users.activeSwitch')}
        </SwitchField>
        <div className="form-actions">
          <Button type="submit" variant="primary" disabled={mutation.isPending}>
            {mutation.isPending ? t('common.saving') : t('common.save')}
          </Button>
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

/**
 * An Entra ID account: its role comes from app roles / groups through the mappings on the
 * Entra ID tab, so here it is shown, not edited. The on/off switch stays as an emergency
 * lock (the next SCIM sync may switch it back on; disable the person in Entra too).
 */
function EntraAccount({ user }: { user: PlatformUser }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [isActive, setIsActive] = useState(user.is_active)
  const { data: account } = useQuery({
    queryKey: ['directory-account', user.id],
    queryFn: () => fetchDirectoryAccount(user.id),
  })
  const mutation = useMutation({
    mutationFn: (active: boolean) => updateUser(user.id, { is_active: active }),
    onSuccess: (updated) => {
      queryClient.setQueryData(['user', user.id], updated)
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  return (
    <section aria-labelledby="entra-heading" className="card card-pad">
      <h2 id="entra-heading" className="section-title">
        {t('users.entraSection')}
      </h2>
      <p className="field-hint section-gap">{t('users.entraHint')}</p>
      <dl className="detail-grid section-gap">
        <div>
          <dt>{t('users.role')}</dt>
          <dd>{user.role ? t(`roles.${user.role}`) : <span className="muted">{t('users.noRole')}</span>}</dd>
        </div>
        <div>
          <dt>{t('users.approvalLevel')}</dt>
          <dd>{user.approval_level === 'none' ? '—' : t(`approvalLevel.${user.approval_level}`)}</dd>
        </div>
        <div>
          <dt>{t('inventory.ownerTeam')}</dt>
          <dd>{user.owner_team ?? '—'}</dd>
        </div>
        <div>
          <dt>{t('users.lastLogin')}</dt>
          <dd>{user.last_login_at ? formatDateTime(user.last_login_at) : t('users.neverSignedIn')}</dd>
        </div>
        <div className="field-wide">
          <dt>{t('users.entraGroups')}</dt>
          <dd>
            {account && account.groups.length > 0
              ? account.groups.map((group) => group.display_name ?? group.external_id).join(', ')
              : '—'}
          </dd>
        </div>
        <div className="field-wide">
          <dt>{t('users.entraAppRoles')}</dt>
          <dd>{account && account.app_roles.length > 0 ? account.app_roles.join(', ') : '—'}</dd>
        </div>
      </dl>
      {account && account.matched.length === 0 && (
        <p className="field-hint section-gap">{t('users.noMappingHint')}</p>
      )}
      <SwitchField
        checked={isActive}
        disabled={mutation.isPending}
        onChange={(on) => {
          setIsActive(on)
          mutation.mutate(on)
        }}
      >
        {t('users.activeSwitch')}
      </SwitchField>
      {mutation.isError && (
        <p className="form-error" role="alert">
          {apiErrorMessage(mutation.error, t('users.updateFailed'))}
        </p>
      )}
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
    <section aria-labelledby="reset-password-heading" className="card card-pad">
      <h2 id="reset-password-heading" className="section-title">
        {t('users.resetPasswordSection')}
      </h2>
      <form className="stack" onSubmit={handleSubmit} noValidate>
        {(validationError || mutation.isError) && (
          <ErrorSummary
            ref={errorSummaryRef}
            title={t('users.resetPasswordErrorSummary')}
            message={validationError ?? t('users.resetPasswordFailed')}
          />
        )}
        <FormField label={t('users.newPassword')} hint={t('users.resetPasswordHint')}>
          <TextInput
            type="password"
            value={newPassword}
            autoComplete="new-password"
            invalid={Boolean(validationError)}
            onChange={(e) => {
              setNewPassword(e.target.value)
              setValidationError(null)
            }}
          />
        </FormField>
        <div className="form-actions">
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? t('common.saving') : t('users.resetPassword')}
          </Button>
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
