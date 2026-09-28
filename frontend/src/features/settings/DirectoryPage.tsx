/**
 * Entra ID (docs/entra-id.md): whether sign-in with Microsoft and SCIM provisioning are
 * switched on, the two addresses to paste into Entra, and the rules that turn an app role
 * or group membership into a platform role. Secrets live in the server's .env, never here.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button, ConfirmDialog, ErrorSummary, FormField, Modal, PillGroup, SelectBox, TextInput } from '../../components/ui'
import { IconCheck, IconPlus } from '../../lib/icons'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { APPROVAL_LEVELS, ROLES } from '../auth/roles'
import type { ApprovalLevel, Role } from '../auth/types'
import {
  createRoleMapping,
  deleteRoleMapping,
  fetchDirectoryStatus,
  listDirectoryGroups,
  listRoleMappings,
  updateRoleMapping,
} from './directoryApi'
import type { MappingKind, RoleMapping, RoleMappingSaved } from './directoryTypes'
import { SettingsTabs } from './SettingsTabs'

// The CI/CD service account stays local; it can never come from the directory.
const MAPPABLE_ROLES = ROLES.filter((role) => role !== 'pipeline')

export function DirectoryPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<RoleMapping | 'new' | null>(null)
  const [deleting, setDeleting] = useState<RoleMapping | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  // Keep the last form in the modal while it fades out, so its title does not flip.
  const [shown, setShown] = useState<RoleMapping | 'new' | null>(null)
  if (editing !== null && editing !== shown) setShown(editing)

  const { data: status } = useQuery({ queryKey: ['directory-status'], queryFn: fetchDirectoryStatus })
  const { data: mappings, isLoading, isError } = useQuery({
    queryKey: ['role-mappings'],
    queryFn: listRoleMappings,
  })

  function saved(result: RoleMappingSaved) {
    queryClient.invalidateQueries({ queryKey: ['role-mappings'] })
    queryClient.invalidateQueries({ queryKey: ['users'] })
    setNotice(t('directory.savedNotice', { count: result.users_changed }))
  }

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteRoleMapping(id),
    onSuccess: (result) => {
      saved(result)
      setDeleting(null)
    },
  })

  return (
    <div className="page">
      <SettingsTabs />
      <div className="page-head">
        <div>
          <h1>{t('directory.title')}</h1>
          <p className="page-sub">{t('directory.subtitle')}</p>
        </div>
      </div>

      {status && (
        <section className="card card-pad section-gap" aria-labelledby="directory-connection">
          <h2 id="directory-connection" className="section-title">
            {t('directory.connection')}
          </h2>
          <dl className="detail-grid">
            <div>
              <dt>{t('directory.sso')}</dt>
              <dd>
                <OnOff on={status.sso_enabled} />
              </dd>
            </div>
            <div>
              <dt>{t('directory.scim')}</dt>
              <dd>
                <OnOff on={status.scim_enabled} />
              </dd>
            </div>
            <div>
              <dt>{t('directory.localLogin')}</dt>
              <dd>{status.local_login_enabled ? t('directory.localEveryone') : t('directory.localAdminsOnly')}</dd>
            </div>
            <div>
              <dt>{t('directory.jit')}</dt>
              <dd>{status.jit_provisioning ? t('directory.jitOn') : t('directory.jitOff')}</dd>
            </div>
          </dl>
          <div className="copy-fields">
            <CopyField label={t('directory.redirectUri')} value={status.redirect_uri} />
            <CopyField label={t('directory.scimUrl')} value={status.scim_url} />
          </div>
          <p className="field-hint">{t('directory.secretsHint')}</p>
        </section>
      )}

      <section className="card card-pad" aria-labelledby="directory-mappings">
        <div className="section-head">
          <div>
            <h2 id="directory-mappings" className="section-title">
              {t('directory.mappings')}
            </h2>
            <p className="field-hint">{t('directory.precedence')}</p>
          </div>
          <Button variant="primary" onClick={() => setEditing('new')}>
            <IconPlus />
            {t('directory.addMapping')}
          </Button>
        </div>

        {notice && (
          <p className="form-success" role="status">
            {notice}
          </p>
        )}
        {isLoading && <p role="status">{t('common.loading')}</p>}
        {isError && (
          <p className="form-error" role="alert">
            {t('directory.loadError')}
          </p>
        )}
        {deleteMutation.isError && (
          <p className="form-error" role="alert">
            {apiErrorMessage(deleteMutation.error, t('directory.saveFailed'))}
          </p>
        )}
        {mappings && mappings.length === 0 && <p className="empty-state">{t('directory.empty')}</p>}
        {mappings && mappings.length > 0 && (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col" className="sticky-column">
                    {t('directory.source')}
                  </th>
                  <th scope="col">{t('users.role')}</th>
                  <th scope="col">{t('users.approvalLevel')}</th>
                  <th scope="col">{t('inventory.ownerTeam')}</th>
                  <th scope="col">
                    <span className="visually-hidden">{t('common.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((mapping) => (
                  <tr key={mapping.id}>
                    <th scope="row" className="sticky-column">
                      {mapping.kind === 'group' ? mapping.group_name ?? t('directory.unnamedGroup') : mapping.value}
                      <span className="cell-sub">
                        {t(`directory.kind.${mapping.kind}`)}
                        {mapping.kind === 'group' && <span className="mono"> · {mapping.value}</span>}
                      </span>
                    </th>
                    <td>{t(`roles.${mapping.role}`)}</td>
                    <td>
                      {mapping.approval_level === 'none' ? (
                        <span className="muted">—</span>
                      ) : (
                        t(`approvalLevel.${mapping.approval_level}`)
                      )}
                    </td>
                    <td>{mapping.owner_team ?? <span className="muted">—</span>}</td>
                    <td className="numeric">
                      <div className="row-actions">
                        <Button small variant="ghost" onClick={() => setEditing(mapping)}>
                          {t('common.edit')}
                        </Button>
                        <Button small variant="ghost" onClick={() => setDeleting(mapping)}>
                          {t('common.delete')}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={shown === 'new' ? t('directory.addMapping') : t('directory.editMapping')}
      >
        {shown !== null && (
          <MappingForm
            key={shown === 'new' ? 'new' : shown.id}
            mapping={shown === 'new' ? null : shown}
            onSaved={(result) => {
              saved(result)
              setEditing(null)
            }}
            onCancel={() => setEditing(null)}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        title={t('directory.confirmDeleteTitle')}
        description={t('directory.confirmDeleteBody')}
        confirmLabel={t('common.delete')}
        pending={deleteMutation.isPending}
      />
    </div>
  )
}

function OnOff({ on }: { on: boolean }) {
  const { t } = useTranslation()
  return on ? (
    <span className="chip chip-sla-within">{t('directory.on')}</span>
  ) : (
    <span className="chip chip-sla-none">{t('directory.off')}</span>
  )
}

function CopyField({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      setCopied(false)
    }
  }
  return (
    <div className="copy-field">
      <span className="field-label">{label}</span>
      <div className="copy-row">
        <code className="copy-value">{value}</code>
        <Button small variant="ghost" onClick={copy} aria-label={t('directory.copyLabel', { what: label })}>
          {copied ? <IconCheck /> : null}
          {copied ? t('directory.copied') : t('directory.copy')}
        </Button>
      </div>
    </div>
  )
}

function MappingForm({
  mapping,
  onSaved,
  onCancel,
}: {
  mapping: RoleMapping | null
  onSaved: (result: RoleMappingSaved) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const [kind, setKind] = useState<MappingKind>(mapping?.kind ?? 'group')
  const [value, setValue] = useState(mapping?.value ?? '')
  const [role, setRole] = useState<Role>(mapping?.role ?? 'dev_team')
  const [ownerTeam, setOwnerTeam] = useState(mapping?.owner_team ?? '')
  const [approvalLevel, setApprovalLevel] = useState<ApprovalLevel>(mapping?.approval_level ?? 'none')
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const { data: groups } = useQuery({ queryKey: ['directory-groups'], queryFn: listDirectoryGroups })
  const namedGroups = (groups ?? []).filter((group) => group.display_name)

  const needsOwnerTeam = role === 'dev_team'
  const canHoldLevel = role === 'appsec' || role === 'management'

  const mutation = useMutation({
    mutationFn: () => {
      const payload = {
        kind,
        value: value.trim(),
        role,
        owner_team: needsOwnerTeam ? ownerTeam.trim() : null,
        approval_level: canHoldLevel ? approvalLevel : ('none' as ApprovalLevel),
      }
      return mapping ? updateRoleMapping(mapping.id, payload) : createRoleMapping(payload)
    },
    onSuccess: onSaved,
  })

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    const problem = !value.trim()
      ? t(kind === 'group' ? 'directory.groupRequired' : 'directory.appRoleRequired')
      : needsOwnerTeam && !ownerTeam.trim()
        ? t('users.ownerTeamRequiredError')
        : null
    setValidationError(problem)
    if (problem) {
      requestAnimationFrame(() => errorSummaryRef.current?.focus())
      return
    }
    mutation.mutate()
  }

  const message = validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('directory.saveFailed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorSummaryRef} title={t('directory.saveErrorSummary')} message={message} />}
      <div className="field">
        <span className="field-label" id="mapping-kind-label">
          {t('directory.kindLabel')}
        </span>
        <PillGroup
          value={kind}
          onChange={(next) => {
            setKind(next)
            setValue('')
          }}
          ariaLabel={t('directory.kindLabel')}
          options={[
            { value: 'group', label: t('directory.kind.group') },
            { value: 'app_role', label: t('directory.kind.app_role') },
          ]}
        />
      </div>
      <div className="form-grid">
        {kind === 'group' && namedGroups.length > 0 && (
          <FormField label={t('directory.pickGroup')} className="field-wide">
            <SelectBox
              value={value}
              onChange={setValue}
              placeholder={t('directory.pickGroupPlaceholder')}
              options={namedGroups.map((group) => ({
                value: group.external_id,
                label: t('directory.groupOption', { name: group.display_name, count: group.member_count }),
              }))}
            />
          </FormField>
        )}
        <FormField
          label={kind === 'group' ? t('directory.groupId') : t('directory.appRoleValue')}
          hint={kind === 'group' ? t('directory.groupIdHint') : t('directory.appRoleHint')}
          className="field-wide"
        >
          <TextInput
            className="mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={kind === 'group' ? '5b0f1c2e-…' : 'AppSec.Lead'}
            autoComplete="off"
          />
        </FormField>
        <FormField label={t('users.role')}>
          <SelectBox
            value={role}
            onChange={setRole}
            options={MAPPABLE_ROLES.map((r) => ({ value: r, label: t(`roles.${r}`) }))}
          />
        </FormField>
        {needsOwnerTeam && (
          <FormField label={t('inventory.ownerTeam')}>
            <TextInput value={ownerTeam} onChange={(e) => setOwnerTeam(e.target.value)} />
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
      <div className="modal-actions">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('common.save')}
        </Button>
      </div>
    </form>
  )
}
