/**
 * Control Library (docs/risk-exception-design.md 3.6): the organisational controls an
 * exception may cite to justify a lower residual severity.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Button,
  ErrorSummary,
  FormField,
  Modal,
  SelectBox,
  SwitchField,
  TextArea,
  TextInput,
} from '../../components/ui'
import { formatDate } from '../../lib/format'
import { IconPlus } from '../../lib/icons'
import { can } from '../../lib/rbac'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { useAuth } from '../auth/context'
import { createControl, listControls, updateControl } from './api'
import type { ControlCategory, ControlEffectiveness, SecurityControl } from './types'

const CATEGORIES: ControlCategory[] = ['network', 'application', 'monitoring', 'process']
const EFFECTIVENESS: ControlEffectiveness[] = ['high', 'medium', 'low']

export function ControlsPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const canManage = can(user?.role, 'manageControls')
  const [editing, setEditing] = useState<SecurityControl | 'new' | null>(null)
  const { data, isLoading, isError } = useQuery({ queryKey: ['controls'], queryFn: listControls })

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>
            {t('controls.title')}
            {data && <span className="count">{data.length}</span>}
          </h1>
          <p className="page-sub">{t('controls.subtitle')}</p>
        </div>
        {canManage && (
          <Button variant="primary" onClick={() => setEditing('new')}>
            <IconPlus />
            {t('controls.add')}
          </Button>
        )}
      </div>

      {isLoading && <p role="status">{t('common.loading')}</p>}
      {isError && (
        <p className="form-error" role="alert">
          {t('controls.loadError')}
        </p>
      )}
      {data && data.length === 0 && <p className="empty-state">{t('controls.empty')}</p>}

      {data && data.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="sticky-column">
                  {t('controls.name')}
                </th>
                <th scope="col">{t('controls.category')}</th>
                <th scope="col">{t('controls.effectivenessLabel')}</th>
                <th scope="col">{t('controls.owner')}</th>
                <th scope="col">{t('controls.reviewDue')}</th>
                {canManage && (
                  <th scope="col">
                    <span className="visually-hidden">{t('common.actions')}</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {data.map((control) => (
                <tr key={control.id}>
                  <th scope="row" className="sticky-column">
                    {control.name}
                    {control.description && <span className="cell-sub">{control.description}</span>}
                    {control.evidence_url && (
                      <a className="cell-sub" href={control.evidence_url} target="_blank" rel="noreferrer noopener">
                        {t('controls.evidence')}
                      </a>
                    )}
                  </th>
                  <td>{t(`controls.categoryValue.${control.category}`)}</td>
                  <td>{t(`controls.effectiveness.${control.effectiveness}`)}</td>
                  <td>{control.owner}</td>
                  <td>
                    <span className="nowrap">{formatDate(control.review_due_on)}</span>
                    {!control.is_usable && (
                      <span className="chip chip-sla-overdue gap-left">
                        {control.is_active ? t('controls.reviewOverdue') : t('controls.inactive')}
                      </span>
                    )}
                  </td>
                  {canManage && (
                    <td className="numeric">
                      <Button small variant="ghost" onClick={() => setEditing(control)}>
                        {t('controls.edit')}
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing === 'new' ? t('controls.add') : t('controls.edit')}
      >
        {editing !== null && (
          <ControlForm
            control={editing === 'new' ? null : editing}
            onDone={() => setEditing(null)}
          />
        )}
      </Modal>
    </div>
  )
}

function inDays(days: number): string {
  const date = new Date()
  date.setDate(date.getDate() + days)
  return date.toISOString().slice(0, 10)
}

function ControlForm({ control, onDone }: { control: SecurityControl | null; onDone: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [name, setName] = useState(control?.name ?? '')
  const [description, setDescription] = useState(control?.description ?? '')
  const [category, setCategory] = useState<ControlCategory>(control?.category ?? 'network')
  const [owner, setOwner] = useState(control?.owner ?? '')
  const [evidenceUrl, setEvidenceUrl] = useState(control?.evidence_url ?? '')
  const [effectiveness, setEffectiveness] = useState<ControlEffectiveness>(
    control?.effectiveness ?? 'medium',
  )
  const [reviewDue, setReviewDue] = useState(control?.review_due_on ?? inDays(180))
  const [isActive, setIsActive] = useState(control?.is_active ?? true)
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorRef = useRef<HTMLDivElement>(null)

  const mutation = useMutation({
    mutationFn: () =>
      control
        ? updateControl(control.id, {
            description: description.trim() || null,
            owner: owner.trim(),
            evidence_url: evidenceUrl.trim() || null,
            effectiveness,
            review_due_on: reviewDue,
            is_active: isActive,
          })
        : createControl({
            name: name.trim(),
            description: description.trim() || null,
            category,
            owner: owner.trim(),
            evidence_url: evidenceUrl.trim() || null,
            effectiveness,
            review_due_on: reviewDue,
          }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controls'] })
      onDone()
    },
  })

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if ((!control && name.trim().length < 3) || !owner.trim() || !reviewDue) {
      setValidationError(t('controls.validation'))
      requestAnimationFrame(() => errorRef.current?.focus())
      return
    }
    setValidationError(null)
    mutation.mutate()
  }

  const message =
    validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('controls.saveFailed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorRef} title={t('controls.saveErrorSummary')} message={message} />}
      <div className="form-grid">
        {control ? (
          <div className="field field-wide">
            <span className="field-label">{t('controls.name')}</span>
            <span>
              {control.name} · {t(`controls.categoryValue.${control.category}`)}
            </span>
          </div>
        ) : (
          <>
            <FormField label={t('controls.name')} className="field-wide">
              <TextInput value={name} onChange={(e) => setName(e.target.value)} />
            </FormField>
            <FormField label={t('controls.category')}>
              <SelectBox
                value={category}
                onChange={setCategory}
                options={CATEGORIES.map((value) => ({ value, label: t(`controls.categoryValue.${value}`) }))}
              />
            </FormField>
          </>
        )}
        <FormField label={t('controls.effectivenessLabel')}>
          <SelectBox
            value={effectiveness}
            onChange={setEffectiveness}
            options={EFFECTIVENESS.map((value) => ({ value, label: t(`controls.effectiveness.${value}`) }))}
          />
        </FormField>
        <FormField label={t('controls.owner')}>
          <TextInput value={owner} onChange={(e) => setOwner(e.target.value)} />
        </FormField>
        <FormField label={t('controls.reviewDue')} hint={t('controls.reviewDueHint')}>
          <TextInput type="date" value={reviewDue} onChange={(e) => setReviewDue(e.target.value)} />
        </FormField>
        <FormField label={t('controls.evidenceUrl')} className="field-wide">
          <TextInput value={evidenceUrl} onChange={(e) => setEvidenceUrl(e.target.value)} />
        </FormField>
        <FormField label={t('controls.description')} className="field-wide">
          <TextArea rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
        </FormField>
      </div>
      {control && (
        <SwitchField checked={isActive} onChange={setIsActive}>
          {t('controls.activeSwitch')}
        </SwitchField>
      )}
      <div className="modal-actions">
        <Button onClick={onDone}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('common.save')}
        </Button>
      </div>
    </form>
  )
}
