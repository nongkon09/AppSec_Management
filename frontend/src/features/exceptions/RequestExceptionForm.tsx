/**
 * Maker side of the Maker-Checker flow (docs/workflows.md W3/W4).
 *
 * The form only offers what the type needs: a risk acceptance can propose a lower
 * residual severity backed by controls and must expire; a false positive / not affected
 * decision needs a VEX justification and a review date. The server re-validates every
 * rule and decides who must approve, so nothing here is a security control.
 */
import { useMutation, useQuery } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { SeverityBadge } from '../../components/SeverityBadge'
import {
  Button,
  CheckboxField,
  ErrorSummary,
  FormField,
  PillGroup,
  SelectBox,
  TextArea,
  TextInput,
} from '../../components/ui'
import { formatDate } from '../../lib/format'
import { apiErrorMessage } from '../../lib/ui-helpers'
import { listControls } from '../controls/api'
import { SEVERITY_LABEL } from '../findings/labels'
import type { Finding, SeverityTier } from '../findings/types'
import { submitException } from './api'
import { EXCEPTION_TYPES, VEX_JUSTIFICATIONS } from './types'
import type { ExceptionType, RiskException, VexJustification } from './types'

const TIERS: SeverityTier[] = ['critical', 'high', 'medium', 'low']
const MAX_DROP = 2

/** Residual tiers the server would accept, so the list never offers a guaranteed refusal. */
function residualOptions(original: SeverityTier, kev: boolean): SeverityTier[] {
  const start = TIERS.indexOf(original)
  return TIERS.filter((_tier, index) => {
    if (index <= start || index - start > MAX_DROP) return false
    return !(kev && index > TIERS.indexOf('high'))
  })
}

function inDays(days: number): string {
  const date = new Date()
  date.setDate(date.getDate() + days)
  return date.toISOString().slice(0, 10)
}

export function RequestExceptionForm({
  finding,
  onCancel,
  onDone,
}: {
  finding: Finding
  onCancel: () => void
  onDone: (created: RiskException) => void
}) {
  const { t } = useTranslation()
  const [type, setType] = useState<ExceptionType>('risk_acceptance')
  const [reason, setReason] = useState('')
  const [evidence, setEvidence] = useState('')
  const [measures, setMeasures] = useState('')
  const [residual, setResidual] = useState<SeverityTier | ''>('')
  const [controlIds, setControlIds] = useState<string[]>([])
  const [justification, setJustification] = useState<VexJustification | ''>('')
  const [expiresOn, setExpiresOn] = useState(inDays(14))
  const [validationError, setValidationError] = useState<string | null>(null)
  const errorRef = useRef<HTMLDivElement>(null)

  const { data: controls } = useQuery({ queryKey: ['controls'], queryFn: listControls })
  const usableControls = (controls ?? []).filter((control) => control.is_usable)
  const isRiskAcceptance = type === 'risk_acceptance'
  const original = finding.severity_tier

  const mutation = useMutation({
    mutationFn: () =>
      submitException({
        exception_type: type,
        finding_ids: [finding.id],
        reason: reason.trim(),
        evidence: evidence.trim() || null,
        compensating_measures: isRiskAcceptance ? measures.trim() || null : null,
        control_ids: isRiskAcceptance ? controlIds : [],
        residual_severity_tier: isRiskAcceptance && residual ? residual : null,
        vex_justification: !isRiskAcceptance && justification ? justification : null,
        expires_on: expiresOn,
      }),
    onSuccess: onDone,
  })

  function fail(message: string) {
    setValidationError(message)
    requestAnimationFrame(() => errorRef.current?.focus())
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    mutation.reset()
    if (reason.trim().length < 10) return fail(t('exceptions.form.reasonTooShort'))
    if (!expiresOn) return fail(t('exceptions.form.expiryRequired'))
    if (!isRiskAcceptance && !justification) return fail(t('exceptions.form.justificationRequired'))
    if (isRiskAcceptance && residual && controlIds.length === 0) {
      return fail(t('exceptions.form.controlRequired'))
    }
    setValidationError(null)
    mutation.mutate()
  }

  function toggleControl(id: string, on: boolean) {
    setControlIds((previous) => (on ? [...previous, id] : previous.filter((item) => item !== id)))
  }

  const message =
    validationError ?? (mutation.isError ? apiErrorMessage(mutation.error, t('exceptions.form.failed')) : null)

  return (
    <form onSubmit={handleSubmit} noValidate>
      {message && <ErrorSummary ref={errorRef} title={t('exceptions.form.errorSummary')} message={message} />}

      <div className="field">
        <span className="field-label" id="exception-type-label">
          {t('exceptions.form.type')}
        </span>
        <PillGroup
          ariaLabel={t('exceptions.form.type')}
          value={type}
          onChange={setType}
          options={EXCEPTION_TYPES.map((value) => ({ value, label: t(`exceptions.type.${value}`) }))}
        />
        <p className="field-hint">{t(`exceptions.typeHint.${type}`)}</p>
      </div>

      <div className="inline">
        <span className="field-hint">{t('exceptions.form.currentSeverity')}</span>
        <SeverityBadge tier={original} />
        {finding.kev_flag && <span className="chip chip-kev">KEV</span>}
        {finding.due_date && (
          <span className="field-hint">{t('exceptions.form.currentDue', { date: formatDate(finding.due_date) })}</span>
        )}
      </div>

      <FormField label={t('exceptions.form.reason')} hint={t('exceptions.form.reasonHint')}>
        <TextArea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
      </FormField>

      {isRiskAcceptance ? (
        <>
          <FormField label={t('exceptions.form.residual')} hint={t('exceptions.form.residualHint')}>
            <SelectBox
              value={residual}
              onChange={setResidual}
              options={[
                { value: '' as const, label: t('exceptions.form.keepOriginal', { tier: SEVERITY_LABEL[original] }) },
                ...residualOptions(original, finding.kev_flag).map((tier) => ({
                  value: tier,
                  label: SEVERITY_LABEL[tier],
                })),
              ]}
            />
          </FormField>

          <div className="field">
            <span className="field-label">{t('exceptions.form.controls')}</span>
            {usableControls.length === 0 ? (
              <p className="field-hint">{t('exceptions.form.noControls')}</p>
            ) : (
              <div className="stack">
                {usableControls.map((control) => (
                  <CheckboxField
                    key={control.id}
                    checked={controlIds.includes(control.id)}
                    onChange={(on) => toggleControl(control.id, on)}
                  >
                    {control.name}{' '}
                    <span className="muted">
                      · {t(`controls.effectiveness.${control.effectiveness}`)} · {control.owner}
                    </span>
                  </CheckboxField>
                ))}
              </div>
            )}
          </div>

          <FormField label={t('exceptions.form.measures')}>
            <TextArea rows={2} value={measures} onChange={(e) => setMeasures(e.target.value)} />
          </FormField>
        </>
      ) : (
        <FormField label={t('exceptions.form.justification')}>
          <SelectBox
            value={justification}
            onChange={setJustification}
            placeholder={t('exceptions.form.selectJustification')}
            options={VEX_JUSTIFICATIONS.map((value) => ({
              value,
              label: <span className="mono">{value}</span>,
            }))}
          />
        </FormField>
      )}

      <FormField label={t('exceptions.form.evidence')} hint={t('exceptions.form.evidenceHint')}>
        <TextArea rows={2} value={evidence} onChange={(e) => setEvidence(e.target.value)} />
      </FormField>

      <FormField
        label={isRiskAcceptance ? t('exceptions.form.expiresOn') : t('exceptions.form.reviewOn')}
        hint={isRiskAcceptance ? t('exceptions.form.expiresHint') : t('exceptions.form.reviewHint')}
      >
        <TextInput type="date" value={expiresOn} onChange={(e) => setExpiresOn(e.target.value)} />
      </FormField>

      <div className="modal-actions">
        <Button onClick={onCancel}>{t('common.cancel')}</Button>
        <Button type="submit" variant="primary" disabled={mutation.isPending}>
          {mutation.isPending ? t('common.saving') : t('exceptions.form.submit')}
        </Button>
      </div>
    </form>
  )
}
