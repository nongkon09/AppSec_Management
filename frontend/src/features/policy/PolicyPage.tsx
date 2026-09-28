/**
 * Severity & SLA Policy Configuration (Requirement.md FR-4.4, FR-5.1, Section 12).
 *
 * The point of this screen is that SLA windows and tiering thresholds are parameters, not
 * code: AppSec edits the numbers here and publishes a new effective-dated version. Earlier
 * versions stay visible and unedited, because a Finding's severity and due date must remain
 * explainable against the policy that was in force when it was raised (NFR Auditability).
 *
 * The "test a Finding" panel dry-runs the live rule engine (FR-4.1), so the effect of a
 * threshold can be checked before anything is published.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { SeverityBadge } from '../../components/SeverityBadge'
import { Button, CheckboxField, ErrorSummary, FormField, SelectBox, TextInput } from '../../components/ui'
import { useAuth } from '../auth/context'
import { formatDate } from '../../lib/format'
import { can } from '../../lib/rbac'
import { SEVERITY_LABEL } from '../findings/labels'
import type { SeverityTier } from '../findings/types'
import { evaluateSeverity, fetchEffectivePolicy, listPolicyVersions, publishPolicyVersion } from './api'
import type { PolicySet, SeverityEvaluationResult, SlaDays } from './types'

const TIERS: SeverityTier[] = ['critical', 'high', 'medium', 'low']
/** The seeded default policy is effective from the epoch: "since the start", not 1970. */
const EPOCH = '1970-01-01'
const SYSTEM_ACTOR = 'system'

type Translate = (key: string, options?: Record<string, unknown>) => string

function effectiveLabel(date: string, t: Translate): string {
  return date === EPOCH ? t('policy.sinceStart') : formatDate(date)
}

function authorLabel(author: string, t: Translate): string {
  return author === SYSTEM_ACTOR ? t('policy.systemAuthor') : author
}

function slaText(days: number | null, t: Translate): string {
  return days === null ? t('policy.noDeadline') : t('policy.daysValue', { count: days })
}

/** Renders a rule's condition as the comparison AppSec actually reasons about. */
function describeCondition(when: Record<string, unknown>): string {
  const parts: string[] = []
  if (when.kev === true) parts.push('CISA KEV = true')
  if (when.kev === false) parts.push('CISA KEV = false')
  if (when.cvss_min !== undefined && when.cvss_min !== null) parts.push(`CVSS >= ${when.cvss_min}`)
  if (when.cvss_max !== undefined && when.cvss_max !== null) parts.push(`CVSS <= ${when.cvss_max}`)
  if (when.epss_min !== undefined && when.epss_min !== null) parts.push(`EPSS >= ${when.epss_min}`)
  if (when.epss_max !== undefined && when.epss_max !== null) parts.push(`EPSS <= ${when.epss_max}`)
  return parts.length > 0 ? parts.join(' AND ') : 'any'
}

export function PolicyPage() {
  const { t } = useTranslation()
  const { user } = useAuth()
  const canManage = can(user?.role, 'managePolicy')

  const { data: effective, isLoading } = useQuery({
    queryKey: ['policy-effective'],
    queryFn: fetchEffectivePolicy,
  })
  const { data: versions } = useQuery({
    queryKey: ['policy-versions'],
    queryFn: listPolicyVersions,
    enabled: canManage,
  })

  if (isLoading || !effective) {
    return (
      <div className="page">
        <p role="status">{t('common.loading')}</p>
      </div>
    )
  }

  return (
    <div className="page">
      <div>
        <h1>{t('policy.title')}</h1>
        <p className="page-sub">
          {t('policy.effectiveVersion', {
            version: effective.version,
            date: effectiveLabel(effective.effective_from, t),
            author: authorLabel(effective.created_by, t),
          })}
        </p>
      </div>

      <section aria-labelledby="sla-heading" className="card card-pad">
        <h2 id="sla-heading" className="section-title">
          {t('policy.slaSection')}
        </h2>
        <p className="field-hint">{t('policy.slaHint')}</p>

        {canManage ? (
          // Seeded once from the policy in force. Deliberately not keyed on the version:
          // publishing makes the values the user just entered the new effective ones, and
          // remounting on publish would wipe the "published as version N" confirmation.
          <SlaPolicyForm policy={effective} />
        ) : (
          <div className="sla-editor">
            {TIERS.map((tier) => (
              <div key={tier} className="sla-row">
                <SlaTier tier={tier} />
                <span className="sla-row-value">{slaText(effective.sla_days[tier], t)}</span>
                <span className="sla-row-route">{t(`policy.routing.${tier}`)}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section aria-labelledby="rules-heading">
        <h2 id="rules-heading" className="section-title">
          {t('policy.rulesSection')}
        </h2>
        <p className="field-hint">{t('policy.rulesHint')}</p>
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col" className="numeric">
                  #
                </th>
                <th scope="col">{t('policy.ruleName')}</th>
                <th scope="col">{t('policy.ruleCondition')}</th>
                <th scope="col">{t('policy.ruleTier')}</th>
              </tr>
            </thead>
            <tbody>
              {effective.severity_rules.map((rule, index) => (
                <tr key={rule.name}>
                  <td className="numeric mono">{index + 1}</td>
                  <td className="mono">{rule.name}</td>
                  <td className="mono">{describeCondition(rule.when as Record<string, unknown>)}</td>
                  <td>
                    <SeverityBadge tier={rule.tier} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {canManage && <RuleTester />}

      {canManage && versions && versions.length > 1 && (
        <PolicyHistory versions={versions} currentVersion={effective.version} />
      )}
    </div>
  )
}

/**
 * SLA window editor (FR-5.1, UXR-7).
 *
 * Holds the draft values for the next policy version. The parent remounts it whenever a
 * new version becomes effective, so the form always starts from what is actually in force.
 */
function SlaPolicyForm({ policy }: { policy: PolicySet }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [slaDays, setSlaDays] = useState<SlaDays>(policy.sla_days)
  const [downgradeDevScope, setDowngradeDevScope] = useState(policy.downgrade_dev_scope_findings)
  const [effectiveFrom, setEffectiveFrom] = useState(() => new Date().toISOString().slice(0, 10))
  const [notes, setNotes] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [published, setPublished] = useState<number | null>(null)
  const errorSummaryRef = useRef<HTMLDivElement>(null)

  const publishMutation = useMutation({
    mutationFn: publishPolicyVersion,
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ['policy-effective'] })
      queryClient.invalidateQueries({ queryKey: ['policy-versions'] })
      setPublished(created.version)
      setNotes('')
    },
  })

  function handlePublish(event: FormEvent) {
    event.preventDefault()
    setPublished(null)
    // A more severe tier must never get a longer window than a less severe one — an
    // inverted ladder would quietly give the worst vulnerabilities the most time.
    const ladder = [slaDays.critical, slaDays.high, slaDays.medium, slaDays.low]
    for (let index = 0; index < ladder.length - 1; index += 1) {
      const current = ladder[index]
      const next = ladder[index + 1]
      if (current !== null && next !== null && current > next) {
        setFormError(t('policy.slaLadderError'))
        requestAnimationFrame(() => errorSummaryRef.current?.focus())
        return
      }
    }
    setFormError(null)
    publishMutation.mutate({
      effective_from: effectiveFrom,
      // Carried over unchanged: this screen edits SLA windows and the dependency-scope
      // switch. Editing the rule list itself is a separate builder.
      severity_rules: policy.severity_rules,
      sla_days: slaDays,
      downgrade_dev_scope_findings: downgradeDevScope,
      auto_ticket_dev_scope_findings: policy.auto_ticket_dev_scope_findings,
      notes: notes || null,
    })
  }

  return (
    <form className="stack sla-form" onSubmit={handlePublish} noValidate>
      {(formError || publishMutation.isError) && (
        <ErrorSummary
          ref={errorSummaryRef}
          title={t('policy.publishErrorSummary')}
          message={formError ?? t('policy.publishFailed')}
        />
      )}

      <div className="sla-editor">
        {TIERS.map((tier) => (
          <div key={tier} className="sla-row">
            <label htmlFor={`sla-${tier}`} className="sla-row-label">
              <SlaTier tier={tier} />
              <span className="visually-hidden">{t('policy.slaDaysFor', { tier })}</span>
            </label>
            <span className="input-suffix">
              <TextInput
                id={`sla-${tier}`}
                type="number"
                className="input-numeric mono"
                min={0}
                max={3650}
                value={slaDays[tier] ?? ''}
                placeholder={t('policy.bestEffortPlaceholder')}
                onChange={(event) =>
                  setSlaDays({
                    ...slaDays,
                    [tier]: event.target.value === '' ? null : Number(event.target.value),
                  })
                }
              />
              <span className="input-suffix-text">{t('policy.slaDays')}</span>
            </span>
            {/* FR-7.2 routing is configured with the ITSM connectors; shown here as the
                Section 12 default so the two read together. */}
            <span className="sla-row-route">{t(`policy.routing.${tier}`)}</span>
          </div>
        ))}
      </div>

      <CheckboxField checked={downgradeDevScope} onChange={setDowngradeDevScope}>
        {t('policy.downgradeDevScope')}
      </CheckboxField>

      <div className="publish-row">
        <FormField label={t('policy.effectiveFrom')}>
          <TextInput type="date" value={effectiveFrom} onChange={(event) => setEffectiveFrom(event.target.value)} required />
        </FormField>
        <FormField label={t('policy.notes')} className="publish-row-grow">
          <TextInput
            value={notes}
            placeholder={t('policy.notesPlaceholder')}
            onChange={(event) => setNotes(event.target.value)}
          />
        </FormField>
        <Button type="submit" variant="primary" disabled={publishMutation.isPending}>
          {publishMutation.isPending ? t('common.saving') : t('policy.publish')}
        </Button>
      </div>
      {published !== null && (
        <p className="form-success" role="status">
          {t('policy.published', { version: published })}
        </p>
      )}
      <p className="field-hint">{t('policy.immutabilityNote')}</p>
    </form>
  )
}

/** Dry-runs the effective rule set against hypothetical scores (FR-4.1). */
function RuleTester() {
  const { t } = useTranslation()
  const [cvss, setCvss] = useState('7.5')
  const [epss, setEpss] = useState('0.1')
  const [kev, setKev] = useState(false)
  const [scope, setScope] = useState('production')
  const [result, setResult] = useState<SeverityEvaluationResult | null>(null)

  const mutation = useMutation({
    mutationFn: evaluateSeverity,
    onSuccess: setResult,
  })

  function handleEvaluate(event: FormEvent) {
    event.preventDefault()
    mutation.mutate({
      cvss: cvss === '' ? null : Number(cvss),
      epss: epss === '' ? null : Number(epss),
      kev_flag: kev,
      scope,
    })
  }

  return (
    <section aria-labelledby="tester-heading" className="card card-pad">
      <h2 id="tester-heading" className="section-title">
        {t('policy.testerSection')}
      </h2>
      <p className="field-hint">{t('policy.testerHint')}</p>
      <form className="toolbar tester-form" onSubmit={handleEvaluate}>
        <FormField label="CVSS">
          <TextInput
            type="number"
            className="input-numeric mono"
            step="0.1"
            min={0}
            max={10}
            value={cvss}
            onChange={(event) => setCvss(event.target.value)}
          />
        </FormField>
        <FormField label="EPSS">
          <TextInput
            type="number"
            className="input-numeric mono"
            step="0.01"
            min={0}
            max={1}
            value={epss}
            onChange={(event) => setEpss(event.target.value)}
          />
        </FormField>
        <FormField label={t('findings.dependencyScope')}>
          <SelectBox
            value={scope}
            onChange={setScope}
            options={[
              { value: 'production', label: 'production' },
              { value: 'development', label: 'development' },
            ]}
          />
        </FormField>
        <CheckboxField checked={kev} onChange={setKev}>
          CISA KEV
        </CheckboxField>
        <Button type="submit" disabled={mutation.isPending}>
          {t('policy.evaluate')}
        </Button>
      </form>

      {result && (
        <div className="tester-result" role="status">
          <SeverityBadge tier={result.severity_tier} />
          <span>
            {t('policy.testerResult', {
              rule: result.matched_rule,
              days: result.sla_days ?? t('sla.bestEffort'),
              due: result.due_date ? formatDate(result.due_date) : '—',
            })}
          </span>
          {result.downgraded_for_dev_scope && (
            <span className="chip chip-source">{t('policy.downgradedForDevScope')}</span>
          )}
        </div>
      )}
    </section>
  )
}

/** Severity dot and name, the same marker the history timeline uses. */
function SlaTier({ tier }: { tier: SeverityTier }) {
  return (
    <span className="sla-row-tier">
      <span className={`sla-dot sla-dot-${tier}`} aria-hidden="true" />
      {SEVERITY_LABEL[tier]}
    </span>
  )
}

/**
 * Version history as a timeline, newest first. Each entry shows what the version set and,
 * against the one before it, what actually changed, so a reviewer does not have to diff
 * a table of numbers by eye.
 */
function PolicyHistory({ versions, currentVersion }: { versions: PolicySet[]; currentVersion: number }) {
  const { t } = useTranslation()
  const ordered = [...versions].sort((a, b) => b.version - a.version)

  return (
    <section aria-labelledby="history-heading">
      <h2 id="history-heading" className="section-title">
        {t('policy.historySection')}
      </h2>
      <p className="field-hint">{t('policy.historyHint')}</p>
      <ol className="timeline card">
        {ordered.map((version, index) => {
          const previous = ordered[index + 1]
          const isCurrent = version.version === currentVersion
          const rulesChanged =
            previous !== undefined &&
            JSON.stringify(previous.severity_rules) !== JSON.stringify(version.severity_rules)
          const downgradeChanged =
            previous !== undefined &&
            previous.downgrade_dev_scope_findings !== version.downgrade_dev_scope_findings
          return (
            <li key={version.id} className={isCurrent ? 'timeline-item current' : 'timeline-item'}>
              <span className="timeline-marker" aria-hidden="true" />
              <div className="timeline-body">
                <div className="timeline-head">
                  <span className="timeline-version">v{version.version}</span>
                  {isCurrent && <span className="chip chip-sla-within">{t('policy.current')}</span>}
                  <span className="timeline-meta">
                    {t('policy.historyMeta', {
                      date: effectiveLabel(version.effective_from, t),
                      author: authorLabel(version.created_by, t),
                    })}
                  </span>
                </div>
                {version.notes && <p className="timeline-note">{version.notes}</p>}
                <ul className="sla-strip" aria-label={t('policy.slaSection')}>
                  {TIERS.map((tier) => {
                    const days = version.sla_days[tier]
                    const before = previous?.sla_days[tier]
                    const changed = previous !== undefined && before !== days
                    return (
                      <li key={tier} className={changed ? 'sla-cell changed' : 'sla-cell'}>
                        <span className={`sla-dot sla-dot-${tier}`} aria-hidden="true" />
                        <span className="sla-tier">{SEVERITY_LABEL[tier]}</span>
                        <span className="sla-days">{slaText(days, t)}</span>
                        {changed && (
                          <span className="sla-before">
                            {t('policy.changedFrom', { value: slaText(before ?? null, t) })}
                          </span>
                        )}
                      </li>
                    )
                  })}
                </ul>
                {(rulesChanged || downgradeChanged) && (
                  <p className="timeline-changes">
                    {[
                      rulesChanged ? t('policy.rulesChanged') : null,
                      downgradeChanged
                        ? version.downgrade_dev_scope_findings
                          ? t('policy.downgradeOn')
                          : t('policy.downgradeOff')
                        : null,
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                  </p>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
