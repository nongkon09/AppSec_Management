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
import { useAuth } from '../auth/context'
import { can } from '../../lib/rbac'
import type { SeverityTier } from '../findings/types'
import { evaluateSeverity, fetchEffectivePolicy, listPolicyVersions, publishPolicyVersion } from './api'
import type { PolicySet, SeverityEvaluationResult, SlaDays } from './types'

const TIERS: SeverityTier[] = ['critical', 'high', 'medium', 'low']

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
      <h1>{t('policy.title')}</h1>
      <p className="detail-meta">
        {t('policy.effectiveVersion', {
          version: effective.version,
          date: effective.effective_from,
          author: effective.created_by,
        })}
      </p>

      <section aria-labelledby="sla-heading">
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
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">{t('findings.severity')}</th>
                  <th scope="col">{t('policy.slaDays')}</th>
                </tr>
              </thead>
              <tbody>
                {TIERS.map((tier) => (
                  <tr key={tier}>
                    <th scope="row">
                      <SeverityBadge tier={tier} />
                    </th>
                    <td className="mono">
                      {effective.sla_days[tier] ?? t('sla.bestEffort')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
        <section aria-labelledby="history-heading">
          <h2 id="history-heading" className="section-title">
            {t('policy.historySection')}
          </h2>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col" className="numeric">
                    {t('policy.version')}
                  </th>
                  <th scope="col">{t('policy.effectiveFrom')}</th>
                  <th scope="col">{t('policy.createdBy')}</th>
                  {TIERS.map((tier) => (
                    <th key={tier} scope="col" className="numeric">
                      {tier}
                    </th>
                  ))}
                  <th scope="col">{t('policy.notes')}</th>
                </tr>
              </thead>
              <tbody>
                {versions.map((version) => (
                  <tr key={version.id}>
                    <td className="numeric mono">
                      {version.version}
                      {version.version === effective.version && (
                        <span className="chip chip-source">{t('policy.current')}</span>
                      )}
                    </td>
                    <td className="mono">{version.effective_from}</td>
                    <td>{version.created_by}</td>
                    {TIERS.map((tier) => (
                      <td key={tier} className="numeric mono">
                        {version.sla_days[tier] ?? '—'}
                      </td>
                    ))}
                    <td className="muted">{version.notes ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
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
    <form onSubmit={handlePublish} noValidate>
      {(formError || publishMutation.isError) && (
        <div className="error-summary" role="alert" tabIndex={-1} ref={errorSummaryRef}>
          <p>{t('policy.publishErrorSummary')}</p>
          <ul>
            <li>{formError ?? t('policy.publishFailed')}</li>
          </ul>
        </div>
      )}

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">{t('findings.severity')}</th>
              <th scope="col">{t('policy.slaDays')}</th>
              <th scope="col">{t('policy.defaultRouting')}</th>
            </tr>
          </thead>
          <tbody>
            {TIERS.map((tier) => (
              <tr key={tier}>
                <th scope="row">
                  <SeverityBadge tier={tier} />
                </th>
                <td>
                  <label className="visually-hidden" htmlFor={`sla-${tier}`}>
                    {t('policy.slaDaysFor', { tier })}
                  </label>
                  <input
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
                </td>
                {/* FR-7.2 routing is configured with the ITSM connectors; shown here as the
                    Section 12 default so the two read together. */}
                <td className="muted">{t(`policy.routing.${tier}`)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <fieldset className="filter-group">
        <legend>{t('policy.dependencyScopeSection')}</legend>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={downgradeDevScope}
            onChange={(event) => setDowngradeDevScope(event.target.checked)}
          />
          {t('policy.downgradeDevScope')}
        </label>
      </fieldset>

      <div className="field-row">
        <label htmlFor="effective-from">{t('policy.effectiveFrom')}</label>
        <input
          id="effective-from"
          type="date"
          value={effectiveFrom}
          onChange={(event) => setEffectiveFrom(event.target.value)}
          required
        />
      </div>

      <div className="field-row">
        <label htmlFor="policy-notes">{t('policy.notes')}</label>
        <input
          id="policy-notes"
          type="text"
          value={notes}
          placeholder={t('policy.notesPlaceholder')}
          onChange={(event) => setNotes(event.target.value)}
        />
      </div>

      <div className="form-actions">
        <button type="submit" disabled={publishMutation.isPending}>
          {publishMutation.isPending ? t('common.saving') : t('policy.publish')}
        </button>
        {published !== null && (
          <span className="form-success" role="status">
            {t('policy.published', { version: published })}
          </span>
        )}
      </div>
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
    <section aria-labelledby="tester-heading">
      <h2 id="tester-heading" className="section-title">
        {t('policy.testerSection')}
      </h2>
      <p className="field-hint">{t('policy.testerHint')}</p>
      <form className="filter-bar" onSubmit={handleEvaluate}>
        <div className="filter-group">
          <label htmlFor="test-cvss">CVSS</label>
          <input
            id="test-cvss"
            type="number"
            className="input-numeric mono"
            step="0.1"
            min={0}
            max={10}
            value={cvss}
            onChange={(event) => setCvss(event.target.value)}
          />
        </div>
        <div className="filter-group">
          <label htmlFor="test-epss">EPSS</label>
          <input
            id="test-epss"
            type="number"
            className="input-numeric mono"
            step="0.01"
            min={0}
            max={1}
            value={epss}
            onChange={(event) => setEpss(event.target.value)}
          />
        </div>
        <div className="filter-group">
          <label className="checkbox-row" htmlFor="test-kev">
            <input
              id="test-kev"
              type="checkbox"
              checked={kev}
              onChange={(event) => setKev(event.target.checked)}
            />
            CISA KEV
          </label>
        </div>
        <div className="filter-group">
          <label htmlFor="test-scope">{t('findings.dependencyScope')}</label>
          <select id="test-scope" value={scope} onChange={(event) => setScope(event.target.value)}>
            <option value="production">production</option>
            <option value="development">development</option>
          </select>
        </div>
        <button type="submit" disabled={mutation.isPending}>
          {t('policy.evaluate')}
        </button>
      </form>

      {result && (
        <div className="tester-result" role="status">
          <SeverityBadge tier={result.severity_tier} />
          <span>
            {t('policy.testerResult', {
              rule: result.matched_rule,
              days: result.sla_days ?? t('sla.bestEffort'),
              due: result.due_date ?? '—',
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
