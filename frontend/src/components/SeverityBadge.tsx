/**
 * Severity and SLA chips (Requirement.md UXR-2).
 *
 * Each chip carries a shape-distinct icon AND a text label, so the tier is legible to a
 * colourblind user, in a monochrome print-out, and to a screen reader — colour only
 * reinforces what the label already says (WCAG 1.4.1 Use of Color).
 *
 * Severity tier names stay in English in both UI languages, because they are the
 * standardised vocabulary shared with CVSS/VEX tooling (UXR-12).
 */
import { useTranslation } from 'react-i18next'
import {
  IconNoSla,
  IconOverdue,
  IconSeverityCritical,
  IconSeverityHigh,
  IconSeverityLow,
  IconSeverityMedium,
  IconWithinSla,
} from '../lib/icons'
import type { SeverityTier } from '../features/findings/types'

const SEVERITY_ICON = {
  critical: IconSeverityCritical,
  high: IconSeverityHigh,
  medium: IconSeverityMedium,
  low: IconSeverityLow,
} as const

const SEVERITY_LABEL: Record<SeverityTier, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export function SeverityBadge({ tier }: { tier: SeverityTier }) {
  const IconComponent = SEVERITY_ICON[tier]
  return (
    <span className={`chip chip-severity chip-severity-${tier}`}>
      <IconComponent />
      {SEVERITY_LABEL[tier]}
    </span>
  )
}

export function SlaBadge({
  isOverdue,
  dueDate,
  daysUntilDue,
}: {
  isOverdue: boolean
  dueDate: string | null
  daysUntilDue: number | null
}) {
  const { t } = useTranslation()

  if (!dueDate) {
    // Section 12: Low is best-effort, so it carries no due date at all.
    return (
      <span className="chip chip-sla-none">
        <IconNoSla />
        {t('sla.bestEffort')}
      </span>
    )
  }
  if (isOverdue) {
    const daysLate = daysUntilDue === null ? 0 : Math.abs(daysUntilDue)
    return (
      <span className="chip chip-sla-overdue">
        <IconOverdue />
        {t('sla.overdueByDays', { count: daysLate })}
      </span>
    )
  }
  // A Finding can be past its due date without being "overdue" (e.g. an approved
  // Waiver or a VEX suppression resolved it) — "Due in -12 days" would be a confusing
  // read once it's no longer actually breaching, so just say it's within SLA.
  const isPastDue = daysUntilDue !== null && daysUntilDue < 0
  return (
    <span className="chip chip-sla-within">
      <IconWithinSla />
      {isPastDue ? t('sla.withinSla') : t('sla.dueInDays', { count: daysUntilDue ?? 0 })}
    </span>
  )
}

/** Legend required on every screen that shows severity (UXR-2). */
export function SeverityLegend() {
  const { t } = useTranslation()
  const tiers: SeverityTier[] = ['critical', 'high', 'medium', 'low']
  return (
    <div className="legend">
      <span className="legend-label">{t('legend.severity')}</span>
      {tiers.map((tier) => (
        <SeverityBadge key={tier} tier={tier} />
      ))}
      <span className="legend-label">{t('legend.sla')}</span>
      <span className="chip chip-sla-overdue">
        <IconOverdue />
        {t('sla.overdue')}
      </span>
      <span className="chip chip-sla-within">
        <IconWithinSla />
        {t('sla.withinSla')}
      </span>
    </div>
  )
}
