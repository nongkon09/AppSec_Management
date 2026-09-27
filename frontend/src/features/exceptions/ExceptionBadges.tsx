import { useTranslation } from 'react-i18next'
import { IconAlertCircle, IconNoSla, IconOverdue, IconWithinSla } from '../../lib/icons'
import type { ExceptionStatus } from './types'

const STATUS_CLASS: Record<ExceptionStatus, string> = {
  pending: 'chip chip-neutral',
  approved: 'chip chip-sla-within',
  rejected: 'chip chip-sla-overdue',
  revoked: 'chip chip-sla-overdue',
  expired: 'chip chip-sla-overdue',
  withdrawn: 'chip chip-sla-none',
  closed: 'chip chip-sla-none',
}

function StatusIcon({ status }: { status: ExceptionStatus }) {
  if (status === 'approved') return <IconWithinSla />
  if (status === 'pending') return <IconAlertCircle />
  if (status === 'withdrawn' || status === 'closed') return <IconNoSla />
  return <IconOverdue />
}

export function ExceptionStatusBadge({ status }: { status: ExceptionStatus }) {
  const { t } = useTranslation()
  return (
    <span className={STATUS_CLASS[status]}>
      <StatusIcon status={status} />
      {t(`exceptions.status.${status}`)}
    </span>
  )
}
