/**
 * Route guard for capabilities (Requirement.md Section 4, UXR-6).
 *
 * Navigation already hides screens a role cannot use, but a bookmarked or hand-typed URL
 * still has to land somewhere sensible. This shows a plain explanation rather than an empty
 * screen or a stack of failed API calls.
 *
 * It is a usability guard only — the backend enforces the same rules on every request.
 */
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { can } from '../../lib/rbac'
import type { Capability } from '../../lib/rbac'
import { useAuth } from './context'

export function RequireCapability({
  capability,
  children,
}: {
  capability: Capability
  children: ReactNode
}) {
  const { t } = useTranslation()
  const { user } = useAuth()

  if (!can(user?.role, capability)) {
    return (
      <div className="page">
        <h1>{t('common.notAuthorisedTitle')}</h1>
        <p>{t('common.notAuthorisedBody', { role: t(`roles.${user?.role ?? 'unknown'}`) })}</p>
        <Link to="/">{t('common.backToDashboard')}</Link>
      </div>
    )
  }

  return <>{children}</>
}
