/**
 * Application shell (Requirement.md UXR-1, UXR-6, UXR-12).
 *
 * Left-sidebar navigation (Clean & Minimal redesign, approved via the AppSec Platform
 * Redesign canvas) — a slim top bar carries branding, language/theme, scope and account,
 * and a persistent left rail carries primary navigation, which scales better than a top
 * nav once there are 7 destinations and reads as current-generation rather than dated.
 *
 * Navigation is built from the user's capabilities, so a screen they have no rights to is
 * never rendered at all rather than shown and then refused on click (UXR-6). Roles whose
 * data is narrowed to one team also get an explicit scope badge, so a Dev Team lead is
 * never left wondering whether they are seeing the whole organisation.
 */
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../features/auth/context'
import {
  IconAudit,
  IconBacklog,
  IconDashboard,
  IconInventory,
  IconLanguage,
  IconLock,
  IconLogout,
  IconMoon,
  IconPackage,
  IconPolicy,
  IconSettings,
  IconSun,
  IconTarget,
  IconTeam,
} from '../lib/icons'
import { can, isScopedToOwnTeam } from '../lib/rbac'
import type { Capability } from '../lib/rbac'
import { useTheme } from '../lib/theme'

interface NavItem {
  to: string
  labelKey: string
  capability: Capability
  Icon: typeof IconDashboard
}

const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', capability: 'viewDashboard', Icon: IconDashboard },
  { to: '/findings', labelKey: 'nav.findings', capability: 'viewFindings', Icon: IconBacklog },
  { to: '/applications', labelKey: 'nav.inventory', capability: 'viewInventory', Icon: IconInventory },
  { to: '/sbom', labelKey: 'nav.sbom', capability: 'manageSbomIngestion', Icon: IconPackage },
  { to: '/policy', labelKey: 'nav.policy', capability: 'viewPolicy', Icon: IconPolicy },
  {
    to: '/pentest/board',
    labelKey: 'nav.pentest',
    capability: 'viewPentestProjects',
    Icon: IconTarget,
  },
  { to: '/audit', labelKey: 'nav.audit', capability: 'viewAuditTrail', Icon: IconAudit },
  { to: '/settings/users', labelKey: 'nav.settings', capability: 'manageUsers', Icon: IconSettings },
]

function initials(fullName: string): string {
  const parts = fullName.trim().split(/\s+/)
  return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? '')).toUpperCase() || '?'
}

export function AppLayout({ children }: { children: ReactNode }) {
  const { t, i18n } = useTranslation()
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const { resolved, toggle } = useTheme()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  const isThai = i18n.language.startsWith('th')

  function toggleLanguage() {
    // UXR-12: the preference is the user's own, persisted by the language detector.
    i18n.changeLanguage(isThai ? 'en' : 'th')
  }

  const visibleItems = NAV_ITEMS.filter((item) => can(user?.role, item.capability))

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        {t('common.skipToContent')}
      </a>

      <header className="topbar">
        <span className="brand">
          <span className="brand-mark">
            <IconLock />
          </span>
          {t('appName')}
        </span>

        <div className="topbar-right">
          {isScopedToOwnTeam(user?.role) && user?.owner_team && (
            // UXR-6: make the active data scope unmistakable for narrowed roles.
            <span className="chip chip-scope" title={t('common.scopeTooltip')}>
              <IconTeam />
              {t('common.yourTeam', { team: user.owner_team })}
            </span>
          )}

          <button
            type="button"
            className="button-icon"
            onClick={toggleLanguage}
            aria-label={t(isThai ? 'common.switchToEnglish' : 'common.switchToThai')}
          >
            <IconLanguage />
            {isThai ? 'EN' : 'TH'}
          </button>

          <button
            type="button"
            className="button-icon"
            onClick={toggle}
            aria-label={t(resolved === 'dark' ? 'common.switchToLight' : 'common.switchToDark')}
          >
            {resolved === 'dark' ? <IconSun /> : <IconMoon />}
          </button>

          {user && (
            <>
              <span className="user-chip">
                <span className="avatar">{initials(user.full_name)}</span>
                <span className="user-meta">
                  <span className="user-name">{user.full_name}</span>
                  <span className="user-role">{t(`roles.${user.role}`)}</span>
                </span>
              </span>
              <button type="button" className="button-icon" onClick={handleLogout}>
                <IconLogout />
                {t('nav.logout')}
              </button>
            </>
          )}
        </div>
      </header>

      <div className="body-row">
        <nav className="sidebar" aria-label={t('common.mainNavigation')}>
          {visibleItems.map(({ to, labelKey, Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              title={t(labelKey)}
              className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}
            >
              <Icon />
              <span>{t(labelKey)}</span>
            </NavLink>
          ))}
        </nav>

        <main className="app-content" id="main-content">
          {children}
        </main>
      </div>
    </div>
  )
}
