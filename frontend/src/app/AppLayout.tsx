/**
 * Application shell (Requirement.md UXR-1, UXR-6, UXR-12).
 *
 * A slim top bar carries branding, the data-scope badge and the account menu (language,
 * theme, sign-out); a persistent left rail carries primary navigation, with the daily
 * screens above the divider and admin/tooling screens below it.
 *
 * Navigation is built from the user's capabilities, so a screen they have no rights to is
 * never rendered at all rather than shown and then refused on click (UXR-6). Roles whose
 * data is narrowed to one team also get an explicit scope badge.
 */
import { Menu, MenuButton, MenuHeading, MenuItem, MenuItems, MenuSection, MenuSeparator } from '@headlessui/react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../features/auth/context'
import {
  IconAudit,
  IconBacklog,
  IconChevronDown,
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

const PRIMARY_NAV: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', capability: 'viewDashboard', Icon: IconDashboard },
  { to: '/findings', labelKey: 'nav.findings', capability: 'viewFindings', Icon: IconBacklog },
  { to: '/applications', labelKey: 'nav.inventory', capability: 'viewInventory', Icon: IconInventory },
  { to: '/pentest/board', labelKey: 'nav.pentest', capability: 'viewPentestProjects', Icon: IconTarget },
]

const SECONDARY_NAV: NavItem[] = [
  { to: '/sbom', labelKey: 'nav.sbom', capability: 'manageSbomIngestion', Icon: IconPackage },
  { to: '/policy', labelKey: 'nav.policy', capability: 'viewPolicy', Icon: IconPolicy },
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

  const isThai = i18n.language.startsWith('th')
  const primary = PRIMARY_NAV.filter((item) => can(user?.role, item.capability))
  const secondary = SECONDARY_NAV.filter((item) => can(user?.role, item.capability))

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  function renderNavItem({ to, labelKey, Icon }: NavItem) {
    return (
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
    )
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        {t('common.skipToContent')}
      </a>

      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand-mark">
            <IconLock />
          </span>
          {t('appName')}
        </Link>

        <div className="topbar-right">
          {isScopedToOwnTeam(user?.role) && user?.owner_team && (
            // UXR-6: make the active data scope unmistakable for narrowed roles.
            <span className="chip chip-scope" title={t('common.scopeTooltip')}>
              <IconTeam />
              {t('common.yourTeam', { team: user.owner_team })}
            </span>
          )}

          {user && (
            <Menu>
              <MenuButton className="user-button" aria-label={t('common.accountMenu')}>
                <span className="avatar">{initials(user.full_name)}</span>
                <span className="user-meta">
                  <span className="user-name">{user.full_name}</span>
                  <span className="user-role">{t(`roles.${user.role}`)}</span>
                </span>
                <IconChevronDown />
              </MenuButton>
              <MenuItems anchor={{ to: 'bottom end', gap: 6 }} transition className="popover-surface menu-items">
                <MenuSection>
                  <MenuHeading className="menu-heading">{user.email}</MenuHeading>
                  {/* UXR-12: the preference is the user's own, persisted by the language detector. */}
                  <MenuItem>
                    <button
                      type="button"
                      className="menu-item"
                      onClick={() => i18n.changeLanguage(isThai ? 'en' : 'th')}
                    >
                      <IconLanguage />
                      {isThai ? t('common.switchToEnglish') : t('common.switchToThai')}
                    </button>
                  </MenuItem>
                  <MenuItem>
                    <button type="button" className="menu-item" onClick={toggle}>
                      {resolved === 'dark' ? <IconSun /> : <IconMoon />}
                      {resolved === 'dark' ? t('common.switchToLight') : t('common.switchToDark')}
                    </button>
                  </MenuItem>
                </MenuSection>
                <MenuSeparator className="menu-separator" />
                <MenuItem>
                  <button type="button" className="menu-item" onClick={handleLogout}>
                    <IconLogout />
                    {t('nav.logout')}
                  </button>
                </MenuItem>
              </MenuItems>
            </Menu>
          )}
        </div>
      </header>

      <div className="body-row">
        <nav className="sidebar" aria-label={t('common.mainNavigation')}>
          {primary.map(renderNavItem)}
          {secondary.length > 0 && <div className="nav-separator" role="presentation" />}
          {secondary.map(renderNavItem)}
        </nav>

        <main className="app-content" id="main-content">
          {children}
        </main>
      </div>
    </div>
  )
}
