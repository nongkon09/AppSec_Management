/**
 * Sub-navigation for the Settings section (Requirement.md Section 4: System Admin
 * manages User/Role, Integration Connector Configuration, and System Configuration —
 * Users and Integrations are the two concrete screens so far).
 */
import { useTranslation } from 'react-i18next'
import { NavLink } from 'react-router-dom'

export function SettingsTabs() {
  const { t } = useTranslation()
  return (
    <nav className="route-tabs" aria-label={t('settings.tabsLabel')}>
      <NavLink
        to="/settings/users"
        className={({ isActive }) => (isActive ? 'route-tab active' : 'route-tab')}
      >
        {t('nav.settingsUsers')}
      </NavLink>
      <NavLink
        to="/settings/integrations"
        className={({ isActive }) => (isActive ? 'route-tab active' : 'route-tab')}
      >
        {t('nav.settingsIntegrations')}
      </NavLink>
    </nav>
  )
}
