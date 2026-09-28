/**
 * The single vector icon set for the whole application (Requirement.md UXR-1).
 *
 * Structural icons — navigation, severity, SLA status, Pentest state — must come from one
 * consistent set and must never be emoji, which render differently per OS and browser.
 * These are drawn in one 24x24 stroke style (Phosphor-like) and inherit `currentColor`,
 * so a severity chip's icon always matches the text colour it was contrast-checked
 * against.
 *
 * Icons are decorative here: every one is paired with a visible text label, so they carry
 * `aria-hidden` and add nothing for screen readers (UXR-2).
 */
import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement> & { size?: number }

function Icon({ size = 16, children, ...props }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  )
}

/* --- Severity tiers (FR-4.4). Distinct shapes, so the tier is readable without colour. --- */

export function IconSeverityCritical(props: IconProps) {
  // Octagon + exclamation: "stop".
  return (
    <Icon {...props}>
      <path d="M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7z" />
      <path d="M12 8v5" />
      <path d="M12 16.5h.01" />
    </Icon>
  )
}

export function IconSeverityHigh(props: IconProps) {
  // Warning triangle.
  return (
    <Icon {...props}>
      <path d="M12 3.5 21 19H3z" />
      <path d="M12 9v5" />
      <path d="M12 16.8h.01" />
    </Icon>
  )
}

export function IconSeverityMedium(props: IconProps) {
  // Diamond.
  return (
    <Icon {...props}>
      <path d="M12 3l9 9-9 9-9-9z" />
      <path d="M12 8.5v4" />
      <path d="M12 15.5h.01" />
    </Icon>
  )
}

export function IconSeverityLow(props: IconProps) {
  // Circled info.
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5" />
      <path d="M12 8h.01" />
    </Icon>
  )
}

/* --- SLA status (FR-5.4) --- */

export function IconOverdue(props: IconProps) {
  // Clock with an alert stroke.
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
      <path d="M19 5 5 19" />
    </Icon>
  )
}

export function IconWithinSla(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8 12.5l2.5 2.5L16 9.5" />
    </Icon>
  )
}

export function IconNoSla(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8.5 12h7" />
    </Icon>
  )
}

export function IconAlertCircle(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v5" />
      <path d="M12 16.2v.1" />
    </Icon>
  )
}

/* --- Finding sources --- */

export function IconPackage(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" />
      <path d="M4 7.5 12 12l8-4.5M12 12v9" />
    </Icon>
  )
}

export function IconCode(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 7 4 12l5 5M15 7l5 5-5 5" />
    </Icon>
  )
}

export function IconTarget(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4" />
      <path d="M12 12h.01" />
    </Icon>
  )
}

/* --- Navigation (UXR-6) --- */

export function IconDashboard(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5" />
    </Icon>
  )
}

export function IconInventory(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 9h18M9 9v11" />
    </Icon>
  )
}

export function IconBacklog(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 6h16M4 12h16M4 18h10" />
    </Icon>
  )
}

export function IconPolicy(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3l7.5 3v6c0 4.2-3 7.8-7.5 9-4.5-1.2-7.5-4.8-7.5-9V6z" />
      <path d="M9 12.5l2 2 4-4.5" />
    </Icon>
  )
}

/** Risk exception register: a signed-off form (Maker-Checker). */
export function IconException(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M8 4h8M9 2.5h6v3H9z" />
      <path d="M16 4h2.5v17h-13V4H8" />
      <path d="M9 13l2 2 4-4" />
    </Icon>
  )
}

/** Control library: stacked layers of defence. */
export function IconLayers(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3l9 4.5-9 4.5-9-4.5z" />
      <path d="M3 12l9 4.5 9-4.5M3 16.5L12 21l9-4.5" />
    </Icon>
  )
}

/** Monthly report: a page with a small bar chart. */
export function IconReport(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M10 17v-3M13 17v-6M16 17v-4" />
    </Icon>
  )
}

export function IconAudit(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M14 3v5h5M9.5 13h5M9.5 17h3" />
    </Icon>
  )
}

/* --- Controls --- */

export function IconSettings(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </Icon>
  )
}

export function IconSun(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19" />
    </Icon>
  )
}

export function IconMoon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z" />
    </Icon>
  )
}

export function IconLanguage(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c2.5 2.5 3.8 5.6 3.8 9S14.5 18.5 12 21c-2.5-2.5-3.8-5.6-3.8-9S9.5 5.5 12 3z" />
    </Icon>
  )
}

export function IconLogout(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M14 4h3.5A2.5 2.5 0 0 1 20 6.5v11A2.5 2.5 0 0 1 17.5 20H14" />
      <path d="M10 8l-4 4 4 4M6 12h9" />
    </Icon>
  )
}

export function IconDownload(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4v11M7.5 10.5 12 15l4.5-4.5" />
      <path d="M5 19h14" />
    </Icon>
  )
}

export function IconPlus(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 5v14M5 12h14" />
    </Icon>
  )
}

export function IconUpload(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 15V4M7.5 8.5 12 4l4.5 4.5" />
      <path d="M5 19h14" />
    </Icon>
  )
}

export function IconRefresh(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 12a8 8 0 0 1 13.66-5.66L20 8.5" />
      <path d="M20 4v4.5h-4.5" />
      <path d="M20 12a8 8 0 0 1-13.66 5.66L4 15.5" />
      <path d="M4 20v-4.5h4.5" />
    </Icon>
  )
}

export function IconChevronRight(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9.5 6l6 6-6 6" />
    </Icon>
  )
}

export function IconChevronDown(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 9.5l6 6 6-6" />
    </Icon>
  )
}

export function IconCheck(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 12.5l4.5 4.5L19 7.5" />
    </Icon>
  )
}

export function IconHelp(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5v.4" />
      <path d="M12 16.8h.01" />
    </Icon>
  )
}

export function IconExternal(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M14 4h6v6" />
      <path d="M20 4 11 13" />
      <path d="M18 14v4.5A1.5 1.5 0 0 1 16.5 20h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10" />
    </Icon>
  )
}

export function IconTeam(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M3 20a6 6 0 0 1 12 0" />
      <path d="M16 5.5a3.5 3.5 0 0 1 0 7M17.5 20h3.5a5.5 5.5 0 0 0-3-4.9" />
    </Icon>
  )
}
