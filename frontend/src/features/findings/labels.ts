import type { Finding, SeverityTier } from './types'

/** Tier names stay in English in both UI languages: they are the standard CVSS/VEX vocabulary (UXR-12). */
export const SEVERITY_LABEL: Record<SeverityTier, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

/** Identifies a Finding: a CVE where there is one, otherwise its title (FR-6.5.5). */
export function findingLabel(finding: Pick<Finding, 'cve_id' | 'title' | 'id'>): string {
  return finding.cve_id ?? finding.title ?? finding.id
}
