import type { ApprovalLevel, Role } from './types'

export const ROLES: Role[] = ['appsec', 'dev_team', 'legal', 'management', 'audit', 'admin', 'pipeline']

export const APPROVAL_LEVELS: ApprovalLevel[] = ['none', 'l1', 'l2', 'l3']
