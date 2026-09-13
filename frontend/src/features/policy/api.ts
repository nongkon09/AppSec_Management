import { apiClient } from '../../lib/api'
import type {
  PolicySet,
  PolicySetCreate,
  SeverityEvaluationRequest,
  SeverityEvaluationResult,
} from './types'

export async function fetchEffectivePolicy(): Promise<PolicySet> {
  const { data } = await apiClient.get<PolicySet>('/policies/effective')
  return data
}

export async function listPolicyVersions(): Promise<PolicySet[]> {
  const { data } = await apiClient.get<PolicySet[]>('/policies')
  return data
}

export async function publishPolicyVersion(payload: PolicySetCreate): Promise<PolicySet> {
  const { data } = await apiClient.post<PolicySet>('/policies', payload)
  return data
}

export async function evaluateSeverity(
  payload: SeverityEvaluationRequest,
): Promise<SeverityEvaluationResult> {
  const { data } = await apiClient.post<SeverityEvaluationResult>('/policies/evaluate', payload)
  return data
}
