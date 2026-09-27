export type ControlCategory = 'network' | 'application' | 'monitoring' | 'process'
export type ControlEffectiveness = 'low' | 'medium' | 'high'

export interface SecurityControl {
  id: string
  name: string
  description: string | null
  category: ControlCategory
  owner: string
  evidence_url: string | null
  effectiveness: ControlEffectiveness
  review_due_on: string
  is_active: boolean
  /** Active and not past its review date: may be cited by a new exception. */
  is_usable: boolean
  created_at: string
}

export interface ControlInput {
  name: string
  description: string | null
  category: ControlCategory
  owner: string
  evidence_url: string | null
  effectiveness: ControlEffectiveness
  review_due_on: string
}

export type ControlUpdateInput = Partial<Omit<ControlInput, 'name' | 'category'>> & {
  is_active?: boolean
}
