export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

/** Class string for a react-router `Link` that should look like a button. */
export function buttonClass(variant: ButtonVariant = 'secondary', small = false): string {
  return cx('btn', `btn-${variant}`, small && 'btn-sm')
}

/** Pulls FastAPI's `detail` string out of an axios error, with a translated fallback. */
export function apiErrorMessage(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}
