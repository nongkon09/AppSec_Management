import i18n from './i18n'

/** Dates follow the UI language, so a Thai-language user sees Thai month names. */
export function formatDate(value: string | null | undefined): string {
  if (!value) return '—'
  return new Date(value).toLocaleDateString(i18n.language, { dateStyle: 'medium' })
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—'
  return new Date(value).toLocaleString(i18n.language, { dateStyle: 'medium', timeStyle: 'short' })
}
