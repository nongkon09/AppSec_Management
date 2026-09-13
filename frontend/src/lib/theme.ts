/**
 * Light/dark theme preference (Requirement.md UXR-1).
 *
 * Dark mode is what the AppSec team uses most of the day, so the choice is explicit and
 * remembered rather than following the OS only. `system` stays available and tracks
 * `prefers-color-scheme` live.
 *
 * Only two things are state here: the user's preference and whether the OS currently
 * reports dark. The applied theme is derived from those during render, so there is no
 * effect writing state back into the component.
 */
import { useCallback, useEffect, useState } from 'react'

export type ThemePreference = 'light' | 'dark' | 'system'

const STORAGE_KEY = 'appsec.theme'
const DARK_QUERY = '(prefers-color-scheme: dark)'

function systemPrefersDark(): boolean {
  return window.matchMedia?.(DARK_QUERY).matches ?? false
}

function readPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      return stored
    }
  } catch {
    // Private mode / blocked storage: fall back to the OS setting.
  }
  return 'system'
}

/**
 * Applies the stored theme before React's first paint.
 *
 * Called from main.tsx: without it a dark-mode user sees a flash of the light palette on
 * load, because the hook's effect only runs after the first render.
 */
export function initTheme(): void {
  const preference = readPreference()
  const resolved = preference === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : preference
  document.documentElement.dataset.theme = resolved
}

export function useTheme() {
  const [preference, setPreference] = useState<ThemePreference>(readPreference)
  const [osPrefersDark, setOsPrefersDark] = useState<boolean>(systemPrefersDark)

  const resolved: 'light' | 'dark' =
    preference === 'system' ? (osPrefersDark ? 'dark' : 'light') : preference

  // The `data-theme` attribute and localStorage are both outside React, which is exactly
  // what an effect is for.
  useEffect(() => {
    document.documentElement.dataset.theme = resolved
  }, [resolved])

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, preference)
    } catch {
      // The preference is cosmetic; losing it is not worth surfacing an error for.
    }
  }, [preference])

  useEffect(() => {
    const media = window.matchMedia(DARK_QUERY)
    const onChange = (event: MediaQueryListEvent) => setOsPrefersDark(event.matches)
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  const toggle = useCallback(() => {
    setPreference(resolved === 'dark' ? 'light' : 'dark')
  }, [resolved])

  return { preference, resolved, setPreference, toggle }
}
