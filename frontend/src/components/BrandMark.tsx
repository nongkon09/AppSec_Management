/**
 * The product mark: a software package (a dependency) with a shield at its core, for a
 * supply chain that is inventoried and secured. Same artwork as public/favicon.svg.
 */
import { useId } from 'react'

export function BrandMark({ className }: { className?: string }) {
  // Unique per instance, so two marks on one page never share a gradient definition.
  const gradient = useId()
  return (
    <svg className={className} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={gradient} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#0f766e" />
          <stop offset="1" stopColor="#2563eb" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="15" fill={`url(#${gradient})`} />
      <path d="M32 10 51 20.5v23L32 54 13 43.5v-23Z" fill="none" stroke="#fff" strokeWidth="3.6" strokeLinejoin="round" />
      <path
        d="M13 20.5 32 31l19-10.5M32 31v23"
        fill="none"
        stroke="#fff"
        strokeOpacity=".6"
        strokeWidth="3.2"
        strokeLinejoin="round"
      />
      <path d="M32 21.5 41 25v6.2c0 5.2-3.6 9.3-9 11.3-5.4-2-9-6.1-9-11.3V25Z" fill="#fff" />
      <path
        d="m28.2 31.8 2.7 2.7 5-5.2"
        fill="none"
        stroke="#0f766e"
        strokeWidth="2.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
