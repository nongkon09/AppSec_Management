import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/tokens.css'
import './styles/app.css'
import './lib/i18n'
import { initTheme } from './lib/theme'
import App from './App.tsx'

// Applied before the first paint, so dark-mode users never see a flash of light (UXR-1).
initTheme()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
