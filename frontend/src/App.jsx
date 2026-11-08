import { useState } from 'react'
import { InsightsSummary } from './views/InsightsSummary'
import { FixFirstQueue } from './views/FixFirstQueue'
import { switchTheme } from './lib/themeTransition'

const THEME_KEY = 'btb-theme'

function initialTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export default function App() {
  const [page, setPage] = useState('insights')
  // Lives here, not in a view, so switching it only reskins the page: the open
  // view keeps its state (selected row, filters, search, sort, open panel).
  const [theme, setTheme] = useState(initialTheme)
  const changeTheme = (next) => {
    if (next === theme) return
    switchTheme(next, () => setTheme(next))
    try {
      localStorage.setItem(THEME_KEY, next)
    } catch {
      /* storage unavailable */
    }
  }

  return page === 'insights' ? (
    <InsightsSummary onOpenFixFirst={() => setPage('fixFirst')} theme={theme} onThemeChange={changeTheme} />
  ) : (
    <FixFirstQueue onOpenInsights={() => setPage('insights')} theme={theme} onThemeChange={changeTheme} />
  )
}
