import { useState } from 'react'
import { InsightsSummary } from './views/InsightsSummary'
import { FixFirstQueue } from './views/FixFirstQueue'
import { YourSoftware } from './views/YourSoftware'
import { switchTheme } from './lib/themeTransition'
import { loadLibrary, saveLibrary } from './lib/sbom'

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
  // Bumped by the logo: remounts Insights so it opens on Summary (the home page).
  const [homeKey, setHomeKey] = useState(0)
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

  // "Your software": the uploaded SBOM and which screen of the flow is open.
  // Kept here so they survive moving to Fix first / Insights and back.
  // Uploads are saved in this browser, so they're still listed next visit.
  const [library, setLibrary] = useState(loadLibrary)
  const [currentId, setCurrentId] = useState(() => library[0]?.id ?? null)
  const sbom = library.find((s) => s.id === currentId) ?? null
  const [swScreen, setSwScreen] = useState(() => ({ name: sbom ? 'overview' : 'empty' }))
  const updateLibrary = (next) => {
    setLibrary(next)
    saveLibrary(next)
  }
  const addSbom = (s) => {
    // Re-uploading the same file replaces the older copy instead of duplicating it.
    const entry = { ...s, id: `${s.fileName}-${s.uploadedAt}` }
    updateLibrary([entry, ...library.filter((x) => x.fileName !== s.fileName)])
    setCurrentId(entry.id)
  }
  const removeSbom = (id) => {
    const next = library.filter((x) => x.id !== id)
    updateLibrary(next)
    if (id === currentId) {
      setCurrentId(next[0]?.id ?? null)
      setSwScreen({ name: next.length ? 'overview' : 'empty' })
    }
  }
  const nav = {
    onOpenFixFirst: () => setPage('fixFirst'),
    onOpenInsights: () => setPage('insights'),
    onHome: () => {
      setPage('insights')
      setHomeKey((k) => k + 1)
    },
    // Saved uploads, listed in the sidebar on every page. Highlighted only on the software page.
    software: {
      library,
      currentId: page === 'software' ? currentId : null,
      onSelect: (id) => {
        setCurrentId(id)
        setSwScreen({ name: 'overview' })
        setPage('software')
      },
      onRemove: (id) => removeSbom(id),
    },
    onUpload: () => {
      setSwScreen({ name: 'empty' })
      setPage('software')
    },
    theme,
    onThemeChange: changeTheme,
  }

  if (page === 'software')
    return (
      <YourSoftware
        {...nav}
        sbom={sbom}
        library={library}
        onSbom={addSbom}
        onSelect={nav.software.onSelect}
        onRemove={removeSbom}
        screen={swScreen}
        onScreen={setSwScreen}
      />
    )
  return page === 'insights' ? <InsightsSummary key={homeKey} {...nav} /> : <FixFirstQueue {...nav} />
}
