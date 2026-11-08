import { useEffect, useState } from 'react'
import { InsightsSummary } from './views/InsightsSummary'
import { FixFirstQueue } from './views/FixFirstQueue'
import { YourSoftware } from './views/YourSoftware'
import { switchTheme } from './lib/themeTransition'
import { LoadingScreen } from './components/LoadingScreen'
import { deleteSbom, prefetchShell, useQueue, useSboms } from './lib/api'

const THEME_KEY = 'btb-theme'
const CURRENT_KEY = 'btb-current-sbom'

function initialTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function savedCurrent() {
  try {
    return localStorage.getItem(CURRENT_KEY)
  } catch {
    return null
  }
}

// Start the shell's requests (user, SBOM list) before the first render. The splash
// waits for them; they never reject, so a backend that's down doesn't block it.
const shellReady = prefetchShell()

// Start-up loading screen: shown until the fonts are ready and the first data has
// arrived, and for at least MIN_SPLASH_MS, so the scan animation can finish once.
const MIN_SPLASH_MS = 1400
const SPLASH_FADE_MS = 360

function useSplash() {
  const [phase, setPhase] = useState('show') // 'show' → 'leaving' → 'done'
  useEffect(() => {
    let cancelled = false
    const minTime = new Promise((r) => setTimeout(r, MIN_SPLASH_MS))
    const fonts = document.fonts?.ready ?? Promise.resolve()
    Promise.all([minTime, fonts, shellReady]).then(() => {
      if (cancelled) return
      setPhase('leaving')
      setTimeout(() => !cancelled && setPhase('done'), SPLASH_FADE_MS)
    })
    return () => {
      cancelled = true
    }
  }, [])
  return phase
}

export default function App() {
  const splash = useSplash()
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

  // Saved SBOMs come from the backend. The selected one (or the newest) drives both
  // Your software and the Fix first queue; only its id is remembered in this browser.
  const sboms = useSboms()
  const library = sboms.data ?? []
  const [chosenId, setChosenId] = useState(savedCurrent)
  const currentId = library.some((s) => s.id === chosenId) ? chosenId : (library[0]?.id ?? null)
  const choose = (id) => {
    setChosenId(id)
    try {
      if (id) localStorage.setItem(CURRENT_KEY, id)
      else localStorage.removeItem(CURRENT_KEY)
    } catch {
      /* storage unavailable */
    }
  }
  const [swState, setSwScreen] = useState({ name: 'overview' })
  // Nothing uploaded yet: the overview becomes the upload screen.
  const swScreen = swState.name === 'overview' && sboms.data && !library.length ? { name: 'empty' } : swState

  // One queue request per SBOM, shared by the Fix first page and every page's
  // sidebar (cached, so switching pages never refetches it).
  const queue = useQueue(currentId)
  const totals = queue.data?.totals ?? null

  const [removeError, setRemoveError] = useState(null)
  const removeSbom = async (id) => {
    setRemoveError(null)
    try {
      await deleteSbom(id)
    } catch (e) {
      setRemoveError(e.message)
      return
    }
    if (id === currentId) {
      const next = library.find((s) => s.id !== id)
      choose(next?.id ?? null)
      setSwScreen({ name: next ? 'overview' : 'empty' })
    }
  }

  const nav = {
    onOpenFixFirst: () => setPage('fixFirst'),
    onOpenInsights: () => setPage('insights'),
    onHome: () => {
      setPage('insights')
      setHomeKey((k) => k + 1)
    },
    totals,
    // Saved uploads, listed in the sidebar on every page. Highlighted only on the software page.
    software: {
      library,
      loading: sboms.loading && !sboms.data,
      error: sboms.error?.message ?? removeError,
      currentId: page === 'software' ? currentId : null,
      onSelect: (id) => {
        choose(id)
        setSwScreen({ name: 'overview' })
        setPage('software')
      },
      onRemove: removeSbom,
    },
    onUpload: () => {
      setSwScreen({ name: 'empty' })
      setPage('software')
    },
    theme,
    onThemeChange: changeTheme,
  }

  // The app renders underneath the splash, so it's ready the moment the splash fades.
  const splashScreen = splash !== 'done' && <LoadingScreen theme={theme} leaving={splash === 'leaving'} />

  if (page === 'software')
    return (
      <>
      {splashScreen}
      <YourSoftware
        {...nav}
        sbomId={currentId}
        library={library}
        onUploaded={(id) => choose(id)}
        onSelect={nav.software.onSelect}
        onRemove={removeSbom}
        screen={swScreen}
        onScreen={setSwScreen}
      />
      </>
    )
  return (
    <>
      {splashScreen}
      {page === 'insights' ? (
        <InsightsSummary key={homeKey} {...nav} />
      ) : (
        <FixFirstQueue {...nav} sbomId={currentId} sbomName={library.find((s) => s.id === currentId)?.name} queue={queue} />
      )}
    </>
  )
}
