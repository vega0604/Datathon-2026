import { flushSync } from 'react-dom'

// Light → dark icon folders (see iconTheme.js); preloaded so they don't pop in mid-fade.
const PAIRS = [
  ['/fixfirst/', '/fixfirst-dark/'],
  ['/nav-v5/', '/nav-v5-dark/'],
  ['/insights/', '/insights-dark/'],
]

function preload(src) {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = img.onerror = resolve
    img.src = src
  })
}

/**
 * Switches the page skin with a short, quiet crossfade (180ms) instead of an instant flip.
 * The next theme's icons are preloaded first so they don't pop in mid-fade.
 * Uses the View Transitions API where available, otherwise a short CSS colour
 * fade; skips animation entirely for people who prefer reduced motion.
 */
export async function switchTheme(next, apply) {
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  if (reduced) return apply()

  const upcoming = [...document.images].flatMap((img) =>
    PAIRS.filter(([light, dark]) => img.src.includes(next === 'dark' ? light : dark)).map(([light, dark]) =>
      next === 'dark' ? img.src.replace(light, dark) : img.src.replace(dark, light),
    ),
  )
  await Promise.race([Promise.all(upcoming.map(preload)), new Promise((r) => setTimeout(r, 400))])

  if (document.startViewTransition) {
    document.startViewTransition(() => flushSync(apply))
    return
  }
  const root = document.documentElement
  root.classList.add('theme-animating')
  apply()
  setTimeout(() => root.classList.remove('theme-animating'), 200)
}
