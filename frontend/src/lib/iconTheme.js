import { createContext, useContext } from 'react'

// True while a page is showing its dark skin. <Icon> then swaps in the same
// icon recoloured in the Figma dark frames, when one exists.
export const IconDarkContext = createContext(false)

// Folders whose every icon has a dark twin.
const DARK_DIRS = { 'fixfirst/': 'fixfirst-dark/', 'nav-v5/': 'nav-v5-dark/' }
// Insights icons (path after insights/) that have a dark twin in insights-dark/.
const DARK_INSIGHTS = new Set([
  'card-target',
  'card-bubbles',
  'card-bars',
  'card-line',
  'kpi-queue',
  'kpi-eye',
  'versus-target',
  'about-data',
  'catch-rate/takeaway-idea',
  'catch-rate/howto-eye',
  'catch-rate/area-our-model',
  'catch-rate/line-our-model',
  'catch-rate/legend-our-model',
  'catch-rate/marker-top500',
  'severity/status-critical',
  'severity/status-high',
  'severity/status-medium',
  'severity/status-low',
])

// Software severity shapes with a dark twin in software-dark/ (Figma dark frames).
const DARK_SOFTWARE = new Set(['sev-critical', 'sev-high', 'sev-medium', 'sev-none'])

export function darkIconName(name) {
  if (name.startsWith('software/') && DARK_SOFTWARE.has(name.slice('software/'.length))) {
    return `software-dark/${name.slice('software/'.length)}`
  }
  for (const [light, dark] of Object.entries(DARK_DIRS)) {
    if (name.startsWith(light)) return dark + name.slice(light.length)
  }
  if (name.startsWith('insights/') && DARK_INSIGHTS.has(name.slice('insights/'.length))) {
    return `insights-dark/${name.slice('insights/'.length)}`
  }
  return name
}

/** For code that builds icon URLs itself (plain <img>): maps a name to the current theme's icon. */
export function useThemedIcon() {
  const dark = useContext(IconDarkContext)
  return (name) => (dark ? darkIconName(name) : name)
}
