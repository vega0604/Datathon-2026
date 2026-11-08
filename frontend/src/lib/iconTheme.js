import { createContext } from 'react'

// True while a page is showing its dark skin. <Icon> then swaps in the same
// icon recoloured in the Figma dark frames, when one exists.
export const IconDarkContext = createContext(false)

// Folders whose every icon has a dark twin.
const DARK_DIRS = { 'fixfirst/': 'fixfirst-dark/', 'nav-v5/': 'nav-v5-dark/' }
// Single Insights icons that have a dark twin in insights-dark/.
const DARK_INSIGHTS = new Set(['card-target', 'kpi-queue', 'kpi-eye', 'versus-target', 'about-data'])

export function darkIconName(name) {
  for (const [light, dark] of Object.entries(DARK_DIRS)) {
    if (name.startsWith(light)) return dark + name.slice(light.length)
  }
  if (name.startsWith('insights/') && DARK_INSIGHTS.has(name.slice('insights/'.length))) {
    return `insights-dark/${name.slice('insights/'.length)}`
  }
  return name
}
