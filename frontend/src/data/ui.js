// Fixed interface text and icons. Every number on screen comes from the backend
// (src/lib/api.js); this file only holds labels the backend doesn't send.

export const insightsNav = [
  // V5 sub-nav: each chip has its own tint (Figma "Insights sub-nav").
  { id: 'summary', label: 'Summary', icon: 'nav-v5/sub-summary', chip: 'bg-blue-soft' },
  { id: 'catch-rate', label: 'Model overview', icon: 'nav-v5/sub-catch-rate', chip: 'bg-green-soft' },
  // Hidden for now: no Time to attack page yet.
  // { id: 'timing', label: 'Time to attack', icon: 'nav-v5/sub-timing', chip: 'bg-blue-soft' },
  { id: 'vendors', label: 'Vendors', icon: 'nav-v5/sub-vendors', chip: 'bg-purple-soft' },
]

// Early warning signs shown in the queue's "Warning sign" column (API `signal`).
export const signals = {
  code: { label: 'Attack code published', icon: 'fixfirst/signal-code', border: 'border-chart-1' },
  vendor: { label: 'Same product attacked', icon: 'fixfirst/signal-vendor', border: 'border-ai' },
  trend: { label: 'Risk score jumped', icon: 'fixfirst/signal-trend', border: 'border-chart-2' },
}

export const severityText = {
  title: 'Severity alone misses most attacks',
  subtitle: 'Share reaching KEV, by CVSS band',
  labels: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' },
}

export const bugTypesText = {
  title: 'Some weakness types are exploited far beyond their volume',
  subtitle: 'One bubble per CWE · x = CVE count (log), y = share reaching KEV, size = KEV count',
}

export const catchRateText = {
  headline: 'Our model catches more exploited CVEs at every queue size',
  // Legend graphics per ranking (exported Figma swatches).
  legend: {
    model: { file: 'legend-our-model', height: 3 },
    exploit_epss: { file: 'legend-exploit-epss', height: 2 },
    epss: { file: 'legend-epss', height: 2 },
    cvss: { file: 'legend-highest-cvss', height: 2 },
  },
}

export const embeddingText = { title: 'Exploited CVEs cluster in Granite’s text space' }

export const vendorsText = {
  title: 'A handful of vendors carry most of the exploitation',
  subtitle: 'Box size = CVE count, shade = share reaching KEV',
  // shade: 1 = under 0.5%, 2 = 0.5 to 1%, 4 = 1 to 3%, 5 = over 3% share reaching KEV.
  legend: [
    { shade: 1, label: 'under 0.5%' },
    { shade: 2, label: '0.5 to 1%' },
    { shade: 4, label: '1 to 3%' },
    { shade: 5, label: 'over 3%' },
  ],
}

/** The heatmap shade bucket for a KEV share (a 0-1 fraction). */
export function kevShade(share) {
  if (share < 0.005) return 1
  if (share < 0.01) return 2
  if (share < 0.03) return 4
  return 5
}

/** 0.0204 -> "2.0%"; small shares keep two decimals ("0.04%"). */
export function pct(share, digits) {
  const p = share * 100
  const d = digits ?? (p > 0 && p < 0.1 ? 2 : 1)
  return `${p.toFixed(d)}%`
}
