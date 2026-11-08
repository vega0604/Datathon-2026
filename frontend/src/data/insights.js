// Insights · Summary. KPI figures are real; chart values are sample data for now.
export const user = { name: 'Jane Doe', role: 'Security lead' }

export const coverage = {
  caughtPct: 24, // share of exploited CVEs caught by fixing our top 500
}

export const kpis = [
  { id: 'benchmark', icon: 'insights/kpi-queue', chip: 'solid', label: 'Benchmark CVEs', value: '72,670', pill: 'Top 500 submitted' },
  { id: 'nist', icon: 'insights/kpi-eye', chip: 'soft', label: 'Not reviewed by NIST', value: '51,046', pill: '55% of 2026' },
]

export const versusPublic = [
  ['Our top 500 catch', '24%'],
  ['Best public score', '8 of 500'],
  ['Any CVE, ever exploited', '1 in 250'],
]

export const aboutData = [
  ['Trained on', '2024 CVEs'],
  ['Tested on', '2025 CVEs'],
  ['CVEs scored', '72,670'],
]

export const insightsNav = [
  { id: 'summary', label: 'Summary', icon: 'insights/sub-target', chip: 'bg-blue-soft' },
  { id: 'catch-rate', label: 'Catch rate', icon: 'insights/sub-shield', chip: 'bg-blue-soft' },
  { id: 'severity', label: 'Severity', icon: 'insights/sub-arrow', chip: 'bg-blue-soft' },
  { id: 'timing', label: 'Time to attack', icon: 'insights/sub-bell', chip: 'bg-blue-soft' },
  { id: 'vendors', label: 'Vendors', icon: 'insights/sub-queue', chip: 'bg-blue-soft' },
  { id: 'bug-types', label: 'Bug types', icon: 'insights/sub-eye', chip: 'bg-blue-soft' },
  { id: 'model', label: 'Model check', icon: 'insights/sub-shield', chip: 'bg-blue-soft' },
]
