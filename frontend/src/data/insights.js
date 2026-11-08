// Insights · Summary. KPI figures are real; chart values are sample data for now.
export const user = { name: 'Jane Doe', role: 'Security lead' }

export const coverage = {
  caughtPct: 24, // share of exploited CVEs caught by fixing our top 500
}

export const kpis = [
  { id: 'benchmark', icon: 'insights/kpi-queue', label: 'Benchmark CVEs', value: '72,670', pill: 'Top 500 submitted' },
  { id: 'nist', icon: 'insights/kpi-eye', label: 'Not reviewed by NIST', value: '51,046', pill: '55% of 2026' },
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

// Catch rate page (chart values are sample data for now).
export const catchRate = {
  headline: 'Our model catches more exploited CVEs at every queue size',
  // Share of exploited CVEs caught after fixing 5k CVEs, by ranking.
  series: [
    { label: 'Our model', value: 62, legend: 'legend-our-model', legendHeight: 3 },
    { label: 'Exploit + EPSS', value: 26, legend: 'legend-exploit-epss', legendHeight: 2 },
    { label: 'EPSS', value: 22, legend: 'legend-epss', legendHeight: 2 },
    { label: 'Highest CVSS', value: 18, legend: 'legend-highest-cvss', legendHeight: 2 },
  ],
  top500: { label: 'Fix 500 (0.7%)', value: 'Catch 24% of exploited CVEs' },
  takeaway:
    'Fixing just 0.7% of the queue, our top 500, catches about a quarter of the CVEs that went on to be exploited, roughly 4× the best public baseline.',
}
