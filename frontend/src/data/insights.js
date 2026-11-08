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
  // V5 sub-nav: each chip has its own tint (Figma "Insights sub-nav").
  { id: 'summary', label: 'Summary', icon: 'nav-v5/sub-summary', chip: 'bg-blue-soft' },
  { id: 'catch-rate', label: 'Catch rate', icon: 'nav-v5/sub-catch-rate', chip: 'bg-green-soft' },
  { id: 'severity', label: 'Severity', icon: 'nav-v5/sub-severity', chip: 'bg-purple-soft' },
  { id: 'timing', label: 'Time to attack', icon: 'nav-v5/sub-timing', chip: 'bg-blue-soft' },
  { id: 'vendors', label: 'Vendors', icon: 'nav-v5/sub-vendors', chip: 'bg-green-soft' },
  { id: 'bug-types', label: 'Bug types', icon: 'nav-v5/sub-bug-types', chip: 'bg-purple-soft' },
  { id: 'model', label: 'Model check', icon: 'nav-v5/sub-model', chip: 'bg-blue-soft' },
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

// Severity page (chart values are sample data for now).
export const severity = {
  bands: {
    title: 'Severity alone misses most attacks',
    subtitle: 'Share reaching KEV, by CVSS band',
    items: [
      { key: 'critical', label: 'Critical', range: '9.0 to 10', value: '1.9%' },
      { key: 'high', label: 'High', range: '7.0 to 8.9', value: '0.7%' },
      { key: 'medium', label: 'Medium', range: '4.0 to 6.9', value: '0.2%' },
      { key: 'low', label: 'Low', range: '0.1 to 3.9', value: '0.04%' },
    ],
    takeaway: 'Critical CVEs reach KEV about 10× as often as Medium ones, yet 98% of them are never exploited.',
  },
  leadTime: {
    title: 'We flag most exploited CVEs weeks before CISA',
    subtitle: '2025 KEV entries, by days between our top-K flag and the KEV listing',
    buckets: [
      { label: 'After listing', count: 9 },
      { label: '0 to 7 days', count: 14 },
      { label: '8 to 30 days', count: 22 },
      { label: '31 to 90 days', count: 18 },
      { label: 'Over 90 days', count: 7 },
    ],
    peak: { label: 'Peak · median 19 days early', value: '22 CVEs' },
    takeaway:
      'Our model raised the flag before CISA for about 9 in 10 of the KEV entries it caught, a median of 19 days early.',
  },
}
