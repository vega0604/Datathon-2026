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
  // Hidden for now: no Time to attack page yet.
  // { id: 'timing', label: 'Time to attack', icon: 'nav-v5/sub-timing', chip: 'bg-blue-soft' },
  { id: 'vendors', label: 'Vendors', icon: 'nav-v5/sub-vendors', chip: 'bg-blue-soft' },
  { id: 'bug-types', label: 'Bug types', icon: 'nav-v5/sub-bug-types', chip: 'bg-green-soft' },
  { id: 'model', label: 'Model check', icon: 'nav-v5/sub-model', chip: 'bg-purple-soft' },
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

// Vendors page (chart values are sample data for now).
// shade: 1 = under 0.5%, 2 = 0.5 to 1%, 4 = 1 to 3%, 5 = over 3% share reaching KEV.
export const vendors = {
  title: 'A handful of vendors carry most of the exploitation',
  subtitle: 'Box size = CVE count, shade = share reaching KEV',
  legend: [
    { shade: 1, label: 'under 0.5%' },
    { shade: 2, label: '0.5 to 1%' },
    { shade: 4, label: '1 to 3%' },
    { shade: 5, label: 'over 3%' },
  ],
  // Heatmap cells. cves sets box size; `short` is the label used when the box is too narrow for the full name.
  cells: [
    { name: 'Microsoft', cves: 6120, kev: '4.2%', shade: 5 },
    { name: 'Linux kernel', cves: 4010, kev: '0.2%', shade: 1 },
    { name: 'Google', cves: 3230, kev: '2.1%', shade: 4 },
    { name: 'Apple', cves: 3180, kev: '1.8%', shade: 4 },
    { name: 'WordPress plugins', short: 'WP', cves: 2040, kev: '0.1%', shade: 1 },
    { name: 'Cisco', cves: 1780, kev: '3.6%', shade: 5 },
    { name: 'Oracle', cves: 1710, kev: '0.7%', shade: 2 },
    { name: 'Adobe', cves: 1740, kev: '0.9%', shade: 2 },
    { name: 'Fortinet', short: 'F', cves: 1000, kev: '6.8%', shade: 5 },
    { name: 'Ivanti', short: 'I', cves: 940, kev: '9.4%', shade: 5 },
    { name: 'Other', cves: 1020, kev: '0.3%', shade: 1 },
  ],
  ranking: [
    { name: 'Ivanti', cves: '940 CVEs', kev: '9.4%' },
    { name: 'Fortinet', cves: '1,000 CVEs', kev: '6.8%' },
    { name: 'Microsoft', cves: '6,120 CVEs', kev: '4.2%' },
    { name: 'Cisco', cves: '1,780 CVEs', kev: '3.6%' },
  ],
  takeaway:
    'Edge vendors like Ivanti, Fortinet and Cisco have few CVEs but the highest exploitation rates; WordPress plugins and the Linux kernel are the reverse.',
}

export const model = {
  leakage: {
    headline: 'Banned columns would have tripled our score',
    status: 'Audit passed, none used',
    banned: { label: 'With banned columns (not allowed)', value: 61 },
    submitted: { label: 'Submitted model', value: 23 },
    takeaway: 'Columns that leak the future nearly triple the hit count, so the submitted model uses none of them.',
  },
  embedding: {
    title: 'Exploited CVEs cluster in Granite’s text space',
    clusters: [
      { label: 'Auth bypass', x: 241.39, y: 26.3 },
      { label: 'Remote code execution', x: 211.04, y: 319.9 },
    ],
    takeaway: 'KEV entries group into two dense regions, which is why Granite embeddings add signal to the ranking.',
  },
}

// Bug types page: one bubble per CWE (Figma "Weakness bubbles" plot, 804×439 design px).
// x = CVE count (log), y = share reaching KEV, size = KEV count.
export const bugTypes = {
  title: 'Some weakness types are exploited far beyond their volume',
  subtitle: 'One bubble per CWE · x = CVE count (log), y = share reaching KEV, size = KEV count',
  // Gridlines: [label, line top]
  yTicks: [['0%', 389.11], ['1%', 295.58], ['2%', 202.04], ['3%', 108.5], ['4%', 14.97]],
  // [label, left]
  xTicks: [['1,000', 32.02], ['3,000', 245.92], ['10k', 486.33], ['30k', 700.22]],
  average: { label: 'All CWEs 0.6%', top: 332.99, labelLeft: 673.76, labelTop: 310.03 },
  // file: bubble/outline SVG pair; [left, top, size]; label [left, top]; key = highlighted (teal, bold label)
  bubbles: [
    { cwe: 'CWE-79', file: 'cwe79', box: [698.01, 366.54, 26.432], label: [638.93, 371.76] },
    { cwe: 'CWE-89', file: 'cwe89', box: [462.81, 337.7, 28], label: [504.06, 343.7] },
    { cwe: 'CWE-787', file: 'cwe787', box: [407.01, 218.58, 41.749], label: [464.46, 231.45] },
    { cwe: 'CWE-20', file: 'cwe20', box: [381.85, 288.91, 32.045], label: [427.6, 296.93] },
    { cwe: 'CWE-125', file: 'cwe79', box: [349.16, 319.78, 26.432], label: [281.18, 324.99] },
    { cwe: 'CWE-416', file: 'cwe416', box: [299.86, 164.26, 38.142], label: [353.3, 175.33] },
    { cwe: 'CWE-22', file: 'cwe20', box: [325.84, 260.85, 32.045], label: [371.59, 268.87] },
    { cwe: 'CWE-78', file: 'cwe78', box: [208.59, 52.26, 37.659], label: [261.49, 63.34], key: true },
    { cwe: 'CWE-352', file: 'cwe352', box: [372.41, 371.24, 17.036], label: [402.36, 371.76] },
    { cwe: 'CWE-434', file: 'cwe434', box: [171.04, 245.22, 25.875], label: [103.13, 250.16] },
    { cwe: 'CWE-862', file: 'cwe862', box: [309.19, 355.99, 19.487], label: [241.99, 357.73] },
    { cwe: 'CWE-287', file: 'cwe287', box: [113.6, 131.55, 28.735], label: [45.36, 137.92] },
    { cwe: 'CWE-502', file: 'cwe502', box: [70.52, 94.5, 28], label: [113.69, 100.75], key: true },
    { cwe: 'CWE-94', file: 'cwe94', box: [149.69, 197.62, 27.544], label: [90.49, 203.39] },
    { cwe: 'CWE-918', file: 'cwe918', box: [89.7, 285.17, 20.817], label: [73.11, 313.03] },
  ],
  callout: { title: 'OS command injection', value: '3.4% reach KEV', left: 281.34, top: 5.18 },
  takeaway:
    'OS command injection and deserialization are rare, yet they reach KEV over 30× as often as cross-site scripting, the most common weakness.',
}
