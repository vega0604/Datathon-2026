// Sample values until the model ships (matches the Figma design).
export const company = { name: 'Maple Freight', components: 214 }

export const queue = [
  {
    rank: 1,
    cveId: 'CVE-2025-9242',
    component: 'WatchGuard Firebox',
    shortName: 'Firebox',
    cvssRank: 9,
    score: 0.91,
    cvss: 9.3,
    severity: 'Critical',
    ticket: null,
    vendorInitials: 'WG',
    subtitle: 'WatchGuard Firebox · Fireware OS · 3 SBOM assets',
    edge: true,
    reasons: [
      { icon: 'icon-code', label: 'Public exploit code appeared in Oct 2025', value: 0.31, barPx: 404, tone: 'primary' },
      { icon: 'icon-shield-sm', label: 'Internet-facing edge device', value: 0.22, barPx: 287, tone: 'inverse' },
      { icon: 'icon-vendor', label: 'WatchGuard already has 14 KEV entries', value: 0.12, barPx: 156, tone: 'inverse' },
    ],
    explanation:
      'An unauthenticated attacker can send crafted IKEv2 packets to the Firebox VPN and run code on it. Exploit code went public in October and WatchGuard devices are a frequent KEV target, so expect attacks soon.',
    xforce: { riskScore: '9.3', exploit: 'Public', attacksSeen: 'Yes' },
  },
  { rank: 2, cveId: 'CVE-2025-12480', component: 'Gladinet Triofox', cvssRank: 12, score: 0.86, cvss: 9.1, severity: 'Critical', ticket: null, edge: false },
  { rank: 3, cveId: 'CVE-2025-48703', component: 'CWP Control Web Panel', cvssRank: 15, score: 0.83, cvss: 9.0, severity: 'Critical', ticket: 'DEMO-12', edge: false },
  { rank: 4, cveId: 'CVE-2025-6205', component: 'Dassault DELMIA Apriso', cvssRank: 24, score: 0.71, cvss: 8.1, severity: 'High', ticket: null, edge: false },
  { rank: 5, cveId: 'CVE-2025-24016', component: 'Wazuh Server', cvssRank: 1, score: 0.64, cvss: 9.9, severity: 'Critical', ticket: 'DEMO-13', edge: false },
  { rank: 6, cveId: 'CVE-2024-38475', component: 'Apache HTTP Server', cvssRank: 13, score: 0.52, cvss: 9.1, severity: 'Critical', ticket: null, edge: true },
  { rank: 7, cveId: 'CVE-2025-4008', component: 'Smartbedded Meteobridge', cvssRank: 19, score: 0.47, cvss: 8.6, severity: 'High', ticket: null, edge: true },
  { rank: 8, cveId: 'CVE-2024-53197', component: 'Linux kernel · USB audio', cvssRank: 27, score: 0.31, cvss: 7.8, severity: 'High', ticket: null, edge: false },
]

// Counts shown in the design (the full queue has 38 items; only the top 8 are sampled here).
export const totals = { open: 38, critical: 6, edge: 9, notInLinear: 26, inLinear: 12, alerts: 6, criticalNew: 2 }
