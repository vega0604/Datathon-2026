// Fix first queue. Ranks, model scores, CVSS ranks, warning signs and row 1's
// reasons / Granite text / X-Force facts are sample values from the Figma design
// (page V5) until the model ships (SHE-47 explanations, SHE-56 reasons).
//
// Rows 2-10 `explanation` and `kev` are real public facts, summarised from each
// CVE's NVD record and the CISA KEV catalog (both checked 2026-11-08). Their
// `reasons` labels are facts from the same sources (NVD exploit references, CVSS
// vector, earlier KEV entries for the vendor); the `value` weights are SAMPLE
// numbers until the model's SHAP output lands (SHE-56).
// CVSS scores match NVD; CVE-2025-6205 is 9.1 Critical there (the design said 8.1 High).

// Early warning signs shown in the queue's "Warning sign" column.
export const signals = {
  code: { label: 'Attack code published', icon: 'fixfirst/signal-code', border: 'border-chart-1' },
  vendor: { label: 'Same vendor attacked', icon: 'fixfirst/signal-vendor', border: 'border-ai' },
  trend: { label: 'Risk score jumped', icon: 'fixfirst/signal-trend', border: 'border-chart-2' },
}

export const queue = [
  {
    rank: 1,
    cveId: 'CVE-2025-9242',
    component: 'WatchGuard Firebox',
    cvssRank: 9,
    score: 0.91,
    cvss: 9.3,
    severity: 'Critical',
    signal: 'code',
    ticket: null,
    vendorInitials: 'WG',
    subtitle: 'WatchGuard Firebox · Fireware OS · 3 SBOM assets',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'Public exploit code appeared in Oct 2025', value: 0.31 },
      { icon: 'fixfirst/reason-shield', label: 'Internet-facing edge device', value: 0.22 },
      // The design said "already has 14 KEV entries"; the KEV catalog lists 2 before this CVE.
      { icon: 'fixfirst/reason-vendor', label: 'WatchGuard had 2 KEV entries before this', value: 0.12 },
    ],
    explanation:
      'Attackers can take over the Firebox VPN from the internet without a password, and working attack code is now public.',
    explanationSource: 'granite',
    xforce: { riskScore: '9.3 of 10', attacksSeen: 'Yes, this month' },
    kev: { added: '2025-11-12', ransomware: false, weakness: 'Out-of-bounds write (CWE-787)' },
  },
  {
    rank: 2,
    cveId: 'CVE-2025-12480',
    component: 'Gladinet Triofox',
    cvssRank: 12,
    score: 0.86,
    cvss: 9.1,
    severity: 'Critical',
    signal: 'vendor',
    ticket: null,
    vendorInitials: 'GL',
    subtitle: 'Gladinet · Triofox before 16.7.10368.56560',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'NVD links a public exploit', value: 0.28 },
      { icon: 'fixfirst/reason-shield', label: 'No login needed, over the network', value: 0.21 },
      { icon: 'fixfirst/reason-vendor', label: 'Gladinet had 2 KEV entries before this', value: 0.09 },
    ],
    explanation:
      'Triofox leaves its first-time setup pages open after setup, so attackers can reach screens that should be locked. Version 16.7.10368.56560 fixes it.',
    kev: { added: '2025-11-12', ransomware: false, weakness: 'Improper access control (CWE-284)' },
  },
  {
    rank: 3,
    cveId: 'CVE-2025-48703',
    component: 'CWP Control Web Panel',
    cvssRank: 15,
    score: 0.83,
    cvss: 9.0,
    severity: 'Critical',
    signal: 'trend',
    ticket: 'DEMO-12',
    vendorInitials: 'CW',
    subtitle: 'CWP (CentOS Web Panel) before 0.9.8.1205',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'NVD links a public exploit', value: 0.26 },
      { icon: 'fixfirst/reason-shield', label: 'No login needed, over the network', value: 0.19 },
      { icon: 'fixfirst/reason-vendor', label: 'CWP had 1 KEV entry before this', value: 0.08 },
    ],
    explanation:
      'Anyone who knows a non-root username can run commands on the server without logging in, via the file manager. Version 0.9.8.1205 fixes it.',
    kev: { added: '2025-11-04', ransomware: false, weakness: 'OS command injection (CWE-78)' },
  },
  {
    rank: 4,
    cveId: 'CVE-2025-6205',
    component: 'Dassault DELMIA Apriso',
    cvssRank: 24,
    score: 0.71,
    cvss: 9.1,
    severity: 'Critical',
    signal: 'code',
    ticket: null,
    vendorInitials: 'DS',
    subtitle: 'Dassault Systèmes · DELMIA Apriso 2020–2025',
    reasons: [
      { icon: 'fixfirst/reason-shield', label: 'No login needed, over the network', value: 0.24 },
      { icon: 'fixfirst/reason-code', label: 'Gives privileged access to the app', value: 0.15 },
      { icon: 'fixfirst/reason-vendor', label: 'Dassault had 1 KEV entry before this', value: 0.07 },
    ],
    explanation:
      'A missing permission check in DELMIA Apriso lets an attacker get privileged access to the application. Releases 2020 through 2025 are affected.',
    kev: { added: '2025-10-28', ransomware: false, weakness: 'Missing authorization (CWE-862)' },
  },
  {
    rank: 5,
    cveId: 'CVE-2025-24016',
    component: 'Wazuh Server',
    cvssRank: 1,
    score: 0.64,
    cvss: 9.9,
    severity: 'Critical',
    signal: null,
    ticket: 'DEMO-13',
    vendorInitials: 'WZ',
    subtitle: 'Wazuh Server 4.4.0 to before 4.9.1',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'NVD links a public exploit', value: 0.25 },
      { icon: 'fixfirst/reason-shield', label: 'Over the network, with a basic login', value: 0.12 },
      { icon: 'fixfirst/reason-vendor', label: 'No earlier Wazuh KEV entries', value: -0.04 },
    ],
    explanation:
      'Anyone with Wazuh API access, such as a hijacked dashboard or cluster server, can make the server run their own Python code. 4.9.1 fixes it.',
    kev: { added: '2025-06-10', ransomware: false, weakness: 'Unsafe deserialization (CWE-502)' },
  },
  {
    rank: 6,
    cveId: 'CVE-2025-6204',
    component: 'Dassault DELMIA Apriso',
    cvssRank: 25,
    score: 0.62,
    cvss: 8.0,
    severity: 'High',
    signal: 'code',
    ticket: null,
    vendorInitials: 'DS',
    subtitle: 'Dassault Systèmes · DELMIA Apriso 2020–2025',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'Lets attackers run their own code', value: 0.2 },
      { icon: 'fixfirst/reason-vendor', label: 'Dassault had 1 KEV entry before this', value: 0.09 },
      { icon: 'fixfirst/reason-shield', label: 'Needs an admin login', value: -0.06 },
    ],
    explanation:
      'A code injection flaw in DELMIA Apriso could let an attacker run their own code. Releases 2020 through 2025 are affected.',
    kev: { added: '2025-10-28', ransomware: false, weakness: 'Code injection (CWE-94)' },
  },
  {
    rank: 7,
    cveId: 'CVE-2025-4008',
    component: 'Smartbedded Meteobridge',
    cvssRank: 19,
    score: 0.58,
    cvss: 8.8,
    severity: 'High',
    signal: 'trend',
    ticket: null,
    vendorInitials: 'SB',
    subtitle: 'Smartbedded · Meteobridge web interface',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'NVD links a public exploit', value: 0.27 },
      { icon: 'fixfirst/reason-shield', label: 'No login needed, from the same network', value: 0.08 },
      { icon: 'fixfirst/reason-vendor', label: 'No earlier Smartbedded KEV entries', value: -0.05 },
    ],
    explanation:
      'The Meteobridge web interface has an endpoint that lets attackers run commands as root over the network, without logging in.',
    kev: { added: '2025-10-02', ransomware: false, weakness: 'Command injection (CWE-77)' },
  },
  {
    rank: 8,
    cveId: 'CVE-2025-10035',
    component: 'Fortra GoAnywhere MFT',
    cvssRank: 2,
    score: 0.55,
    cvss: 10.0,
    severity: 'Critical',
    signal: null,
    ticket: null,
    vendorInitials: 'FO',
    subtitle: 'Fortra · GoAnywhere MFT License Servlet',
    reasons: [
      { icon: 'fixfirst/reason-shield', label: 'No login needed, over the network', value: 0.22 },
      { icon: 'fixfirst/reason-vendor', label: 'Fortra had 3 KEV entries before this', value: 0.14 },
      { icon: 'fixfirst/reason-code', label: 'Can lead to running commands', value: 0.1 },
    ],
    explanation:
      'A forged license response lets an attacker make GoAnywhere MFT load an object they control, which can lead to running commands. CISA reports ransomware use.',
    kev: { added: '2025-09-29', ransomware: true, weakness: 'Unsafe deserialization (CWE-502)' },
  },
  {
    rank: 9,
    cveId: 'CVE-2025-20352',
    component: 'Cisco IOS SNMP',
    cvssRank: 31,
    score: 0.49,
    cvss: 7.7,
    severity: 'High',
    signal: null,
    ticket: null,
    vendorInitials: 'CI',
    subtitle: 'Cisco · IOS and IOS XE SNMP subsystem',
    reasons: [
      { icon: 'fixfirst/reason-vendor', label: 'Cisco had 80 KEV entries before this', value: 0.24 },
      { icon: 'fixfirst/reason-code', label: 'Can run code as root on IOS XE', value: 0.13 },
      { icon: 'fixfirst/reason-shield', label: 'Needs SNMP credentials', value: -0.07 },
    ],
    explanation:
      'A crafted SNMP packet crashes Cisco IOS and IOS XE for anyone with a read-only SNMP login. With admin rights, it runs code as root on IOS XE.',
    kev: { added: '2025-09-29', ransomware: false, weakness: 'Stack-based buffer overflow (CWE-121)' },
  },
  {
    rank: 10,
    cveId: 'CVE-2025-53690',
    component: 'Sitecore XM',
    cvssRank: 14,
    score: 0.47,
    cvss: 9.0,
    severity: 'Critical',
    signal: null,
    ticket: null,
    vendorInitials: 'SC',
    subtitle: 'Sitecore · XM and XP through 9.0',
    reasons: [
      { icon: 'fixfirst/reason-code', label: 'NVD links a public exploit', value: 0.22 },
      { icon: 'fixfirst/reason-shield', label: 'No login needed, over the network', value: 0.13 },
      { icon: 'fixfirst/reason-vendor', label: 'Sitecore had 3 KEV entries before this', value: 0.07 },
    ],
    explanation:
      'Sitecore Experience Manager and Experience Platform up to 9.0 trust data they unpack, which lets an attacker inject and run code.',
    kev: { added: '2025-09-04', ransomware: false, weakness: 'Unsafe deserialization (CWE-502)' },
  },
]

// Counts for the full 38-item queue (only the top 10 are sampled here). From the
// design, except critical: the design said 6, but the 10 rows above already hold 7
// Critical CVEs once CVE-2025-6205 uses its NVD score.
export const totals = { open: 38, critical: 7, notInLinear: 26, warningSigns: 6 }
