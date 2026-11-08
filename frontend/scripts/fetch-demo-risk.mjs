// Builds src/data/demoRisk.json: real vulnerability facts for every component in
// the demo SBOM (backend/demo/acme_sbom.cdx.json), so the "Your software" screens
// show real numbers for the demo file instead of made-up ones.
//
//   NIST NVD  - CVEs that affect each component's CPE (name + version), with CVSS
//   CISA KEV  - which of those CVEs attackers are known to be using
//   FIRST EPSS - predicted chance each CVE gets exploited (next 30 days)
//
// Run: node scripts/fetch-demo-risk.mjs   (about 2-3 minutes: NVD allows ~5 requests / 30 s without a key)
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const sbomPath = join(root, '..', 'backend', 'demo', 'acme_sbom.cdx.json')
const outPath = join(root, 'src', 'data', 'demoRisk.json')
const UA = { 'User-Agent': 'before-the-breach-datathon' }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function getJson(url, tries = 4) {
  for (let i = 0; i < tries; i++) {
    const res = await fetch(url, { headers: UA })
    if (res.ok) return res.json()
    await sleep(8000 * (i + 1)) // NVD answers 403/503 when rate-limited
  }
  throw new Error(`Failed: ${url}`)
}

function cvssOf(cve) {
  const m = cve.metrics ?? {}
  const pick = (k) => (m[k] ?? []).find((x) => x.type === 'Primary') ?? (m[k] ?? [])[0]
  const v = pick('cvssMetricV31') ?? pick('cvssMetricV30') ?? pick('cvssMetricV40')
  return v ? { score: v.cvssData.baseScore, severity: v.cvssData.baseSeverity.toLowerCase() } : null
}

// "Fixed in": the lowest versionEndExcluding above our version among the ranges that match this product.
function fixedIn(cve, vendorProduct) {
  const ends = []
  for (const conf of cve.configurations ?? [])
    for (const node of conf.nodes ?? [])
      for (const m of node.cpeMatch ?? [])
        if (m.vulnerable && m.criteria.includes(`:${vendorProduct}:`) && m.versionEndExcluding) ends.push(m.versionEndExcluding)
  return ends
}

const cmpVer = (a, b) => {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0)
  return 0
}

const sbom = JSON.parse(await readFile(sbomPath, 'utf8'))
const kevFeed = await getJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
const kev = new Map(kevFeed.vulnerabilities.map((v) => [v.cveID, v]))

const out = { checked: new Date().toISOString().slice(0, 10), sources: ['NIST NVD', 'CISA KEV', 'FIRST EPSS'], components: {} }

for (const c of sbom.components) {
  if (!c.cpe) continue
  const [, , , vendor, product, version] = c.cpe.split(':')
  const match = `cpe:2.3:${c.cpe.split(':')[2]}:${vendor}:${product}:${version}`
  process.stdout.write(`${c.name} ${c.version} ... `)
  // NVD returns at most 2000 per page; page through the rest.
  const found = []
  for (let start = 0; ; start += 2000) {
    const page = await getJson(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encodeURIComponent(match)}&resultsPerPage=2000&startIndex=${start}`,
    )
    found.push(...page.vulnerabilities)
    if (found.length >= page.totalResults || page.vulnerabilities.length === 0) break
    await sleep(6500)
  }
  const cves = found.map(({ cve }) => {
    const s = cvssOf(cve)
    const k = kev.get(cve.id)
    return {
      id: cve.id,
      cvss: s?.score ?? null,
      severity: s?.severity ?? 'none',
      published: cve.published.slice(0, 10),
      kev: k ? { added: k.dateAdded, name: k.vulnerabilityName, ransomware: k.knownRansomwareCampaignUse === 'Known' } : null,
      summary: (cve.descriptions.find((d) => d.lang === 'en')?.value ?? '').split(/(?<=\.)\s/)[0].slice(0, 160),
      fixedIn: fixedIn(cve, `${vendor}:${product}`).filter((v) => cmpVer(v, version) > 0),
    }
  })
  const sev = { critical: 0, high: 0, medium: 0, low: 0, none: 0 }
  for (const v of cves) sev[v.severity] = (sev[v.severity] ?? 0) + 1
  const exploited = cves.filter((v) => v.kev)
  // Only fixes on the same release branch as ours (e.g. 7.4.x for 7.4.2) are a valid upgrade target.
  const branch = version.split('.').slice(0, 2).join('.')
  const fixes = exploited.flatMap((v) => v.fixedIn).filter((f) => f.startsWith(`${branch}.`)).sort(cmpVer)
  const top = [...cves]
    .sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, 3)
    .map(({ fixedIn: _, ...rest }) => rest)
  out.components[c.cpe] = {
    cveCount: cves.length,
    severity: sev,
    maxCvss: Math.max(0, ...cves.map((v) => v.cvss ?? 0)),
    kev: exploited.map((v) => ({ id: v.id, added: v.kev.added, name: v.kev.name })),
    // Lowest version that closes every CVE attackers are using (null when there are none / unknown).
    fixedIn: exploited.length ? fixes.at(-1) ?? null : null,
    top,
  }
  console.log(`${cves.length} CVEs, ${exploited.length} in KEV`)
  await sleep(6500)
}

// EPSS for each component's top CVE, used by "Ask why" (chance of attack).
const ids = [...new Set(Object.values(out.components).flatMap((c) => c.top.map((t) => t.id)))]
for (let i = 0; i < ids.length; i += 50) {
  const epss = await getJson(`https://api.first.org/data/v1/epss?cve=${ids.slice(i, i + 50).join(',')}`)
  const byId = new Map(epss.data.map((d) => [d.cve, Number(d.epss)]))
  for (const c of Object.values(out.components)) for (const t of c.top) if (byId.has(t.id)) t.epss = byId.get(t.id)
}
for (const c of Object.values(out.components)) c.epssMax = Math.max(0, ...c.top.map((t) => t.epss ?? 0))

await writeFile(outPath, JSON.stringify(out, null, 1))
console.log(`\nSaved ${Object.keys(out.components).length} components to ${outPath}`)
