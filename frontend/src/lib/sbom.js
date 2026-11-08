// Reads a CycloneDX SBOM in the browser and joins it with real vulnerability
// facts. Component names, versions and CPE names come from the file itself.
// CVE counts, severities and "used in attacks" come from src/data/demoRisk.json
// (NIST NVD + CISA KEV + FIRST EPSS, fetched by scripts/fetch-demo-risk.mjs) and
// only exist for components in the demo file; anything else is "not checked".
import demoRisk from '../data/demoRisk.json'

export const MAX_BYTES = 10 * 1024 * 1024
export const DEMO_URL = `${import.meta.env.BASE_URL}demo/acme_sbom.cdx.json`
export const riskChecked = demoRisk.checked

// CPE vendor ids → display names (from the CPE dictionary's vendor field).
const VENDORS = {
  fortinet: 'Fortinet',
  ivanti: 'Ivanti',
  paloaltonetworks: 'Palo Alto Networks',
  cisco: 'Cisco',
  microsoft: 'Microsoft',
  google: 'Google',
  apache: 'Apache',
  openssl: 'OpenSSL',
  wordpress: 'WordPress',
  atlassian: 'Atlassian',
  gitlab: 'GitLab',
  mozilla: 'Mozilla',
  jenkins: 'Jenkins',
  f5: 'F5',
  mongodb: 'MongoDB',
  citrix: 'Citrix',
  progress: 'Progress',
  n8n: 'n8n',
}

function vendorFrom(c) {
  if (c.cpe) {
    const v = c.cpe.split(':')[3]
    return VENDORS[v] ?? v.charAt(0).toUpperCase() + v.slice(1)
  }
  return c.supplier?.name ?? c.publisher ?? c.group ?? null
}

function fromJson(doc) {
  if (doc.bomFormat !== 'CycloneDX' || !Array.isArray(doc.components)) throw new Error('This file isn’t a CycloneDX SBOM.')
  return {
    name: doc.metadata?.component?.name ?? null,
    specVersion: doc.specVersion ?? null,
    components: doc.components.map((c) => ({ name: c.name, version: c.version ?? '', cpe: c.cpe ?? null, purl: c.purl ?? null, raw: c })),
  }
}

function fromXml(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  const bom = doc.documentElement
  if (bom.nodeName !== 'bom') throw new Error('This file isn’t a CycloneDX SBOM.')
  const text1 = (el, tag) => el.getElementsByTagName(tag)[0]?.textContent ?? null
  const list = [...bom.getElementsByTagName('components')[0]?.children ?? []]
  return {
    name: text1(bom.getElementsByTagName('metadata')[0] ?? bom, 'name'),
    specVersion: bom.namespaceURI?.split('/').pop() ?? null,
    components: list.map((el) => ({ name: text1(el, 'name'), version: text1(el, 'version') ?? '', cpe: text1(el, 'cpe'), purl: text1(el, 'purl'), raw: { supplier: { name: text1(el, 'supplier') } } })),
  }
}

/** Parses an SBOM file's text. Throws an Error with a plain message when it can't. */
export function parseSbom(text, fileName) {
  const trimmed = text.trim()
  const parsed = trimmed.startsWith('<') ? fromXml(trimmed) : fromJson(JSON.parse(trimmed))
  if (!parsed.components.length) throw new Error('This SBOM lists no components.')
  return {
    name: parsed.name ?? fileName.replace(/\.(cdx\.)?(json|xml)$/i, ''),
    fileName,
    specVersion: parsed.specVersion,
    components: parsed.components.map((c, i) => ({
      id: `${i}-${c.name}`,
      name: c.name,
      version: c.version,
      cpe: c.cpe,
      part: c.cpe ? (c.cpe.split(':')[2] === 'o' ? 'operating system' : c.cpe.split(':')[2] === 'h' ? 'hardware' : 'application') : null,
      vendor: vendorFrom({ ...c.raw, cpe: c.cpe }),
      risk: c.cpe ? (demoRisk.components[c.cpe] ?? null) : null,
    })),
  }
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low']

export function worstSeverity(risk) {
  if (!risk) return null
  return SEVERITIES.find((s) => risk.severity[s] > 0) ?? 'none'
}

/**
 * Orders components by how urgent they look from public facts: CVEs attackers are
 * using (KEV) first, then predicted chance of attack (EPSS), then worst CVSS.
 * This is a simple stand-in until the model's own ranking is served for uploads.
 */
export function rankComponents(components) {
  return [...components].sort(
    (a, b) =>
      (b.risk?.kev.length ?? -1) - (a.risk?.kev.length ?? -1) ||
      (b.risk?.epssMax ?? 0) - (a.risk?.epssMax ?? 0) ||
      (b.risk?.maxCvss ?? 0) - (a.risk?.maxCvss ?? 0),
  )
}

export function summarize(sbom) {
  const checked = sbom.components.filter((c) => c.risk)
  const sev = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const c of checked) for (const s of SEVERITIES) sev[s] += c.risk.severity[s]
  return {
    total: sbom.components.length,
    withCpe: sbom.components.filter((c) => c.cpe).length,
    checked: checked.length,
    affected: checked.filter((c) => c.risk.cveCount > 0).length,
    clear: checked.filter((c) => c.risk.cveCount === 0).length,
    cves: checked.reduce((n, c) => n + c.risk.cveCount, 0),
    sev,
    exploitedComponents: checked.filter((c) => c.risk.kev.length > 0).length,
  }
}

export function toCsv(sbom) {
  const esc = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`
  const rows = [['Component', 'Vendor', 'Version', 'CPE', 'CVEs', 'Worst severity', 'Used in attacks (KEV)']]
  for (const c of sbom.components)
    rows.push([c.name, c.vendor, c.version, c.cpe, c.risk?.cveCount ?? 'not checked', worstSeverity(c.risk) ?? 'not checked', c.risk?.kev.length ?? ''])
  return rows.map((r) => r.map(esc).join(',')).join('\n')
}

// ── Saved uploads ──────────────────────────────────────────────────────────
// Every uploaded SBOM is kept in this browser (localStorage) so it's still in
// the sidebar next time. Only what came from the file is stored; vulnerability
// facts are re-joined on load so they always come from the current risk data.
const LIBRARY_KEY = 'btb-sboms'

const withRisk = (c) => ({ ...c, risk: c.cpe ? (demoRisk.components[c.cpe] ?? null) : null })

export function loadLibrary() {
  try {
    const saved = JSON.parse(localStorage.getItem(LIBRARY_KEY) ?? '[]')
    return Array.isArray(saved) ? saved.map((s) => ({ ...s, components: s.components.map(withRisk) })) : []
  } catch {
    return []
  }
}

export function saveLibrary(library) {
  try {
    const stored = library.map((s) => ({ ...s, components: s.components.map((c) => ({ ...c, risk: undefined })) }))
    localStorage.setItem(LIBRARY_KEY, JSON.stringify(stored))
    return true
  } catch {
    return false // storage full or blocked: uploads still work for this visit
  }
}
