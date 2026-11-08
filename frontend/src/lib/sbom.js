// SBOM helpers for Your software. The backend (POST /api/sboms) parses the file,
// matches it to vulnerabilities and stores it; components and their `risk` come
// from GET /api/sboms/{id}/components. The file is also read here, only to show the
// upload preview (component count, CPE names) while the server works.

export const MAX_BYTES = 10 * 1024 * 1024
export const DEMO_URL = `${import.meta.env.BASE_URL}demo/acme_sbom.cdx.json`
export const DEMO_FILE = 'acme_sbom.cdx.json'

function fromJson(doc) {
  if (doc.bomFormat !== 'CycloneDX' || !Array.isArray(doc.components)) throw new Error('This file isn’t a CycloneDX SBOM.')
  return {
    name: doc.metadata?.component?.name ?? null,
    specVersion: doc.specVersion ?? null,
    components: doc.components.map((c) => ({ name: c.name, version: c.version ?? '', cpe: c.cpe ?? null })),
  }
}

function fromXml(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  const bom = doc.documentElement
  if (bom.nodeName !== 'bom') throw new Error('This file isn’t a CycloneDX SBOM.')
  const text1 = (el, tag) => el.getElementsByTagName(tag)[0]?.textContent ?? null
  const list = [...(bom.getElementsByTagName('components')[0]?.children ?? [])]
  return {
    name: text1(bom.getElementsByTagName('metadata')[0] ?? bom, 'name'),
    specVersion: bom.namespaceURI?.split('/').pop() ?? null,
    components: list.map((el) => ({ name: text1(el, 'name'), version: text1(el, 'version') ?? '', cpe: text1(el, 'cpe') })),
  }
}

/** The upload preview: name, spec version and components as listed in the file.
 *  Throws an Error with a plain message when the file can't be read. */
export function previewSbom(text, fileName) {
  const trimmed = text.trim()
  const parsed = trimmed.startsWith('<') ? fromXml(trimmed) : fromJson(JSON.parse(trimmed))
  if (!parsed.components.length) throw new Error('This SBOM doesn’t list any components.')
  return {
    name: parsed.name ?? fileName.replace(/\.(cdx\.)?(json|xml)$/i, ''),
    fileName,
    specVersion: parsed.specVersion,
    components: parsed.components.map((c, i) => ({ id: `${i}-${c.name}`, ...c })),
  }
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low']

export function worstSeverity(risk) {
  if (!risk) return null
  return SEVERITIES.find((s) => risk.severity[s] > 0) ?? 'none'
}

/** Components in the backend's order: by each one's highest-ranked CVE in the Fix
 *  first queue (API `rank`). */
export function rankComponents(components) {
  return [...components].sort((a, b) => a.rank - b.rank)
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
    // Distinct CVEs (the Fix first queue's length): one CVE can affect several components,
    // so the per-component counts add up to more.
    cves: sbom.cveTotal ?? checked.reduce((n, c) => n + c.risk.cveCount, 0),
    sev,
    exploitedComponents: checked.filter((c) => c.risk.kev.length > 0).length,
  }
}

export function toCsv(sbom) {
  const esc = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`
  const rows = [['Component', 'Vendor', 'Version', 'CPE', 'CVEs', 'Worst severity', 'Used in attacks (KEV)', 'Fixed in']]
  for (const c of sbom.components)
    rows.push([c.name, c.vendor, c.version, c.cpe, c.risk?.cveCount ?? 'not checked', worstSeverity(c.risk) ?? 'not checked', c.risk?.kev.length ?? '', c.risk?.fixedIn ?? ''])
  return rows.map((r) => r.map(esc).join(',')).join('\n')
}
