// Every call the app makes to the FastAPI backend, plus the mapping from the API's
// snake_case JSON to the camelCase shapes the components already use.
import { drop, load, mutate, mutateMatching, useApi } from './useApi'

const BASE = (import.meta.env.VITE_API_URL ?? '').replace(/\/$/, '')

/** An error from the API. `message` is the backend's plain sentence (its `detail`). */
export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

// Sent with every request. When the backend is reached through an ngrok tunnel, ngrok
// answers browser requests with its HTML warning page unless this header is present
// (any value), and the app would get that page instead of JSON.
const BASE_HEADERS = { 'ngrok-skip-browser-warning': 'true' }

/** Base fetch: JSON in and out, errors as ApiError with a readable message. */
export async function apiFetch(path, { method = 'GET', json, body, signal } = {}) {
  let res
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      signal,
      body: json === undefined ? body : JSON.stringify(json),
      // No Content-Type for FormData uploads: the browser sets it with the boundary.
      headers: json === undefined ? BASE_HEADERS : { ...BASE_HEADERS, 'Content-Type': 'application/json' },
    })
  } catch {
    throw new ApiError(0, 'We couldn’t reach the server. Is the backend running?')
  }
  if (res.status === 204) return null
  const data = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(res.status, data?.detail ?? `The server answered ${res.status}.`)
  return data
}

// ── Cache keys and TTLs ──────────────────────────────────────────────────────
// Insights, benchmark facts and the user only change when the model is rebuilt, so
// they stay cached for the whole session. SBOM data is per upload and changes only
// through this app, which updates the cache itself.
const SESSION = Infinity
const keys = {
  me: '/api/me',
  benchmark: '/api/benchmark',
  summary: '/api/insights/summary',
  catchRate: '/api/insights/catch-rate',
  vendors: '/api/insights/vendors',
  sboms: '/api/sboms',
  components: (id) => `/api/sboms/${id}/components`,
  queue: (id) => `/api/sboms/${id}/queue`,
}

// ── Mapping: API -> component shapes ─────────────────────────────────────────
const SEVERITY = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None' }
const SIGNAL = { exploit_code: 'code', vendor_attacked: 'vendor', score_jump: 'trend' }
const STATUS = { to_do: 'To do', in_progress: 'In progress', done: 'Done' }
export const STATUS_VALUE = Object.fromEntries(Object.entries(STATUS).map(([k, v]) => [v, k]))
const REASON_ICON = { exploit: 'fixfirst/reason-code', exposure: 'fixfirst/reason-shield', vendor: 'fixfirst/reason-vendor' }

function weakness(row) {
  if (!row.cwe_id) return null
  return row.cwe_name ? `${row.cwe_name} (${row.cwe_id})` : row.cwe_id
}

export function toQueueItem(row) {
  return {
    rank: row.rank,
    cveId: row.cve_id,
    component: row.component,
    cvssRank: row.cvss_rank,
    score: row.score ?? 0,
    cvss: row.cvss_score ?? 0,
    severity: SEVERITY[row.severity] ?? 'None',
    signal: SIGNAL[row.signal] ?? null,
    status: STATUS[row.status] ?? 'To do',
    ticket: row.ticket?.id ?? null,
    ticketUrl: row.ticket?.url ?? null,
    vendorInitials: row.vendor_initials,
    subtitle: row.subtitle,
    explanation: row.explanation,
    explanationSource: row.explanation_source,
    reasons: (row.reasons ?? []).map((r) => ({ icon: REASON_ICON[r.kind] ?? REASON_ICON.exposure, label: r.label, value: r.value })),
    reasonsAreSample: !!row.reasons_are_sample,
    kev: row.on_kev
      ? { added: row.kev_date_added, ransomware: !!row.known_ransomware, weakness: weakness(row), name: row.kev_name }
      : null,
    facts: { epss: row.epss, published: row.published, weakness: weakness(row), exploitCode: !!row.exploit_code },
    asOf: row.as_of,
    stale: !!row.stale,
  }
}

export function toQueue(body) {
  return {
    sbomId: body.sbom_id,
    ranking: body.ranking,
    total: body.total,
    matched: body.matched ?? body.total,
    totals: {
      open: body.counts.open,
      critical: body.counts.critical,
      notInLinear: body.counts.not_in_linear,
      warningSigns: body.counts.warning_signs,
    },
    items: body.items.map(toQueueItem),
  }
}

function toRisk(r) {
  if (!r) return null
  return {
    cveCount: r.cve_count,
    severity: r.severity,
    maxCvss: r.max_cvss,
    epssMax: r.epss_max ?? 0,
    fixedIn: r.fixed_in,
    kev: r.kev.map((k) => ({ id: k.cve_id, added: k.date_added, name: k.name })),
    top: r.top.map((t) => ({
      id: t.cve_id,
      cvss: t.cvss,
      severity: t.severity,
      published: t.published,
      summary: t.summary,
      epss: t.epss,
      kev: t.kev ? { added: t.kev.date_added, name: t.kev.name, ransomware: t.kev.ransomware } : null,
    })),
  }
}

export function toSbom(body) {
  return {
    id: body.sbom_id,
    name: body.name,
    fileName: body.filename,
    uploadedAt: body.uploaded_at,
    specVersion: body.spec_version,
    riskChecked: body.risk_checked,
    cveTotal: body.cve_total, // distinct CVEs (one CVE can affect several components)
    components: body.components.map((c) => ({
      id: String(c.component_id),
      name: c.name,
      version: c.version ?? '',
      vendor: c.vendor,
      cpe: c.cpe,
      purl: c.purl,
      part: c.part,
      rank: c.rank,
      matchMethods: c.match_methods ?? [],
      risk: toRisk(c.risk),
    })),
  }
}

const toSummaryRow = (s) => ({
  id: s.sbom_id,
  name: s.name,
  fileName: s.filename,
  uploadedAt: s.uploaded_at,
  componentCount: s.component_count,
})

// ── Hooks: one per endpoint ──────────────────────────────────────────────────
export const useMe = () => useApi(keys.me, () => apiFetch(keys.me), { ttl: SESSION })
export const useBenchmark = () => useApi(keys.benchmark, () => apiFetch(keys.benchmark), { ttl: SESSION })
export const useSummary = () => useApi(keys.summary, () => apiFetch(keys.summary), { ttl: SESSION })
export const useCatchRate = () => useApi(keys.catchRate, () => apiFetch(keys.catchRate), { ttl: SESSION })
export const useVendors = () => useApi(keys.vendors, () => apiFetch(keys.vendors), { ttl: SESSION })
export const useSboms = () =>
  useApi(keys.sboms, async () => (await apiFetch(keys.sboms)).map(toSummaryRow), { ttl: 5 * 60_000 })
export const useSbom = (id) =>
  useApi(id ? keys.components(id) : null, async () => toSbom(await apiFetch(keys.components(id))), { ttl: 10 * 60_000 })
// The whole queue (up to the API's 1000-row page) in one request: the page filters,
// searches and sorts in the browser, and the sidebar badges read its counts.
export const useQueue = (id) =>
  useApi(id ? keys.queue(id) : null, async () => toQueue(await apiFetch(`${keys.queue(id)}?limit=1000`)), {
    ttl: 10 * 60_000,
  })

/** The queue searched, filtered and sorted on the server, for queues longer than the
 *  1,000 rows the page holds. `params` null skips it. Cached per query, so going back
 *  to an earlier search is instant. */
export function useQueueView(id, params) {
  const search = params && id ? new URLSearchParams({ limit: '1000', ...params }).toString() : null
  const key = search ? `${keys.queue(id)}?${search}` : null
  return useApi(key, async () => toQueue(await apiFetch(key)), { ttl: 2 * 60_000 })
}

/** Starts the requests the first screen needs, in parallel, before it renders. */
export function prefetchShell() {
  return Promise.all([
    load(keys.me, () => apiFetch(keys.me)),
    load(keys.sboms, async () => (await apiFetch(keys.sboms)).map(toSummaryRow)),
  ])
}

// ── Writes: they update the cache in place instead of refetching ─────────────

/** Uploads a CycloneDX file; caches the SBOM and puts it first in the list.
 *  Cancelling (`signal`) undoes it: aborting the request wouldn't stop the server from
 *  storing the file, so the request finishes and the stored SBOM is deleted again. */
export async function uploadSbom(file, signal) {
  const form = new FormData()
  form.append('file', file, file.name)
  const body = await apiFetch('/api/sboms', { method: 'POST', body: form })
  if (signal?.aborted) {
    await apiFetch(`/api/sboms/${body.sbom_id}`, { method: 'DELETE' }).catch(() => {})
    throw new DOMException('Upload cancelled', 'AbortError')
  }
  const sbom = toSbom(body)
  mutate(keys.components(sbom.id), sbom)
  mutate(keys.sboms, (list = []) => [
    { id: sbom.id, name: sbom.name, fileName: sbom.fileName, uploadedAt: sbom.uploadedAt, componentCount: sbom.components.length },
    // The backend replaces an earlier upload with the same filename.
    ...list.filter((s) => s.fileName !== sbom.fileName),
  ])
  return sbom
}

export async function deleteSbom(id) {
  await apiFetch(`/api/sboms/${id}`, { method: 'DELETE' })
  mutate(keys.sboms, (list = []) => list.filter((s) => s.id !== id))
  drop(`/api/sboms/${id}/`) // its components and every cached queue view
}

// A row can sit in the main queue and in any number of searched views: update all.
function updateRow(sbomId, cveId, patch) {
  mutateMatching(keys.queue(sbomId), (q) => {
    let notInLinear = q.totals.notInLinear
    const items = q.items.map((i) => {
      if (i.cveId !== cveId) return i
      const next = { ...i, ...patch }
      if (!i.ticket && next.ticket) notInLinear -= 1
      return next
    })
    return { ...q, items, totals: { ...q.totals, notInLinear } }
  })
}

/** Optimistic status change; rolls back and rethrows if the API refuses it. */
export async function setStatus(sbomId, cveId, status, previous) {
  updateRow(sbomId, cveId, { status })
  try {
    await apiFetch(`/api/sboms/${sbomId}/queue/${cveId}`, { method: 'PATCH', json: { status: STATUS_VALUE[status] } })
  } catch (e) {
    updateRow(sbomId, cveId, { status: previous })
    throw e
  }
}

export async function pushToLinear(sbomId, cveId) {
  const { ticket } = await apiFetch(`/api/sboms/${sbomId}/queue/${cveId}/linear`, { method: 'POST' })
  updateRow(sbomId, cveId, { ticket: ticket.id, ticketUrl: ticket.url })
  return ticket
}
