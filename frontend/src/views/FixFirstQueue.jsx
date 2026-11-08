import { useEffect, useMemo, useRef, useState } from 'react'
import { useFitHeight } from '../lib/useFitHeight'
import { AppHeader } from '../components/insights/AppHeader'
import { Sidebar } from '../components/Sidebar'
import { QueueTable } from '../components/QueueTable'
import { WhyPanel } from '../components/WhyPanel'
import { IconDarkContext } from '../lib/iconTheme'
import { pushToLinear, setStatus, useQueueView } from '../lib/api'

// Fix first · v5 (Figma page "V5", frame "Fix first · v5 · Light · 1512").
// The queue is the selected SBOM's (GET /api/sboms/{id}/queue, cached in App).

const VIEW_FILTERS = {
  all: () => true,
  critical: (i) => i.severity === 'Critical',
  notInLinear: (i) => !i.ticket,
}
// The same views and sorts as the queue API's `view` / `sort` parameters.
const VIEW_PARAM = { all: 'all', critical: 'critical', notInLinear: 'not_in_linear' }
const SORT_PARAM = { desc: 'cvss_desc', asc: 'cvss_asc' }

// Rows rendered at once. Real queues hold hundreds to thousands of CVEs; the list
// grows by this much on "Show more", so the DOM (and the detail panel, which lays
// out every rendered row's text to keep its size steady) stays small.
const PAGE = 50

function matches(item, q) {
  if (!q) return true
  const s = q.toLowerCase()
  return item.cveId.toLowerCase().includes(s) || item.component.toLowerCase().includes(s)
}

export function FixFirstQueue({ onHome, onOpenInsights, onUpload, software, totals, theme = 'light', onThemeChange, sbomId, sbomName, queue }) {
  const dark = theme === 'dark'
  // On short windows the page shrinks slightly to fit, except the queue rows, which scroll.
  const mainRef = useRef(null)
  useFitHeight(mainRef)
  const items = useMemo(() => queue.data?.items ?? [], [queue.data])
  const [view, setView] = useState('all')
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState(null) // null = model rank, 'desc' / 'asc' = by CVSS
  const [shown, setShown] = useState(PAGE)
  const [chosenId, setChosenId] = useState(null)
  const [panelOpen, setPanelOpen] = useState(true)
  const [actionError, setActionError] = useState(null)

  // Search waits for a pause in typing before asking the server.
  const [typed, setTyped] = useState('')
  useEffect(() => {
    const t = setTimeout(() => setTyped(query.trim()), 250)
    return () => clearTimeout(t)
  }, [query])

  // The page holds the top 1,000 rows. When the queue is longer, a search, filter or
  // sort runs on the server over every row; until it answers, the loaded rows show.
  const complete = !queue.data || queue.data.total <= items.length
  const serverParams =
    !complete && (typed || view !== 'all' || sort)
      ? { ...(typed && { q: typed }), view: VIEW_PARAM[view], sort: SORT_PARAM[sort] ?? 'rank' }
      : null
  const server = useQueueView(sbomId, serverParams)
  const serverRows = serverParams ? server.data?.items : null

  const filtered = useMemo(() => {
    if (serverRows) return serverRows
    const rows = items.filter((i) => VIEW_FILTERS[view](i) && matches(i, query))
    if (sort) rows.sort((a, b) => (sort === 'desc' ? b.cvss - a.cvss : a.cvss - b.cvss) || a.rank - b.rank)
    return rows
  }, [serverRows, items, view, query, sort])
  const visible = filtered.slice(0, shown)
  const selectedId = chosenId ?? items[0]?.cveId
  const selected = items.find((i) => i.cveId === selectedId) ?? serverRows?.find((i) => i.cveId === selectedId)

  // Rows that exist but aren't in the browser (only the top 1,000 of a view are sent).
  let note = null
  if (serverParams && server.loading) note = `Searching all ${queue.data.total.toLocaleString('en-US')}…`
  else if (serverParams && server.error) note = `Showing loaded rows only: ${server.error.message}`
  else if (serverParams && server.data && server.data.matched > server.data.items.length)
    note = `Showing the top 1,000 of ${server.data.matched.toLocaleString('en-US')} matches.`
  else if (!serverParams && !complete)
    note = `Showing the top 1,000; ${(queue.data.total - items.length).toLocaleString('en-US')} lower-ranked load when you search, filter or sort.`

  const select = (id) => {
    setChosenId(id)
    setPanelOpen(true)
    setActionError(null)
  }
  const updateStatus = async (id, status) => {
    setActionError(null)
    const previous = (items.find((i) => i.cveId === id) ?? serverRows?.find((i) => i.cveId === id))?.status
    try {
      await setStatus(sbomId, id, status, previous)
    } catch (e) {
      setActionError(e.message)
    }
  }
  const sendToLinear = async (id) => {
    setActionError(null)
    try {
      await pushToLinear(sbomId, id)
    } catch (e) {
      setActionError(e.message) // e.g. "Linear isn't set up yet." The button stays clickable.
    }
  }
  const seeAll = () => {
    setView('all')
    setQuery('')
    setSort(null)
    setShown(PAGE)
  }

  let body
  if (!sbomId && !software.loading) body = <Notice title="Nothing to rank yet" action="Upload an SBOM" onAction={onUpload}>Upload a CycloneDX SBOM and we’ll rank its vulnerabilities by how likely attackers are to use them.</Notice>
  else if (queue.error && !queue.data) body = <Notice title="We couldn’t load the queue" action="Try again" onAction={queue.reload}>{queue.error.message}</Notice>
  else if (!queue.data) body = <Notice title="Ranking your software…">Matching components to known vulnerabilities and scoring them. This takes a few seconds.</Notice>
  else
    body = (
      <QueueTable
        items={visible}
        totals={totals}
        view={view}
        onViewChange={(v) => (setView(v), setShown(PAGE))}
        query={query}
        onQueryChange={(q) => (setQuery(q), setShown(PAGE))}
        sort={sort}
        onSortChange={setSort}
        selectedId={panelOpen ? selectedId : null}
        onSelect={select}
        onSeeAll={seeAll}
        more={filtered.length - visible.length}
        onShowMore={() => setShown((n) => n + PAGE)}
        note={note}
      />
    )

  // The panel keeps its size steady across the rows it can show: the rendered ones,
  // plus the selected row if it was found by search further down.
  const panelItems = selected && !visible.includes(selected) ? [...visible, selected] : visible

  return (
    <IconDarkContext.Provider value={dark}>
    <div className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[560px] min-w-[1024px] flex-col bg-page font-sans`}>
      <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} onHome={onHome} />

      <div className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 wide:gap-5 wide:p-5 compact:py-3">
        <Sidebar current="fixFirst" onOpenInsights={onOpenInsights} onUpload={onUpload} software={software} totals={totals} />

        <main ref={mainRef} className="flex h-full min-w-0 flex-1 flex-col gap-4 overflow-hidden pt-2 [&>*]:[zoom:var(--fit,1)]">
          <div className="flex shrink-0 flex-col gap-1">
            <h1 className="flex items-center gap-3 text-[44px] leading-[64px] font-light text-ink short:text-[36px] short:leading-[48px]">
              Fix first
              {queue.data?.ranking === 'epss_placeholder' && (
                <span className="type-label rounded-full bg-subtle px-2.5 py-1 font-normal text-ink-muted" title="The model's scores aren't built on the server yet: ranked by KEV, EPSS and CVSS.">
                  Sample ranking
                </span>
              )}
            </h1>
            <p className="text-sm leading-5 text-ink-muted wide:text-base wide:leading-6">
              {totals
                ? `${totals.open.toLocaleString('en-US')} vulnerabilities${sbomName ? ` in ${sbomName}` : ''} ranked by how likely attackers are to use them. ${totals.warningSigns.toLocaleString('en-US')} showed early warning signs.`
                : 'Vulnerabilities ranked by how likely attackers are to use them.'}
            </p>
          </div>
          {body}
        </main>

        {queue.data && panelOpen && selected && (
          <WhyPanel
            item={selected}
            items={panelItems}
            error={actionError}
            onClose={() => setPanelOpen(false)}
            onStatusChange={updateStatus}
            onPushToLinear={sendToLinear}
          />
        )}
      </div>
    </div>
    </IconDarkContext.Provider>
  )
}

function Notice({ title, children, action, onAction }) {
  return (
    <section className="flex min-h-px w-full flex-1 flex-col items-center justify-center gap-3 rounded-[28px] bg-card p-10 text-center shadow-float" role="status">
      <h2 className="text-xl leading-7 text-ink">{title}</h2>
      <p className="type-body max-w-[460px] text-ink-muted">{children}</p>
      {action && (
        <button type="button" onClick={onAction} className="mt-2 cursor-pointer rounded-full bg-blue px-5 py-2.5 text-sm font-semibold text-white hover:bg-primary-strong">
          {action}
        </button>
      )}
    </section>
  )
}
