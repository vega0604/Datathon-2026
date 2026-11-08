import { useMemo, useRef, useState } from 'react'
import { useFitHeight } from '../lib/useFitHeight'
import { AppHeader } from '../components/insights/AppHeader'
import { Sidebar } from '../components/Sidebar'
import { QueueTable } from '../components/QueueTable'
import { WhyPanel } from '../components/WhyPanel'
import { IconDarkContext } from '../lib/iconTheme'
import { queue, totals } from '../data/queue'

// Fix first · v5 (Figma page "V5", frame "Fix first · v5 · Light · 1512").

const VIEW_FILTERS = {
  all: () => true,
  critical: (i) => i.severity === 'Critical',
  notInLinear: (i) => !i.ticket,
}

function matches(item, q) {
  if (!q) return true
  const s = q.toLowerCase()
  return item.cveId.toLowerCase().includes(s) || item.component.toLowerCase().includes(s)
}

export function FixFirstQueue({ onOpenInsights, onUpload, software, theme = 'light', onThemeChange }) {
  const dark = theme === 'dark'
  // The queue never scrolls or clips: on short windows it shrinks slightly to fit.
  const mainRef = useRef(null)
  useFitHeight(mainRef)
  const [items, setItems] = useState(() => queue.map((i) => ({ ...i, status: 'To do' })))
  const [view, setView] = useState('all')
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState(null) // null = model rank, 'desc' / 'asc' = by CVSS
  const [selectedId, setSelectedId] = useState(queue[0].cveId)
  const [panelOpen, setPanelOpen] = useState(true)
  const [nextTicket, setNextTicket] = useState(14)

  const visible = useMemo(() => {
    const rows = items.filter((i) => VIEW_FILTERS[view](i) && matches(i, query))
    if (sort) rows.sort((a, b) => (sort === 'desc' ? b.cvss - a.cvss : a.cvss - b.cvss) || a.rank - b.rank)
    return rows
  }, [items, view, query, sort])
  const selected = items.find((i) => i.cveId === selectedId)

  const select = (id) => {
    setSelectedId(id)
    setPanelOpen(true)
  }
  const updateStatus = (id, status) => setItems((prev) => prev.map((i) => (i.cveId === id ? { ...i, status } : i)))
  const pushToLinear = (id) => {
    setItems((prev) => prev.map((i) => (i.cveId === id ? { ...i, ticket: `DEMO-${nextTicket}` } : i)))
    setNextTicket((n) => n + 1)
  }
  const seeAll = () => {
    setView('all')
    setQuery('')
    setSort(null)
  }

  return (
    <IconDarkContext.Provider value={dark}>
    <div className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[560px] min-w-[1024px] flex-col bg-page font-sans`}>
      <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} />

      <div className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 wide:gap-5 wide:p-5 compact:py-3">
        <Sidebar current="fixFirst" onOpenInsights={onOpenInsights} onUpload={onUpload} software={software} />

        <main ref={mainRef} className="flex h-full min-w-0 flex-1 flex-col gap-4 overflow-hidden pt-2 [&>*]:[zoom:var(--fit,1)]">
          <div className="flex shrink-0 flex-col gap-1">
            <h1 className="text-[44px] leading-[64px] font-light text-ink short:text-[36px] short:leading-[48px]">Fix first</h1>
            <p className="text-sm leading-5 text-ink-muted wide:text-base wide:leading-6">
              {totals.open} vulnerabilities ranked by how likely attackers are to use them. {totals.warningSigns} showed
              early warning signs.
            </p>
          </div>

          <QueueTable
            items={visible}
            view={view}
            onViewChange={setView}
            query={query}
            onQueryChange={setQuery}
            sort={sort}
            onSortChange={setSort}
            selectedId={panelOpen ? selectedId : null}
            onSelect={select}
            onSeeAll={seeAll}
          />
        </main>

        {panelOpen && selected && (
          <WhyPanel
            item={selected}
            items={items}
            onClose={() => setPanelOpen(false)}
            onStatusChange={updateStatus}
            onPushToLinear={pushToLinear}
          />
        )}
      </div>
    </div>
    </IconDarkContext.Provider>
  )
}
