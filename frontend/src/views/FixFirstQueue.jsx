import { useMemo, useState } from 'react'
import { Header } from '../components/Header'
import { Sidebar } from '../components/Sidebar'
import { Highlights } from '../components/Highlights'
import { QueueTable } from '../components/QueueTable'
import { WhyPanel } from '../components/WhyPanel'
import { Icon } from '../lib/Icon'
import { company, queue, totals } from '../data/queue'

const VIEW_FILTERS = {
  all: () => true,
  critical: (i) => i.severity === 'Critical',
  edge: (i) => i.edge,
  notInLinear: (i) => !i.ticket,
  inLinear: (i) => !!i.ticket,
}

function matches(item, q) {
  if (!q) return true
  const s = q.toLowerCase()
  return item.cveId.toLowerCase().includes(s) || item.component.toLowerCase().includes(s)
}

export function FixFirstQueue({ onOpenInsights }) {
  const [items, setItems] = useState(() => queue.map((i) => ({ ...i, status: 'To do' })))
  const [view, setView] = useState('all')
  const [query, setQuery] = useState('')
  const [globalSearch, setGlobalSearch] = useState('')
  const [selectedId, setSelectedId] = useState(queue[0].cveId)
  const [panelOpen, setPanelOpen] = useState(true)
  const [nextTicket, setNextTicket] = useState(14)

  const visible = useMemo(
    () => items.filter((i) => VIEW_FILTERS[view](i) && matches(i, query) && matches(i, globalSearch)),
    [items, view, query, globalSearch],
  )
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

  return (
    <div className="flex h-screen min-w-[1280px] flex-col bg-background">
      <Header search={globalSearch} onSearch={setGlobalSearch} />

      <div className="flex min-h-px w-full flex-1 items-start gap-5 overflow-hidden px-4 pb-4">
        <Sidebar view={view} onViewChange={setView} onOpenInsights={onOpenInsights} />

        <main className="flex h-full min-w-px flex-1 flex-col gap-4 overflow-hidden">
          <div className="flex shrink-0 flex-col gap-1">
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1.5 rounded-full bg-layer py-1 pr-3 pl-2.5">
                <Icon name="icon-upload" className="size-3.5" />
                <span className="type-label whitespace-nowrap text-text-secondary">
                  {company.name} SBOM · {company.components} components
                </span>
              </span>
              <span className="flex items-center gap-1.5 rounded-full border border-dashed border-border-strong py-1 pr-3 pl-2.5">
                <Icon name="icon-idea" className="size-3.5" />
                <span className="type-label whitespace-nowrap text-text-secondary">Sample values until the model ships</span>
              </span>
            </div>
            <h1 className="flex items-baseline gap-3.5 text-[52px] leading-[64px] font-light whitespace-nowrap">
              <span className="text-text-primary">Fix-First queue</span>
              <span className="text-text-secondary">{totals.open} open</span>
            </h1>
          </div>

          <Highlights topItem={items[0]} onOpenTop={() => select(items[0].cveId)} />

          <QueueTable
            items={visible}
            view={view}
            onViewChange={setView}
            query={query}
            onQueryChange={setQuery}
            selectedId={panelOpen ? selectedId : null}
            onSelect={select}
            onStatusChange={updateStatus}
          />
        </main>

        {panelOpen && selected && (
          <WhyPanel
            item={selected}
            onClose={() => setPanelOpen(false)}
            onStatusChange={updateStatus}
            onPushToLinear={pushToLinear}
          />
        )}
      </div>
    </div>
  )
}
