import { Icon } from '../lib/Icon'
import { signals, totals } from '../data/queue'

const COLS = {
  rank: 'w-12',
  // Below the roomy breakpoint the component name moves under the CVE ID, so this
  // column flexes instead of the separate "What it is" column.
  cve: 'min-w-0 flex-1 roomy:w-[132px] roomy:flex-none',
  what: 'hidden min-w-px flex-1 roomy:block',
  risk: 'w-11',
  cvss: 'w-[104px]',
  signal: 'w-[172px]',
}

// Carbon status tag: colour is always paired with a shape and a text label.
export function SeverityTag({ cvss, severity }) {
  return (
    <span className="flex items-center gap-1 rounded-xl bg-subtle px-2 py-1">
      <Icon name={severity === 'Critical' ? 'fixfirst/status-critical' : 'fixfirst/status-high'} className="size-3" />
      <span className="type-label whitespace-nowrap text-ink">
        {cvss.toFixed(1)} {severity}
      </span>
    </span>
  )
}

function WarningSign({ signal }) {
  const s = signals[signal]
  if (!s) return <span className="text-[13px] whitespace-nowrap text-ink-muted">No signs yet</span>
  return (
    <span className={`flex items-center gap-1.5 rounded-full border-[1.5px] bg-card py-1 pr-3 pl-2 ${s.border}`}>
      <Icon name={s.icon} className="size-3.5" />
      <span className="type-label whitespace-nowrap text-ink">{s.label}</span>
    </span>
  )
}

function QueueRow({ item, selected, onSelect }) {
  return (
    <div
      role="row"
      tabIndex={0}
      aria-selected={selected}
      onClick={() => onSelect(item.cveId)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSelect(item.cveId)
        }
      }}
      className={`flex max-h-[61px] min-h-0 w-full flex-1 basis-0 cursor-pointer items-center gap-2 wide:gap-3 rounded-[14px] py-[7px] pr-3 pl-2.5 short:py-1 outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue ${
        // Inset ring instead of a border so selecting a row doesn't squeeze its columns.
        selected ? 'bg-page ring-2 ring-blue ring-inset' : 'border-b border-line hover:bg-page/70'
      }`}
    >
      <span role="gridcell" className={`flex h-full max-h-[46px] min-h-6 ${COLS.rank} shrink-0 items-center justify-center rounded-[10px] bg-blue-soft`}>
        <span className="text-[22px] leading-[26px] tracking-body text-blue-ink">{item.rank}</span>
      </span>
      <span role="gridcell" className={`${COLS.cve} flex flex-col`}>
        <span className="font-mono text-sm leading-5 tracking-label text-blue-ink">{item.cveId}</span>
        <span className="type-label truncate font-semibold text-ink roomy:hidden">{item.component}</span>
      </span>
      <span role="gridcell" className={`${COLS.what} type-body-compact truncate font-semibold text-ink`}>
        {item.component}
      </span>
      <span role="gridcell" className={`flex h-5 ${COLS.risk} shrink-0 flex-col gap-1 overflow-hidden`}>
        <span className="font-mono text-sm leading-5 tracking-label text-ink">{item.score.toFixed(2)}</span>
        <span className="relative h-1.5 w-10 shrink-0 overflow-hidden rounded-full bg-subtle">
          <span className="absolute inset-y-0 left-0 rounded-full bg-blue" style={{ width: `${item.score * 100}%` }} />
        </span>
      </span>
      <span role="gridcell" className={`flex ${COLS.cvss} shrink-0 items-center`}>
        <SeverityTag cvss={item.cvss} severity={item.severity} />
      </span>
      <span role="gridcell" className={`flex h-7 ${COLS.signal} shrink-0 items-center overflow-hidden`}>
        <WarningSign signal={item.signal} />
      </span>
    </div>
  )
}

function SortButton({ sort, onSortChange }) {
  const next = sort === 'desc' ? 'asc' : sort === 'asc' ? null : 'desc'
  const label = { desc: 'highest first', asc: 'lowest first' }
  return (
    <button
      type="button"
      onClick={() => onSortChange(next)}
      aria-label={`Sort by CVSS${sort ? ` (now ${label[sort]})` : ''}`}
      title="Sort by CVSS"
      className="flex h-5 w-[22px] shrink-0 cursor-pointer items-center justify-center gap-px rounded-[5px] hover:bg-subtle focus-visible:outline-2 focus-visible:outline-blue"
    >
      <Icon name="fixfirst/sort-up" className={`h-3.5 w-[7px] ${sort === 'desc' ? 'opacity-30' : ''}`} />
      <Icon name="fixfirst/sort-down" className={`h-3.5 w-[7px] ${sort === 'asc' ? 'opacity-30' : ''}`} />
    </button>
  )
}

const FILTERS = [
  { id: 'all', label: 'All', count: totals.open },
  { id: 'critical', label: 'Critical', count: totals.critical },
  { id: 'notInLinear', label: 'Not sent', count: totals.notInLinear },
]

export function QueueTable({ items, view, onViewChange, query, onQueryChange, sort, onSortChange, selectedId, onSelect, onSeeAll }) {
  return (
    <section className="flex min-h-px w-full flex-1 flex-col overflow-hidden rounded-[28px] bg-card px-4 pt-3.5 pb-4 shadow-float short:pt-3 short:pb-3">
      <div className="flex w-full shrink-0 items-center gap-2 pb-2.5">
        <label className="flex h-9 w-[170px] shrink-0 items-center gap-2 rounded-full bg-page pr-3.5 pl-3 focus-within:ring-2 focus-within:ring-blue/40">
          <Icon name="fixfirst/icon-search" className="size-3.5" />
          <input
            type="search"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder="Search queue"
            aria-label="Search queue"
            className="type-body w-full min-w-0 bg-transparent text-ink outline-none placeholder:text-ink-muted"
          />
        </label>
        {FILTERS.map((f) => {
          const active = f.id === view
          return (
            <button
              key={f.id}
              type="button"
              aria-pressed={active}
              onClick={() => onViewChange(f.id)}
              className={`type-body flex h-9 shrink-0 cursor-pointer items-center rounded-full px-3.5 whitespace-pre ${
                active ? 'bg-blue-soft text-blue-ink' : 'border border-line text-ink hover:bg-page'
              }`}
            >
              {`${f.label}  ${f.count}`}
            </button>
          )
        })}
      </div>

      <div role="grid" aria-label="Fix first queue" className="flex min-h-0 w-full flex-1 flex-col">
        <div role="row" className="type-label flex w-full shrink-0 items-center gap-2 py-1.5 pr-3 pl-2.5 text-ink-muted wide:gap-3">
          <span role="columnheader" className={`${COLS.rank} shrink-0`}>Rank</span>
          <span role="columnheader" className={COLS.cve}>
            CVE ID<span className="roomy:hidden"> · what it is</span>
          </span>
          <span role="columnheader" className={COLS.what}>What it is</span>
          <span role="columnheader" className={`${COLS.risk} shrink-0`}>Risk</span>
          <span
            role="columnheader"
            aria-sort={sort === 'desc' ? 'descending' : sort === 'asc' ? 'ascending' : 'none'}
            className={`flex ${COLS.cvss} shrink-0 items-center gap-1`}
          >
            CVSS
            <SortButton sort={sort} onSortChange={onSortChange} />
          </span>
          <span role="columnheader" className={`${COLS.signal} shrink-0`}>Warning sign</span>
        </div>

        <div role="rowgroup" className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          {items.map((item) => (
            <QueueRow key={item.cveId} item={item} selected={item.cveId === selectedId} onSelect={onSelect} />
          ))}
          {items.length === 0 && (
            <p className="type-body py-10 text-center text-ink-muted">No vulnerabilities match this view.</p>
          )}
        </div>
      </div>

      <div className="shrink-0 pt-3 pl-2.5 short:pt-2">
        <button
          type="button"
          onClick={onSeeAll}
          className="cursor-pointer text-sm font-semibold whitespace-pre text-blue-ink hover:underline"
        >
          {`See all ${totals.open}  ›`}
        </button>
      </div>
    </section>
  )
}
