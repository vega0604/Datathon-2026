import { Icon } from '../lib/Icon'
import { totals } from '../data/queue'

const COLS = {
  rank: 'w-11',
  cve: 'w-[126px]',
  score: 'w-[52px]',
  cvss: 'w-24',
  status: 'w-[110px]',
}

export function SeverityTag({ cvss, severity }) {
  return (
    <span className="flex items-center gap-1 rounded-xl bg-layer-accent px-2 py-1">
      <Icon name={severity === 'Critical' ? 'status-critical' : 'status-high'} className="size-3" />
      <span className="type-label whitespace-nowrap text-text-primary">
        {cvss.toFixed(1)} {severity}
      </span>
    </span>
  )
}

function StatusCell({ item, onStatusChange }) {
  if (item.ticket) {
    return (
      <button
        type="button"
        onClick={(e) => e.stopPropagation()}
        title={`Open ${item.ticket} in Linear`}
        className="flex cursor-pointer items-center gap-1.5 rounded-lg bg-inverse py-[5px] pr-2 pl-2.5"
      >
        <Icon name="icon-check" className="size-3" />
        <span className="type-label whitespace-nowrap text-white">{item.ticket}</span>
        <Icon name="chevron-down-white" className="size-3" />
      </button>
    )
  }
  return (
    <label
      onClick={(e) => e.stopPropagation()}
      className="relative flex cursor-pointer items-center gap-1.5 rounded-lg border border-border-strong py-[5px] pr-2 pl-2.5"
    >
      <span className="type-label whitespace-nowrap text-text-primary">{item.status}</span>
      <Icon name="chevron-down" className="size-3" />
      <select
        aria-label={`Status for ${item.cveId}`}
        value={item.status}
        onChange={(e) => onStatusChange(item.cveId, e.target.value)}
        className="absolute inset-0 cursor-pointer opacity-0"
      >
        <option>To do</option>
        <option>In progress</option>
        <option>Done</option>
      </select>
    </label>
  )
}

function QueueRow({ item, selected, onSelect, onStatusChange }) {
  return (
    <div
      role="row"
      tabIndex={0}
      aria-selected={selected}
      onClick={() => onSelect(item.cveId)}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onSelect(item.cveId)}
      className={`flex w-full shrink-0 cursor-pointer items-center gap-3 rounded-[14px] py-2 pr-3 pl-2.5 outline-none focus-visible:ring-2 focus-visible:ring-primary/40 ${
        selected ? 'border-2 border-primary bg-background' : 'border-b border-border-subtle hover:bg-background/60'
      }`}
    >
      <span className={`flex h-7 ${COLS.rank} shrink-0 items-center justify-center rounded-full bg-inverse`}>
        <span className="type-body-compact font-semibold text-white">#{item.rank}</span>
      </span>
      <span className={`${COLS.cve} shrink-0 font-mono text-sm leading-5 tracking-label text-primary`}>{item.cveId}</span>
      <div className="flex min-w-px flex-1 flex-col gap-0.5 overflow-hidden whitespace-nowrap">
        <p className="type-body-compact w-full truncate font-semibold text-text-primary">{item.component}</p>
        <p className="type-label w-full truncate text-text-secondary">
          CVSS would rank this #{item.cvssRank}; we rank it #{item.rank}.
        </p>
      </div>
      <div className={`flex h-5 ${COLS.score} shrink-0 flex-col gap-1 overflow-hidden`}>
        <span className="font-mono text-sm leading-5 tracking-label text-text-primary">{item.score.toFixed(2)}</span>
        <span className="relative h-1.5 w-10 shrink-0 overflow-hidden rounded-full bg-layer-accent">
          <span className="absolute inset-y-0 left-0 rounded-full bg-primary" style={{ width: `${item.score * 100}%` }} />
        </span>
      </div>
      <div className={`flex ${COLS.cvss} shrink-0 items-center`}>
        <SeverityTag cvss={item.cvss} severity={item.severity} />
      </div>
      <div className={`flex ${COLS.status} shrink-0 items-center`}>
        <StatusCell item={item} onStatusChange={onStatusChange} />
      </div>
    </div>
  )
}

const FILTERS = [
  { id: 'all', label: `All ${totals.open}` },
  { id: 'critical', label: `Critical ${totals.critical}` },
  { id: 'notInLinear', label: `Not in Linear ${totals.notInLinear}` },
]

export function QueueTable({ items, view, onViewChange, query, onQueryChange, selectedId, onSelect, onStatusChange }) {
  return (
    <section className="flex min-h-px w-full flex-1 flex-col overflow-hidden rounded-[28px] bg-layer px-4 pt-3.5 pb-2 shadow-card">
      <div className="flex w-full shrink-0 items-center gap-2 pb-2.5">
        <label className="flex h-9 w-[170px] shrink-0 items-center gap-2 rounded-full bg-background pr-3.5 pl-3">
          <Icon name="icon-search" className="size-3.5" />
          <input
            type="search"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder="Search queue"
            className="type-body w-full min-w-0 bg-transparent text-text-primary outline-none placeholder:text-text-secondary"
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
              className={`type-body flex h-9 shrink-0 cursor-pointer items-center rounded-full px-3.5 whitespace-nowrap ${
                active ? 'bg-inverse text-white' : 'border border-border-subtle text-text-primary hover:bg-background'
              }`}
            >
              {f.label}
            </button>
          )
        })}
        <div className="h-px min-w-px flex-1" />
        <button
          type="button"
          aria-label="Filter"
          className="flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-full border border-border-subtle hover:bg-background"
        >
          <Icon name="icon-filter" className="size-4" />
        </button>
      </div>

      <div role="row" className="type-label flex w-full shrink-0 items-center gap-3 py-1.5 pr-3 pl-2.5 text-text-secondary">
        <span className={`${COLS.rank} shrink-0`}>Rank</span>
        <span className={`${COLS.cve} shrink-0`}>CVE ID</span>
        <span className="min-w-px flex-1">Component · CVSS vs our rank</span>
        <span className={`${COLS.score} shrink-0`}>Score</span>
        <span className={`${COLS.cvss} shrink-0`}>CVSS</span>
        <span className={`${COLS.status} shrink-0`}>Status</span>
      </div>

      <div role="rowgroup" className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        {items.map((item) => (
          <QueueRow
            key={item.cveId}
            item={item}
            selected={item.cveId === selectedId}
            onSelect={onSelect}
            onStatusChange={onStatusChange}
          />
        ))}
        {items.length === 0 && (
          <p className="type-body py-10 text-center text-text-secondary">No vulnerabilities match this view.</p>
        )}
      </div>
    </section>
  )
}
