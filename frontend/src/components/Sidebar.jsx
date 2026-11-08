import { Icon } from '../lib/Icon'
import { totals } from '../data/queue'

function SectionLabel({ children }) {
  return <p className="type-label w-full pt-3 pb-1 pl-2.5 text-text-secondary">{children}</p>
}

function NavItem({ icon, label, current, badge, badgeClass, onClick }) {
  return (
    <a
      href="#"
      onClick={(e) => {
        if (onClick) {
          e.preventDefault()
          onClick()
        }
      }}
      aria-current={current ? 'page' : undefined}
      className={`flex w-full items-center gap-2.5 rounded-xl px-2.5 py-[9px] ${current ? 'bg-background' : 'hover:bg-background'}`}
    >
      {current && <span className="h-5 w-[3px] shrink-0 rounded-[2px] bg-primary" />}
      <Icon name={icon} className="size-[18px]" />
      <span className={`type-body-compact min-w-px flex-1 text-text-primary ${current ? 'font-semibold' : ''}`}>{label}</span>
      {badge != null && (
        <span className={`type-label rounded-full px-2 py-0.5 text-white ${badgeClass}`}>{badge}</span>
      )}
    </a>
  )
}

const VIEWS = [
  { id: 'all', count: totals.open, label: 'All tickets' },
  { id: 'critical', count: totals.critical, label: 'Critical' },
  { id: 'edge', count: totals.edge, label: 'Edge devices' },
  { id: 'notInLinear', count: totals.notInLinear, label: 'Not in Linear' },
  { id: 'inLinear', count: totals.inLinear, label: 'In Linear' },
]

export function Sidebar({ view, onViewChange, onOpenInsights }) {
  return (
    <nav className="flex h-full w-[220px] shrink-0 flex-col gap-1 overflow-hidden rounded-3xl bg-layer p-4 shadow-sidebar">
      <SectionLabel>Before the Breach</SectionLabel>
      <NavItem icon="nav-arrow" label="Import SBOM" />
      <NavItem icon="nav-queue" label="Fix-First queue" current badge={totals.open} badgeClass="bg-inverse" />
      <NavItem icon="nav-bell" label="Alerts" badge={totals.alerts} badgeClass="bg-magenta" />
      <NavItem icon="nav-target" label="Insights" onClick={onOpenInsights} />

      <div className="h-px w-full shrink-0 bg-border-subtle" />
      <SectionLabel>Queue views</SectionLabel>
      {VIEWS.map((v) => {
        const selected = v.id === view
        return (
          <button
            key={v.id}
            type="button"
            onClick={() => onViewChange(v.id)}
            className={`flex w-full cursor-pointer items-center gap-2 rounded-[10px] px-2.5 py-[7px] text-left ${selected ? 'bg-background' : 'hover:bg-background'}`}
          >
            <span className="type-label font-mono text-text-secondary">{v.count}</span>
            <span className={`type-body-compact min-w-px flex-1 text-text-primary ${selected ? 'font-semibold' : ''}`}>
              {v.label}
            </span>
          </button>
        )
      })}

      <div className="min-h-px flex-1" />

      <div className="flex w-full flex-col gap-2 rounded-[18px] bg-inverse p-4 whitespace-nowrap text-white">
        <p className="type-label">Benchmark run</p>
        <p className="text-base leading-6 font-semibold">Top 500 ready</p>
        <p className="type-label">top500.csv · 72,670 ranked</p>
      </div>
    </nav>
  )
}
