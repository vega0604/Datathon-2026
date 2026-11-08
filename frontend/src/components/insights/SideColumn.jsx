import { Icon } from '../../lib/Icon'

function KpiCard({ kpi }) {
  return (
    <div className="flex w-full shrink-0 flex-col gap-2 rounded-3xl bg-card px-5 py-4 shadow-float xl:gap-3 xl:px-6 xl:py-5">
      <div className="flex items-center gap-3">
        <span
          className={`flex size-9 shrink-0 items-center justify-center rounded-xl xl:size-10 bg-blue-soft`}
        >
          <Icon name={kpi.icon} className="size-5" />
        </span>
        <p className="type-body truncate text-ink-muted">{kpi.label}</p>
      </div>
      <div className="flex flex-col items-start gap-2">
        <p className="text-[clamp(30px,2.9vw,44px)] leading-[1.1] font-light whitespace-nowrap text-ink">{kpi.value}</p>
        <span className="type-label rounded-full bg-blue-soft px-2.5 py-1 whitespace-nowrap text-blue-ink">{kpi.pill}</span>
      </div>
    </div>
  )
}

export function SideColumn({ kpis }) {
  return (
    <div className="flex h-full w-[240px] shrink-0 flex-col gap-4 overflow-y-auto xl:w-[280px] xl:gap-5 2xl:w-[300px] short:gap-3">
      {kpis.map((k) => (
        <KpiCard key={k.id} kpi={k} />
      ))}
    </div>
  )
}
