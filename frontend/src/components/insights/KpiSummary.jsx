import { Icon } from '../../lib/Icon'

// Same layout as the original KPI cards (icon + label, big value, pill below),
// shown as two cards side by side under the Severity chart.
function KpiCard({ kpi }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col justify-between gap-2 rounded-[28px] bg-card p-5 shadow-float short:gap-1.5 short:p-4">
      <div className="flex items-center gap-2.5">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-blue-soft">
          <Icon name={kpi.icon} className="size-[18px]" />
        </span>
        <p className="type-body text-ink-muted">{kpi.label}</p>
      </div>
      {/* On very short windows the pill moves next to the value to save height. */}
      <div className="flex flex-col items-start gap-1.5 tiny:flex-row tiny:flex-wrap tiny:items-center tiny:justify-between tiny:gap-x-1.5 tiny:gap-y-1">
        <p className="text-[clamp(26px,2.3vw,34px)] leading-[1.1] font-light whitespace-nowrap text-ink tiny:text-2xl">{kpi.value}</p>
        <span className="type-label rounded-full bg-blue-soft px-2.5 py-0.5 whitespace-nowrap text-blue-ink tiny:px-2">{kpi.pill}</span>
      </div>
      {/* Share bar from the same numbers; hidden on very short windows to save height. */}
      {kpi.share && (
        <div className="flex flex-col gap-1.5">
          <div className="h-2 w-full overflow-hidden rounded-full bg-track">
            <div
              className={`chart-grow-x h-full min-w-2 rounded-full ${kpi.share.tone}`}
              style={{ width: `${kpi.share.pct}%` }}
            />
          </div>
          <p className="type-label text-ink-muted">{kpi.share.caption}</p>
        </div>
      )}
    </div>
  )
}

/** Headline numbers for the Summary page, shown under the Severity chart. */
export function KpiSummary({ kpis }) {
  return kpis.map((k) => <KpiCard key={k.id} kpi={k} />)
}
