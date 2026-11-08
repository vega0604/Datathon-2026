import { useRef } from 'react'
import { useFitHeight } from '../../lib/useFitHeight'
import { Takeaway } from './ChartParts'
import { VendorHeatmap } from './VendorHeatmap'
import { SHADE } from './vendorShades'
import { vendors } from '../../data/insights'

function RankingRow({ vendor }) {
  return (
    <div className="flex w-full shrink-0 items-center gap-2.5 rounded-full bg-card py-1.5 pr-3.5 pl-1.5 short:py-1">
      <span className="type-body-compact flex size-9 short:size-7 shrink-0 items-center justify-center rounded-full bg-blue-soft font-semibold text-blue-ink">
        {vendor.name[0]}
      </span>
      <div className="flex min-w-0 flex-1 flex-col whitespace-nowrap">
        <span className="type-body-compact truncate font-semibold text-ink">{vendor.name}</span>
        <span className="type-label text-ink-muted">{vendor.cves}</span>
      </div>
      <span className="type-body-compact shrink-0 rounded-full bg-purple-soft px-2.5 py-1 font-semibold text-purple-ink">
        {vendor.kev}
      </span>
    </div>
  )
}

function LegendSwatch({ shade, children }) {
  const outlined = shade <= 2 // light swatches get an outline so they stay visible
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <span className={`size-3 rounded ${SHADE[shade].split(' ')[0]} ${outlined ? 'border border-context' : ''}`} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

export function VendorsPage() {
  // Never scrolls or clips: on short windows the card shrinks slightly to fit.
  const ref = useRef(null)
  useFitHeight(ref)
  return (
      <main ref={ref} className="flex h-full min-w-0 flex-1 flex-col gap-4 overflow-hidden xl:gap-5 xl:pt-2 [&>*]:[zoom:var(--fit,1)]">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Vendors</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            Which vendors’ bugs get exploited most often.
          </p>
        </div>

        <section className="flex min-h-0 w-full flex-1 overflow-y-auto rounded-[32px] bg-card p-4 shadow-float xl:p-6 short:p-4">
          <div className="flex min-h-min w-full flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
            <div className="flex shrink-0 flex-col gap-1">
              <h2 className="text-lg leading-7 text-ink xl:text-xl">{vendors.title}</h2>
              <p className="type-body text-ink-muted">{vendors.subtitle}</p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              {vendors.legend.map((l) => (
                <LegendSwatch key={l.shade} shade={l.shade}>
                  {l.label}
                </LegendSwatch>
              ))}
            </div>

            <div className="flex w-full flex-1 items-stretch gap-5">
              {/* Heatmap fills the space it gets; the layout is recomputed on resize */}
              <div className="min-h-[160px] w-[62%] shrink-0">
                <VendorHeatmap cells={vendors.cells} />
              </div>
              <div className="flex min-w-0 flex-1 flex-col justify-start gap-2.5 short:gap-2">
                <p className="type-body-compact font-semibold text-ink-muted">Highest KEV rate</p>
                {vendors.ranking.map((v) => (
                  <RankingRow key={v.name} vendor={v} />
                ))}
              </div>
            </div>

            <Takeaway>{vendors.takeaway}</Takeaway>
          </div>
        </section>
      </main>
  )
}
