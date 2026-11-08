import { useRef } from 'react'
import { iconUrl } from '../../lib/Icon'
import { useThemedIcon } from '../../lib/iconTheme'
import { useFitHeight } from '../../lib/useFitHeight'
import { useBenchmark, useCatchRate } from '../../lib/api'
import { catchRateText } from '../../data/ui'
import { InsightsState } from './InsightsState'
import { EmbeddingCard } from './EmbeddingCard'
import { Takeaway } from './ChartParts'
import { CatchRateChart } from './CatchRateChart'
import { CardHead, ChartPopup } from './ExpandableCard'
import { useExpand } from '../../lib/useExpand'

function LegendPill({ file, height, children }) {
  const themed = useThemedIcon()
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <img alt="" src={iconUrl(themed(`insights/catch-rate/${file}`))} className="block w-5 max-w-none" style={{ height }} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

// Model overview: the catch-rate curve + the embedding map (GET /api/insights/catch-rate).
export function CatchRatePage() {
  const query = useCatchRate()
  return <InsightsState query={query}>{(data) => <CatchRateBody data={data} />}</InsightsState>
}

/** API curves -> the chart's series: % caught every 100 CVEs fixed (0 … 5,000), the
 *  end value for its label, and where the marker rests (the top N, as a share of every
 *  CVE scored; the benchmark facts are cached, falling back to the API's own share). */
function toChart(data, benchmark) {
  const series = data.curves.map((c) => {
    const curve = c.points.map((p) => Math.round(p.caught_share * 1000) / 10)
    return { label: c.label, value: Math.round(curve.at(-1)), curve }
  })
  const at = data.top_n?.fixed ?? 500
  const queueSize = benchmark?.cves_scored ?? Math.round(at / (data.top_n?.share_of_queue || 0.0069))
  return { series, top500: { at, queueSize } }
}

function Legend({ curves }) {
  return (
    <div className="flex shrink-0 flex-wrap gap-2">
      {curves.map((c) => {
        const legend = catchRateText.legend[c.ranking] ?? catchRateText.legend.cvss
        return (
          <LegendPill key={c.ranking} file={legend.file} height={legend.height}>
            {c.label}
          </LegendPill>
        )
      })}
    </div>
  )
}

// Catch-rate card, with an expand button that opens the chart in a large popup.
function CatchRateCard({ data, chart }) {
  const expand = useExpand()
  const head = { icon: 'insights/card-line', title: catchRateText.title, subtitle: catchRateText.subtitle }
  const takeaway = data.takeaways?.curves && <Takeaway>{data.takeaways.curves}</Takeaway>
  return (
    <div className="flex min-h-0 min-w-0 flex-[1.4] flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
      <CardHead {...head} onExpand={expand.open} />
      <Legend curves={data.curves} />
      <div className="flex min-h-0 w-full flex-1 items-center justify-center [container-type:size]">
        <CatchRateChart {...chart} />
      </div>
      {takeaway}
      <ChartPopup expand={expand} {...head}>
        <Legend curves={data.curves} />
        <div className="min-h-0 w-full flex-1">
          <CatchRateChart {...chart} />
        </div>
        {takeaway}
      </ChartPopup>
    </div>
  )
}

function CatchRateBody({ data }) {
  const benchmark = useBenchmark().data
  // Never scrolls or clips: on short windows both cards shrink slightly to fit.
  const ref = useRef(null)
  useFitHeight(ref)
  const backtest = data.backtest
  return (
      <main ref={ref} className="flex h-full min-w-0 flex-1 flex-col gap-4 overflow-hidden xl:gap-5 xl:pt-2 [&>*]:[zoom:var(--fit,1)]">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Model overview</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            How many exploited bugs you catch as you fix more of the list, and why the model spots them.
            {backtest && ` Trained on ${backtest.train_year}, tested on ${backtest.test_year} (${backtest.positives} exploited CVEs).`}
          </p>
        </div>

        <section className="flex min-h-0 w-full flex-1 gap-4 rounded-[32px] bg-card p-4 shadow-float xl:gap-5 xl:p-6 short:p-4">
          <CatchRateCard data={data} chart={toChart(data, benchmark)} />
          <EmbeddingCard embedding={data.embedding} takeaway={data.takeaways?.embedding} />
        </section>
      </main>
  )
}
