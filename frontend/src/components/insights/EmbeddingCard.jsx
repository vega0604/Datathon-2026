import { iconUrl } from '../../lib/Icon'
import { embeddingText } from '../../data/ui'
import { ChartImg, PlotFrame, PlotSurface, Takeaway, chartText, plotBox } from './ChartParts'
import { CardHead, ChartPopup } from './ExpandableCard'
import { useExpand } from '../../lib/useExpand'

const ICON = 'insights/model'

// ---- Embedding map: 2-D projection of Granite description embeddings, 362×367 design plot ----
// The API sends x and y from 0 to 1 (y = 0 at the top); markers are placed so they
// stay inside the plot.
const MAP_W = 362
const MAP_H = 367
const mapBox = plotBox(MAP_W, MAP_H)
const PAD = 14
const DOT = 6
const KEV_W = 12
const KEV_H = 19.1478
const at = (v, size, extent) => PAD + v * (extent - 2 * PAD - size)

function LegendPill({ file, size, children }) {
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <img alt="" src={iconUrl(`${ICON}/${file}`)} className="block max-w-none" style={{ width: size, height: size }} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

function EmbeddingMap({ points, clusters }) {
  const kev = points.filter((p) => p.on_kev)
  const other = points.filter((p) => !p.on_kev)
  return (
    <PlotFrame minH="min-h-[140px]">
      <PlotSurface width={MAP_W} height={MAP_H}>
        <div
          className="absolute inset-0 rounded-[18px] bg-card"
          role="img"
          aria-label={`Map of ${points.length} CVE descriptions; ${kev.length} KEV entries are shown as diamonds.`}
        >
          {other.map((p, i) => (
            <ChartImg key={p.cve_id} file={`${ICON}/pt`} className="chart-pop" style={{ ...mapBox(at(p.x, DOT, MAP_W), at(p.y, DOT, MAP_H), DOT, DOT), '--i': i % 30 }} />
          ))}
          {kev.map((p, i) => (
            <ChartImg key={p.cve_id} file={`${ICON}/kev`} className="chart-pop" style={{ ...mapBox(at(p.x, KEV_W, MAP_W), at(p.y, KEV_H, MAP_H), KEV_W, KEV_H), '--i': 10 + (i % 20) }} />
          ))}
          {!points.length && (
            <p className="absolute inset-0 flex items-center justify-center p-6 text-center text-sm text-ink-muted">
              The backend has no description embeddings yet.
            </p>
          )}
          {clusters.map((c, i) => (
            <span
              key={`${c.label}-${i}`}
              className={`absolute -translate-x-1/2 rounded-full bg-blue-soft px-[0.833em] py-[0.333em] text-blue-ink ${chartText.label}`}
              style={mapBox(at(c.x, 0, MAP_W), at(c.y, 0, MAP_H))}
            >
              {c.label}
            </span>
          ))}
        </div>
      </PlotSurface>
    </PlotFrame>
  )
}

function Legend() {
  return (
    <div className="flex shrink-0 flex-wrap gap-2">
      <LegendPill file="legend-dot" size={7}>Not on KEV (dot)</LegendPill>
      <LegendPill file="legend-diamond" size={11}>On KEV (diamond)</LegendPill>
    </div>
  )
}

// Granite text map on the Model overview page (GET /api/insights/catch-rate `embedding`),
// with an expand button that opens it in a large popup.
export function EmbeddingCard({ embedding, takeaway }) {
  const expand = useExpand()
  const head = { icon: 'insights/card-bubbles', title: embeddingText.title, subtitle: embeddingText.subtitle }
  const map = <EmbeddingMap points={embedding?.points ?? []} clusters={embedding?.clusters ?? []} />
  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
      <CardHead {...head} onExpand={expand.open} />
      <Legend />
      {map}
      {takeaway && <Takeaway>{takeaway}</Takeaway>}
      <ChartPopup expand={expand} {...head} size="w-[min(900px,94vw)]">
        <Legend />
        {map}
        {takeaway && <Takeaway>{takeaway}</Takeaway>}
      </ChartPopup>
    </div>
  )
}
