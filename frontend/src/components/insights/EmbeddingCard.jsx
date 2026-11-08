import { iconUrl } from '../../lib/Icon'
import { ChartImg, PlotFrame, PlotSurface, Takeaway, chartText, plotBox } from './ChartParts'
import { model } from '../../data/insights'
// modelEmbedding.js is generated model output. It's loaded optionally so a copy
// of the repo without it still runs: the map then shows a note instead of points.
const embedding = Object.values(import.meta.glob('../../data/modelEmbedding.js', { eager: true }))[0]
const kevPoints = embedding?.kevPoints ?? []
const otherPoints = embedding?.otherPoints ?? []

const ICON = 'insights/model'

// ---- Embedding map: 2-D projection of CVE text embeddings, 362×367 design plot ----
const MAP_W = 362
const MAP_H = 367
const mapBox = plotBox(MAP_W, MAP_H)

function LegendPill({ file, size, children }) {
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <img alt="" src={iconUrl(`${ICON}/${file}`)} className="block max-w-none" style={{ width: size, height: size }} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

function EmbeddingMap({ clusters }) {
  return (
    <PlotFrame>
      <PlotSurface width={MAP_W} height={MAP_H}>
        <div
          className="absolute inset-0 rounded-[18px] bg-card"
          role="img"
          aria-label={`Map of ${otherPoints.length + kevPoints.length} CVEs; ${kevPoints.length} KEV entries, shown as diamonds, form two clusters.`}
        >
          {otherPoints.map(([x, y], i) => (
            <ChartImg key={`p${i}`} file={`${ICON}/pt`} className="chart-pop" style={{ ...mapBox(x, y, 6, 6), '--i': i % 30 }} />
          ))}
          {kevPoints.map(([x, y], i) => (
            <ChartImg key={`k${i}`} file={`${ICON}/kev`} className="chart-pop" style={{ ...mapBox(x, y, 12, 19.1478), '--i': 10 + (i % 20) }} />
          ))}
          {!embedding && (
            <p className="absolute inset-0 flex items-center justify-center p-6 text-center text-sm text-ink-muted">
              The embedding data (src/data/modelEmbedding.js) isn’t in this copy of the project yet.
            </p>
          )}
          {embedding && clusters.map((c) => (
            <span
              key={c.label}
              className={`absolute rounded-full bg-blue-soft px-[0.833em] py-[0.333em] text-blue-ink ${chartText.label}`}
              style={mapBox(c.x, c.y)}
            >
              {c.label}
            </span>
          ))}
        </div>
      </PlotSurface>
    </PlotFrame>
  )
}

// "Exploited CVEs cluster in Granite’s text space" (from the former Model check page),
// shown on the Catch rate page.
export function EmbeddingCard() {
  const e = model.embedding
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
      <h2 className="shrink-0 text-lg leading-7 text-ink xl:text-xl">{e.title}</h2>
      <div className="flex shrink-0 flex-wrap gap-2">
        <LegendPill file="legend-dot" size={7}>Not on KEV (dot)</LegendPill>
        <LegendPill file="legend-diamond" size={11}>On KEV (diamond)</LegendPill>
      </div>
      <EmbeddingMap clusters={e.clusters} />
      <Takeaway>{e.takeaway}</Takeaway>
    </div>
  )
}
