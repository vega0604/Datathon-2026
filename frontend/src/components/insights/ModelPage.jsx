import { Icon, iconUrl } from '../../lib/Icon'
import { ChartImg, PlotFrame, PlotSurface, Takeaway, chartText, plotBox } from './ChartParts'
import { AboutDataBox, NoteBox, SidePanel, WhatToDoCard } from './NextStepsPanel'
import { aboutData, model } from '../../data/insights'
// modelEmbedding.js is generated model output. It's loaded optionally so a copy
// of the repo without it still runs: the map then shows a note instead of points.
const embedding = Object.values(import.meta.glob('../../data/modelEmbedding.js', { eager: true }))[0]
const kevPoints = embedding?.kevPoints ?? []
const otherPoints = embedding?.otherPoints ?? []

const ICON = 'insights/model'

// ---- Leakage audit: two bars on a 362×144 design plot ----
const BAR_W = 362
const BAR_H = 144
const barBox = plotBox(BAR_W, BAR_H)

function LeakageBars({ banned, submitted }) {
  return (
    // Scales with the card's width; text is em-based so it shrinks with the bars.
    <div className="w-full shrink-0 [container-type:inline-size]">
      <div
        className="relative w-full"
        style={{ aspectRatio: `${BAR_W} / ${BAR_H}`, fontSize: `clamp(8px, ${(12 / BAR_W) * 100}cqw, 12px)` }}
      >
        <span className={`absolute text-ink-muted ${chartText.label}`} style={barBox(0, 0)}>
          {banned.label}
        </span>
        <ChartImg file={`${ICON}/bar-banned`} style={barBox(0, 22, 274.84, 40)} />
        <span className="absolute text-[2.333em] leading-[1.286em] whitespace-nowrap text-purple-ink" style={barBox(284.84, 24)}>
          {banned.value}
        </span>

        <span className={`absolute text-ink-muted ${chartText.label}`} style={barBox(0, 76)}>
          {submitted.label}
        </span>
        <div className="absolute rounded-full bg-purple" style={barBox(0, 98, 103.628, 40)} />
        <span className="absolute text-[2.333em] leading-[1.286em] whitespace-nowrap text-purple-ink" style={barBox(113.63, 100)}>
          {submitted.value}
        </span>
      </div>
    </div>
  )
}

function LeakageCard() {
  const l = model.leakage
  return (
    <div className="flex min-w-0 flex-1 flex-col justify-between gap-5 rounded-[28px] bg-purple-soft p-5 xl:p-7 short:gap-4 short:p-5">
      <div className="flex flex-col items-start gap-3">
        <p className="type-label text-ink-muted">Leakage audit</p>
        <h2 className="text-[clamp(20px,1.9vw,28px)] leading-[1.29] text-purple-ink">{l.headline}</h2>
        <span className="flex items-center gap-1 rounded-xl bg-card px-2 py-1">
          <Icon name={`${ICON}/status-passed`} className="size-3" />
          <span className="type-label whitespace-nowrap text-ink">{l.status}</span>
        </span>
      </div>
      <LeakageBars banned={l.banned} submitted={l.submitted} />
      <Takeaway tone="ai">{l.takeaway}</Takeaway>
    </div>
  )
}

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
            <ChartImg key={`p${i}`} file={`${ICON}/pt`} style={mapBox(x, y, 6, 6)} />
          ))}
          {kevPoints.map(([x, y], i) => (
            <ChartImg key={`k${i}`} file={`${ICON}/kev`} style={mapBox(x, y, 12, 19.1478)} />
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

function EmbeddingCard() {
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

export function ModelPage({ onOpenFixFirst }) {
  return (
    <>
      <main className="flex h-full min-w-0 flex-1 flex-col gap-4 xl:gap-5 xl:pt-2">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Model check</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            Proof the ranking is fair and doesn’t peek at the future.
          </p>
        </div>

        <section className="flex min-h-0 w-full flex-1 overflow-y-auto rounded-[32px] bg-card p-4 shadow-float xl:p-6 short:p-4">
          <div className="flex min-h-min w-full gap-4 xl:gap-5">
            <LeakageCard />
            <EmbeddingCard />
          </div>
        </section>
      </main>

      <SidePanel>
        <WhatToDoCard onOpenFixFirst={onOpenFixFirst}>No action needed. The model passed its leakage audit.</WhatToDoCard>
        <NoteBox
          title="How to read this"
          icon="insights/catch-rate/howto-eye"
          boxClass="bg-green-soft"
          chipClass="bg-card"
          titleClass="text-green-ink"
        >
          Left: the score with banned columns vs our real model. Right: similar CVEs sit close together.
        </NoteBox>
        <AboutDataBox rows={aboutData} />
      </SidePanel>
    </>
  )
}
