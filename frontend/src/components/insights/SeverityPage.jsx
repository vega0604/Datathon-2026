import { iconUrl } from '../../lib/Icon'
import { ChartImg, PlotFrame, PlotSurface, Takeaway, chartText, plotBox } from './ChartParts'
import { AboutDataBox, NoteBox, SidePanel, WhatToDoCard } from './NextStepsPanel'
import { aboutData, severity } from '../../data/insights'

const svg = (name) => `insights/severity/${name}`

/* ── Left chart: share reaching KEV, by CVSS band ─────────────────────────
   Figma plot is 292×291; the band labels sit underneath, so the scaled
   block is 292×347 (plot + 16px gap + 40px axis). */
const SEV_W = 292
const SEV_H = 347
const sevBox = plotBox(SEV_W, SEV_H)
const TRACK = { y: 45.55, h: 245.452 }
// Bar geometry from the design, per band (x, top, height, Figma bar graphic or null for the solid bar).
const SEV_BARS = {
  critical: { x: 13.5, y: 104.46, h: 186.544, file: null },
  high: { x: 86.5, y: 222.27, h: 68.727, file: 'bar-high', labelX: 92, labelY: 196.83 },
  medium: { x: 159.5, y: 271.36, h: 19.636, file: 'bar-medium', labelX: 165, labelY: 245.92 },
  low: { x: 232.5, y: 283.41, h: 7.591, file: 'bar-low', labelX: 233.5, labelY: 257.96 },
}

function StatusTag({ band }) {
  return (
    <span className="flex items-center gap-[0.333em] rounded-[1em] bg-subtle px-[0.667em] py-[0.333em]">
      <img alt="" src={iconUrl(svg(`status-${band.key}`))} className="block size-[1em] max-w-none" />
      <span className={`${chartText.label} text-[#161616]`}>{band.label}</span>
    </span>
  )
}

function SeverityChart({ bands }) {
  return (
    <PlotSurface width={SEV_W} height={SEV_H}>
      {bands.map((b) => {
        const bar = SEV_BARS[b.key]
        return (
          <div key={b.key}>
            <div className="absolute rounded-full bg-card" style={sevBox(bar.x, TRACK.y, 46, TRACK.h)} />
            {bar.file ? (
              <ChartImg file={svg(bar.file)} style={sevBox(bar.x, bar.y, 46, bar.h)} />
            ) : (
              <div className="absolute rounded-full bg-purple" style={sevBox(bar.x, bar.y, 46, bar.h)} />
            )}
            {bar.labelX != null && (
              <span className={`absolute text-ink ${chartText.value}`} style={sevBox(bar.labelX, bar.labelY)}>
                {b.value}
              </span>
            )}
          </div>
        )
      })}
      {/* Critical gets a callout instead of a plain label */}
      <span
        className="absolute rounded-[1em] bg-purple-soft px-[1em] py-[0.667em] text-purple-ink"
        style={sevBox(-13.5, 53.3)}
      >
        <span className={chartText.value}>{bands[0].value} reach KEV</span>
      </span>

      {/* x axis: CVSS bands */}
      <div className="absolute inset-x-0 flex items-start" style={{ top: `${(307 / SEV_H) * 100}%` }}>
        {bands.map((b) => (
          <div key={b.key} className="flex min-w-0 flex-1 flex-col items-center gap-[0.333em]">
            <StatusTag band={b} />
            <span className={`${chartText.label} text-ink-muted`}>{b.range}</span>
          </div>
        ))}
      </div>
    </PlotSurface>
  )
}

/* ── Right chart: days between our flag and the KEV listing ──────────────── */
const LEAD_W = 440
const LEAD_H = 351
const leadBox = plotBox(LEAD_W, LEAD_H)
const GRID_X = 21.46
const GRID_W = 418.537
const GRID = [
  { y: 314.33, label: '0', labelX: 9.41, file: 'grid-0' },
  { y: 261.94, label: '5', labelX: 9.41, file: 'grid-line' },
  { y: 209.55, label: '10', labelX: 3.57, file: 'grid-line' },
  { y: 157.16, label: '15', labelX: 3.57, file: 'grid-line' },
  { y: 104.78, label: '20', labelX: 3.57, file: 'grid-line' },
  { y: 52.39, label: '25', labelX: 3.57, file: 'grid-line' },
]
// Per bucket: bar x/top/height, bar graphic (null = solid peak bar), dot, value label and axis label positions.
const LEAD_BARS = [
  { x: 44.54, y: 220.03, h: 94.299, file: 'bar-after-listing', dot: 'dot-after', valueX: 58.82, axisX: 30.32 },
  { x: 128.24, y: 167.64, h: 146.687, file: 'bar-0-7', dot: 'dot-before', valueX: 138.52, axisX: 115.52 },
  { x: 211.95, y: 83.82, h: 230.507, file: null, dot: 'dot-before', valueX: null, axisX: 195.73 },
  { x: 295.66, y: 125.73, h: 188.597, file: 'bar-31-90', dot: 'dot-before', valueX: 305.94, axisX: 275.44 },
  { x: 379.37, y: 240.99, h: 73.343, file: 'bar-over-90', dot: 'dot-before', valueX: 393.65, axisX: 361.15 },
]
const BAR_W = 37.561

function LeadTimeChart({ buckets, peak }) {
  return (
    <PlotSurface width={LEAD_W} height={LEAD_H}>
      {GRID.map((g) => (
        <div key={g.label}>
          <ChartImg file={svg(g.file)} style={leadBox(GRID_X - GRID_W * 0.0012, g.y - 0.5, GRID_W * 1.0024, 1)} />
          <span className={`absolute text-ink-muted ${chartText.label}`} style={leadBox(g.labelX, g.y - 8)}>
            {g.label}
          </span>
        </div>
      ))}

      {buckets.map((b, i) => {
        const bar = LEAD_BARS[i]
        return (
          <div key={b.label}>
            {bar.file ? (
              <ChartImg file={svg(bar.file)} style={leadBox(bar.x, bar.y, BAR_W, bar.h)} />
            ) : (
              <div className="absolute rounded-full bg-blue" style={leadBox(bar.x, bar.y, BAR_W, bar.h)} />
            )}
            <ChartImg file={svg(bar.dot)} style={leadBox(bar.x + 12.78, bar.y - 6, 12, 12)} />
            {bar.valueX != null && (
              <span className={`absolute text-ink ${chartText.value}`} style={leadBox(bar.valueX, bar.y - 33.88)}>
                {b.count}
              </span>
            )}
            <span className={`absolute text-ink-muted ${chartText.label}`} style={leadBox(bar.axisX, 327.28)}>
              {b.label}
            </span>
          </div>
        )
      })}

      {/* Peak callout */}
      <div
        className="absolute flex flex-col gap-[0.167em] rounded-[1em] bg-blue-soft px-[1em] py-[0.667em] text-blue-ink"
        style={leadBox(146.78, 21.15)}
      >
        <span className={chartText.label}>{peak.label}</span>
        <span className={chartText.value}>{peak.value}</span>
      </div>
    </PlotSurface>
  )
}

function LegendSwatch({ className, children }) {
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <span className={`size-3 rounded ${className}`} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

const chartCard = 'flex min-h-min flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4'

export function SeverityPage({ onOpenFixFirst }) {
  return (
    <>
      <main className="flex h-full min-w-0 flex-1 flex-col gap-4 xl:gap-5 xl:pt-2">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Severity isn’t enough</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            Severity scores alone miss most attacks. Our ranking flags them earlier.
          </p>
        </div>

        <section className="flex min-h-0 w-full flex-1 gap-4 overflow-y-auto rounded-[32px] bg-card p-4 shadow-float xl:gap-5 xl:p-6 short:p-4">
          {/* Severity vs exploitation */}
          <div className={`${chartCard} w-[clamp(240px,38%,340px)] shrink-0`}>
            <h2 className="shrink-0 text-lg leading-7 text-ink xl:text-xl">{severity.bands.title}</h2>
            <p className="type-body shrink-0 text-ink-muted">{severity.bands.subtitle}</p>
            <PlotFrame>
              <SeverityChart bands={severity.bands.items} />
            </PlotFrame>
            <Takeaway tone="purple">{severity.bands.takeaway}</Takeaway>
          </div>

          {/* Lead time before KEV */}
          <div className={`${chartCard} min-w-0 flex-1`}>
            <div className="flex shrink-0 flex-col gap-1">
              <h2 className="text-lg leading-7 text-ink xl:text-xl">{severity.leadTime.title}</h2>
              <p className="type-body text-ink-muted">{severity.leadTime.subtitle}</p>
            </div>
            <div className="flex shrink-0 flex-wrap gap-2">
              <LegendSwatch className="bg-blue">Flagged before KEV</LegendSwatch>
              <LegendSwatch className="bg-context">Flagged after KEV</LegendSwatch>
            </div>
            <PlotFrame>
              <LeadTimeChart buckets={severity.leadTime.buckets} peak={severity.leadTime.peak} />
            </PlotFrame>
            <Takeaway>{severity.leadTime.takeaway}</Takeaway>
          </div>
        </section>
      </main>

      <SidePanel>
        <WhatToDoCard onOpenFixFirst={onOpenFixFirst}>
          Don’t sort by severity score alone. The Fix first order flags threats weeks before CISA does.
        </WhatToDoCard>
        <NoteBox
          title="How to read this"
          icon="insights/catch-rate/howto-eye"
          boxClass="bg-green-soft"
          chipClass="bg-card"
          titleClass="text-green-ink"
        >
          Left: the share of each severity band that later got attacked. Right: how many days before CISA’s listing we
          flagged them.
        </NoteBox>
        <AboutDataBox rows={aboutData} />
      </SidePanel>
    </>
  )
}
