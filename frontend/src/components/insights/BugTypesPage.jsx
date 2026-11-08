import { ChartImg, PlotFrame, PlotSurface, Takeaway, chartText, plotBox } from './ChartParts'
import { AboutDataBox, NoteBox, SidePanel, WhatToDoCard } from './NextStepsPanel'
import { aboutData, bugTypes } from '../../data/insights'

const ICON = 'insights/bug-types'
const W = 804
const H = 439
const box = plotBox(W, H)
const LINE_LEFT = 49.02
const LINE_W = 718.207

/** Horizontal rule spanning the plot; `top` is the line's centre in design px. */
function Rule({ file, top }) {
  return <ChartImg file={`${ICON}/${file}`} style={box(LINE_LEFT, top - 0.5, LINE_W, 1)} />
}

function AxisLabel({ x, y, children }) {
  return (
    <span className={`absolute text-ink-muted ${chartText.label}`} style={box(x, y)}>
      {children}
    </span>
  )
}

function BubbleChart({ data }) {
  return (
    <PlotFrame>
      <PlotSurface width={W} height={H}>
        <div
          role="img"
          aria-label="Bubble chart of bug types: CWE-78 and CWE-502 reach KEV most often despite being rare."
          className="absolute inset-0"
        >
          {/* y axis: gridlines and % labels (0% is the solid axis line) */}
          {data.yTicks.map(([label, top]) => (
            <div key={label}>
              <Rule file={label === '0%' ? 'line-axis' : 'line-grid'} top={top} />
              <AxisLabel x={18.08} y={top - 8}>
                {label}
              </AxisLabel>
            </div>
          ))}

          {/* x axis */}
          {data.xTicks.map(([label, left]) => (
            <AxisLabel key={label} x={left} y={401.07}>
              {label}
            </AxisLabel>
          ))}
          <AxisLabel x={348.13} y={421.02}>
            CVE count (log scale)
          </AxisLabel>

          {/* Average across all CWEs */}
          <Rule file="ref-average" top={data.average.top} />
          <AxisLabel x={data.average.labelLeft} y={data.average.labelTop}>
            {data.average.label}
          </AxisLabel>

          {data.bubbles.map((b) => {
            const [x, y, size] = b.box
            return (
              <div key={b.cwe}>
                <ChartImg file={`${ICON}/bubble-${b.file}`} style={box(x, y, size, size)} />
                <ChartImg file={`${ICON}/outline-${b.file}`} style={box(x, y, size, size)} />
                <span
                  className={`absolute text-ink ${b.key ? 'text-[1.1667em] leading-[1.5em] font-semibold tracking-body whitespace-nowrap' : chartText.label}`}
                  style={box(b.label[0], b.label[1])}
                >
                  {b.cwe}
                </span>
              </div>
            )
          })}

          {/* Callout on the top bubble */}
          <div
            className="absolute flex flex-col gap-[0.1667em] rounded-[1em] bg-blue-soft px-[1em] py-[0.6667em] whitespace-nowrap text-blue-ink"
            style={box(data.callout.left, data.callout.top)}
          >
            <span className={chartText.label}>{data.callout.title}</span>
            <span className="text-[1.1667em] leading-[1.2857em] font-semibold tracking-body">{data.callout.value}</span>
          </div>
        </div>
      </PlotSurface>
    </PlotFrame>
  )
}

export function BugTypesPage({ onOpenFixFirst }) {
  return (
    <>
      <main className="flex h-full min-w-0 flex-1 flex-col gap-4 xl:gap-5 xl:pt-2">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Bug types</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">Which kinds of bugs attackers prefer.</p>
        </div>

        <section className="flex min-h-0 w-full flex-1 overflow-y-auto rounded-[32px] bg-card p-4 shadow-float xl:p-6 short:p-4">
          <div className="flex min-h-min w-full flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
            <div className="flex shrink-0 flex-col gap-1">
              <h2 className="text-lg leading-7 text-ink xl:text-xl">{bugTypes.title}</h2>
              <p className="type-body text-ink-muted">{bugTypes.subtitle}</p>
            </div>
            <BubbleChart data={bugTypes} />
            <Takeaway>{bugTypes.takeaway}</Takeaway>
          </div>
        </section>
      </main>

      <SidePanel>
        <WhatToDoCard onOpenFixFirst={onOpenFixFirst}>
          Fix command injection (CWE-78) and unsafe deserialization (CWE-502) bugs first.
        </WhatToDoCard>
        <NoteBox
          title="How to read this"
          icon="insights/catch-rate/howto-eye"
          boxClass="bg-green-soft"
          chipClass="bg-card"
          titleClass="text-green-ink"
        >
          Each bubble is a bug type. Further right means more common; higher means more often exploited.
        </NoteBox>
        <AboutDataBox rows={aboutData} />
      </SidePanel>
    </>
  )
}
