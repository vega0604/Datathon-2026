import { ChartImg, PlotFrame, PlotSurface, chartText, plotBox } from './ChartParts'

// Weakness-type bubble chart (one bubble per CWE), shown on Insights → Summary.

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

export function BubbleChart({ data, minH }) {
  return (
    <PlotFrame minH={minH}>
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

          {data.bubbles.map((b, i) => {
            const [x, y, size] = b.box
            return (
              <div key={b.cwe}>
                <ChartImg file={`${ICON}/bubble-${b.file}`} className="chart-pop" style={{ ...box(x, y, size, size), '--i': i }} />
                <ChartImg file={`${ICON}/outline-${b.file}`} className="chart-pop" style={{ ...box(x, y, size, size), '--i': i }} />
                <span
                  className={`chart-fade absolute text-ink ${b.key ? 'text-[1.1667em] leading-[1.5em] font-semibold tracking-body whitespace-nowrap' : chartText.label}`}
                  style={box(b.label[0], b.label[1])}
                >
                  {b.cwe}
                </span>
              </div>
            )
          })}

          {/* Callout on the top bubble */}
          <div
            className="chart-fade absolute flex flex-col gap-[0.1667em] rounded-[1em] bg-blue-soft px-[1em] py-[0.6667em] whitespace-nowrap text-blue-ink"
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
