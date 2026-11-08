import { ChartImg, PlotFrame, PlotSurface, chartText, plotBox } from './ChartParts'
import { pct } from '../../data/ui'

// Weakness-type bubble chart (one bubble per CWE), shown on Insights → Summary.
// Drawn from GET /api/insights/summary `weaknesses` on the Figma plot (804×439 design
// px): x = CVE count (log scale), y = share reaching KEV, area = KEV count. The two
// highest KEV shares are highlighted and the highest gets a callout.

const ICON = 'insights/bug-types'
const W = 804
const H = 439
const box = plotBox(W, H)
const LINE_LEFT = 49.02
const LINE_W = 718.207
// Bubble centres stay inside this box so the largest bubble and its label fit.
const X0 = 86
const X1 = 720
const Y_ZERO = 389.11 // the 0% axis line
const Y_TOP = 30 // the highest tick
const MIN_D = 14
const MAX_D = 44

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

const LOG_TICKS = [100, 300, 1_000, 3_000, 10_000, 30_000, 100_000, 300_000]
const fmtCount = (n) => (n >= 10_000 ? `${n / 1000}k` : n.toLocaleString('en-US'))

function yStep(max) {
  if (max <= 0.02) return 0.005
  if (max <= 0.05) return 0.01
  return 0.02
}

export function BubbleChart({ weaknesses, minH }) {
  const items = weaknesses.items
  const logs = items.map((w) => Math.log10(w.cve_count))
  const lo = Math.min(...logs) - 0.08
  const hi = Math.max(...logs) + 0.08
  const step = yStep(Math.max(...items.map((w) => w.kev_share), weaknesses.overall_kev_share))
  const yMax = Math.ceil(Math.max(...items.map((w) => w.kev_share)) / step) * step || step
  const x = (count) => X0 + ((Math.log10(count) - lo) / (hi - lo)) * (X1 - X0)
  const y = (share) => Y_ZERO - (share / yMax) * (Y_ZERO - Y_TOP)
  const maxKev = Math.max(...items.map((w) => w.kev_count), 1)
  const diameter = (k) => MIN_D + Math.sqrt(k / maxKev) * (MAX_D - MIN_D)
  const keys = [...items].sort((a, b) => b.kev_share - a.kev_share).slice(0, 2).map((w) => w.cwe_id)
  const top = items.find((w) => w.cwe_id === keys[0])
  const yTicks = Array.from({ length: Math.round(yMax / step) + 1 }, (_, i) => i * step)
  const xTicks = LOG_TICKS.filter((t) => Math.log10(t) >= lo && Math.log10(t) <= hi)

  return (
    <PlotFrame minH={minH}>
      <PlotSurface width={W} height={H}>
        <div
          role="img"
          aria-label={`Bubble chart of ${items.length} weakness types: ${top?.name} reaches KEV most often (${pct(top?.kev_share ?? 0)}).`}
          className="absolute inset-0"
        >
          {/* y axis: gridlines and % labels (0% is the solid axis line) */}
          {yTicks.map((t) => (
            <div key={t}>
              <Rule file={t === 0 ? 'line-axis' : 'line-grid'} top={y(t)} />
              <AxisLabel x={10} y={y(t) - 8}>
                {pct(t, step < 0.01 ? 1 : 0)}
              </AxisLabel>
            </div>
          ))}

          {/* x axis */}
          {xTicks.map((t) => (
            <AxisLabel key={t} x={x(t) - 14} y={401.07}>
              {fmtCount(t)}
            </AxisLabel>
          ))}
          <AxisLabel x={348.13} y={421.02}>
            CVE count (log scale)
          </AxisLabel>

          {/* Average across all CWEs */}
          <Rule file="ref-average" top={y(weaknesses.overall_kev_share)} />
          <AxisLabel x={LINE_LEFT + LINE_W - 92} y={y(weaknesses.overall_kev_share) - 22}>
            All CWEs {pct(weaknesses.overall_kev_share)}
          </AxisLabel>

          {items.map((w, i) => {
            const d = diameter(w.kev_count)
            const cx = x(w.cve_count)
            const cy = y(w.kev_share)
            const key = keys.includes(w.cwe_id)
            return (
              <div key={w.cwe_id} title={`${w.name} (${w.cwe_id}): ${w.cve_count.toLocaleString('en-US')} CVEs, ${w.kev_count} on KEV, ${pct(w.kev_share)}`}>
                <span
                  className={`chart-pop absolute rounded-full ${key ? 'border-2 border-chart-2 bg-chart-2/30' : 'border border-chart-1 bg-chart-1/15'}`}
                  style={{ ...box(cx - d / 2, cy - d / 2, d, d), '--i': i }}
                />
                <span
                  className={`chart-fade absolute text-ink ${key ? 'text-[1.1667em] leading-[1.5em] font-semibold tracking-body whitespace-nowrap' : chartText.label}`}
                  style={box(cx + d / 2 + 4, cy - 8)}
                >
                  {w.cwe_id}
                </span>
              </div>
            )
          })}

          {/* Callout on the top bubble */}
          {top && (
            <div
              className="chart-fade absolute flex flex-col gap-[0.1667em] rounded-[1em] bg-blue-soft px-[1em] py-[0.6667em] whitespace-nowrap text-blue-ink"
              style={box(Math.min(x(top.cve_count) + 26, W - 230), Math.max(0, y(top.kev_share) - 58))}
            >
              <span className={chartText.label}>{top.name}</span>
              <span className="text-[1.1667em] leading-[1.2857em] font-semibold tracking-body">{pct(top.kev_share)} reach KEV</span>
            </div>
          )}
        </div>
      </PlotSurface>
    </PlotFrame>
  )
}
