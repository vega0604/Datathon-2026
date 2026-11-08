import { useMemo, useRef } from 'react'
import { useSize } from '../../lib/useSize'
import { pct } from '../../data/ui'
import { plotBox } from './ChartParts'

// Weakness-type bubble chart (one bubble per CWE), shown on Insights → Summary.
// Drawn from GET /api/insights/summary `weaknesses`: x = CVE count (log scale),
// y = share reaching KEV, area = KEV count. The two highest KEV shares are
// highlighted and the highest gets a callout.
//
// Laid out at the card's real size so text stays a fixed, readable size however
// small the card gets. Where bubbles crowd together, a label that can't be placed
// clear of the others is left off; hovering any bubble still names it.

const LOG_TICKS = [100, 300, 1_000, 3_000, 5_000, 10_000, 20_000, 30_000, 50_000, 100_000, 300_000]
const fmtCount = (n) => (n >= 10_000 ? `${n / 1000}k` : n.toLocaleString('en-US'))

const PLOT_LEFT = 42 // room for the % labels
const PLOT_BOTTOM = 42 // room for the x ticks and axis title
const LABEL_H = 18
const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi)

// Rough text widths for IBM Plex Sans (12px labels, 14px semibold for the highlights).
const labelWidth = (text, key) => text.length * (key ? 8.6 : 7.2) + 8 // includes the backing's padding

function yStep(max) {
  if (max <= 0.02) return 0.005
  if (max <= 0.05) return 0.01
  return 0.02
}

const hits = (a, b) => a.x < b.x + b.w + 2 && a.x + a.w + 2 > b.x && a.y < b.y + b.h + 1 && a.y + a.h + 1 > b.y

/** Positions every bubble, the callout and as many labels as fit without touching. */
function layout(weaknesses, W, H) {
  const items = weaknesses.items
  const logs = items.map((w) => Math.log10(w.cve_count))
  const lo = Math.min(...logs) - 0.08
  const hi = Math.max(...logs) + 0.08
  const step = yStep(Math.max(...items.map((w) => w.kev_share), weaknesses.overall_kev_share))
  const yMax = Math.ceil(Math.max(...items.map((w) => w.kev_share)) / step) * step || step
  const X0 = PLOT_LEFT + 24
  const X1 = W - 48
  const yZero = H - PLOT_BOTTOM
  const yTop = 12
  const xAt = (count) => X0 + ((Math.log10(count) - lo) / (hi - lo)) * (X1 - X0)
  const yAt = (share) => yZero - (share / yMax) * (yZero - yTop)
  const maxKev = Math.max(...items.map((w) => w.kev_count), 1)
  const maxD = clamp(H * 0.15, 22, 46)

  const keys = [...items].sort((a, b) => b.kev_share - a.kev_share).slice(0, 2).map((w) => w.cwe_id)
  const bubbles = items.map((w) => {
    const d = 9 + Math.sqrt(w.kev_count / maxKev) * (maxD - 9)
    return { w, d, cx: xAt(w.cve_count), cy: yAt(w.kev_share), key: keys.includes(w.cwe_id) }
  })
  const rects = bubbles.map((b) => ({ x: b.cx - b.d / 2, y: b.cy - b.d / 2, w: b.d, h: b.d, owner: b.w.cwe_id }))
  const yAvg = yAt(weaknesses.overall_kev_share)
  const avgLabel = { x: W - 104, y: yAvg - 18, w: 100, h: 16 }
  const taken = [avgLabel]

  // Callout: beside the top bubble, on whichever side stays clear.
  const top = bubbles.find((b) => b.w.cwe_id === keys[0])
  let callout = null
  if (top) {
    const value = `${pct(top.w.kev_share)} reach KEV`
    const w = Math.min(230, Math.max(top.w.name.length * 6.7, value.length * 7.8)) + 26
    const h = 48
    const near = [top.cx + top.d / 2 + 12, top.cx - top.d / 2 - 12 - w]
    const spots = [clamp(top.cy - h / 2, 0, yZero - h - 2), 0]
      .flatMap((y) => near.map((x) => ({ x, y, w, h })))
      .concat({ x: W - w - 4, y: 0, w, h }) // the top-right corner is usually empty
      .filter((s) => s.x >= PLOT_LEFT && s.x + w <= W)
    callout = spots.find((s) => !rects.some((r) => hits(s, r))) ?? spots[0] ?? null
    if (callout) taken.push(callout)
  }

  // Labels, most important first, so crowding only ever drops the minor ones.
  const order = [...bubbles].sort((a, b) => b.key - a.key || b.w.kev_count - a.w.kev_count)
  const labels = []
  for (const b of order) {
    const w = labelWidth(b.w.cwe_id, b.key)
    const h = LABEL_H
    const r = b.d / 2
    const spots = [
      { x: b.cx + r + 4, y: b.cy - h / 2 },
      { x: b.cx - r - 4 - w, y: b.cy - h / 2 },
      { x: b.cx - w / 2, y: b.cy - r - h - 1 },
      { x: b.cx - w / 2, y: b.cy + r + 1 },
      { x: b.cx + r * 0.7 + 2, y: b.cy - r * 0.7 - h },
      { x: b.cx + r * 0.7 + 2, y: b.cy + r * 0.7 },
    ]
    const spot = spots
      .map((s) => ({ ...s, w, h }))
      .find((s) => s.x >= PLOT_LEFT + 2 && s.x + w <= W - 2 && s.y >= 0 && s.y + h <= yZero - 1 && !taken.some((t) => hits(s, t)) && !rects.some((q) => q.owner !== b.w.cwe_id && hits(s, q)))
    if (!spot) continue
    taken.push(spot)
    labels.push({ ...spot, id: b.w.cwe_id, key: b.key })
  }

  return {
    bubbles,
    labels,
    callout,
    top,
    yAvg,
    avgLabel,
    yZero,
    yTicks: Array.from({ length: Math.round(yMax / step) + 1 }, (_, i) => ({ t: i * step, y: yAt(i * step) })),
    xTicks: LOG_TICKS.filter((t) => Math.log10(t) >= lo && Math.log10(t) <= hi).map((t) => ({ t, x: xAt(t) })),
    decimals: step < 0.01 ? 1 : 0,
  }
}

export function BubbleChart({ weaknesses, minH = 'min-h-[160px]' }) {
  const ref = useRef(null)
  const { width: W, height: H } = useSize(ref)
  const plot = useMemo(() => (W && H ? layout(weaknesses, W, H) : null), [weaknesses, W, H])
  const box = plotBox(W || 1, H || 1)
  const axis = 'absolute text-xs leading-4 whitespace-nowrap text-ink-muted'

  return (
    <div ref={ref} className={`relative w-full flex-1 ${minH}`}>
      {plot && (
        <div
          role="img"
          aria-label={`Bubble chart of ${weaknesses.items.length} weakness types: ${plot.top?.w.name} reaches KEV most often (${pct(plot.top?.w.kev_share ?? 0)}).`}
          className="absolute inset-0"
        >
          {plot.yTicks.map(({ t, y }) => (
            <div key={t}>
              <div className={`absolute border-t ${t === 0 ? 'border-line-strong' : 'border-dashed border-line'}`} style={box(PLOT_LEFT, y, W - PLOT_LEFT, 0)} />
              <span className={axis} style={box(0, y - 8)}>{pct(t, plot.decimals)}</span>
            </div>
          ))}

          {plot.xTicks.map(({ t, x }) => (
            <span key={t} className={`${axis} -translate-x-1/2`} style={box(x, plot.yZero + 5)}>{fmtCount(t)}</span>
          ))}
          <span className={`${axis} -translate-x-1/2`} style={box((PLOT_LEFT + W) / 2, plot.yZero + 23)}>CVE count (log scale)</span>

          <div className="absolute border-t border-dashed border-ink-muted" style={box(PLOT_LEFT, plot.yAvg, W - PLOT_LEFT, 0)} />
          <span className={`${axis} text-right`} style={box(plot.avgLabel.x, plot.avgLabel.y, plot.avgLabel.w)}>
            All CWEs {pct(weaknesses.overall_kev_share)}
          </span>

          {plot.bubbles.map((b, i) => (
            <span
              key={b.w.cwe_id}
              title={`${b.w.name} (${b.w.cwe_id}): ${b.w.cve_count.toLocaleString('en-US')} CVEs, ${b.w.kev_count} on KEV, ${pct(b.w.kev_share)}`}
              className={`chart-pop absolute rounded-full ${b.key ? 'border-2 border-chart-2 bg-chart-2/30' : 'border border-chart-1 bg-chart-1/15'}`}
              style={{ ...box(b.cx - b.d / 2, b.cy - b.d / 2, b.d, b.d), '--i': i }}
            />
          ))}

          {plot.labels.map((l) => (
            <span
              key={l.id}
              className={`chart-fade pointer-events-none absolute rounded bg-card/85 px-1 leading-[18px] whitespace-nowrap text-ink ${l.key ? 'text-sm font-semibold' : 'text-xs'}`}
              style={box(l.x, l.y)}
            >
              {l.id}
            </span>
          ))}

          {plot.callout && (
            <div
              className="chart-fade pointer-events-none absolute flex flex-col justify-center rounded-xl bg-blue-soft px-3 text-blue-ink"
              style={box(plot.callout.x, plot.callout.y, plot.callout.w, plot.callout.h)}
            >
              <span className="truncate text-xs leading-4">{plot.top.w.name}</span>
              <span className="text-sm leading-5 font-semibold whitespace-nowrap">{pct(plot.top.w.kev_share)} reach KEV</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
