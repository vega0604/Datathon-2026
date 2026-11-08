import { iconUrl } from '../../lib/Icon'
import { useThemedIcon } from '../../lib/iconTheme'

// Coverage curve from the Figma "Catch rate" frame. The lines, area, grid and
// markers are the exported Figma SVGs, placed on the design's 804×419 plot and
// scaled as one unit so the chart shrinks with its card.
const W = 804
const H = 419
const PLOT_X = 49.02
const PLOT_W = 593.195


/** Absolute box in design pixels → percentage style. */
function box(x, y, w, h) {
  return {
    left: `${(x / W) * 100}%`,
    top: `${(y / H) * 100}%`,
    width: w == null ? undefined : `${(w / W) * 100}%`,
    height: h == null ? undefined : `${(h / H) * 100}%`,
  }
}

/** Box grown by Figma's stroke insets (fractions of the box size). */
function inset(x, y, w, h, dx, dy) {
  return box(x - w * dx, y - h * dy, w * (1 + 2 * dx), h * (1 + 2 * dy))
}

const GRID = [
  { y: 379, label: '0%', file: 'grid-0', labelX: 18.08 },
  { y: 287.25, label: '20%', file: 'grid-line', labelX: 9.17 },
  { y: 195.5, label: '40%', file: 'grid-line', labelX: 9.17 },
  { y: 103.75, label: '60%', file: 'grid-line', labelX: 9.17 },
  { y: 12, label: '80%', file: 'grid-line', labelX: 9.17 },
]

const X_TICKS = [
  ['0', 45.02],
  ['1k', 160.66],
  ['2k', 279.3],
  ['3k', 397.94],
  ['4k', 516.58],
  ['5k', 635.22],
]

// [file, top, height, vertical inset, horizontal inset]
const BASELINES = [
  ['line-exploit-epss', 260.06, 118.941, 0.0084, 0.0017],
  ['line-epss', 279.74, 99.257, 0.0101, 0.0017],
  ['line-highest-cvss', 297.09, 81.908, 0.0122, 0.0017],
]

// Text is sized in em so it scales with the chart (1em = 12px at full size).
const label = 'absolute text-[1em] leading-[1.333em] tracking-label whitespace-nowrap text-ink-muted'

export function CatchRateChart({ series, top500 }) {
  // Our-model line, area and marker are teal (the Catch rate colour) with dark-mode twins.
  const themed = useThemedIcon()
  const src = (name) => iconUrl(themed(`insights/catch-rate/${name}`))
  return (
    <div className="relative aspect-[804/419] w-[min(100cqw,calc(100cqh*804/419))] [container-type:inline-size]">
      <div className="absolute inset-0 text-[clamp(8px,1.4925cqw,12px)]">
      {GRID.map((g) => (
        <div key={g.label}>
          <img alt="" src={src(g.file)} className="absolute block max-w-none" style={box(PLOT_X, g.y - 0.5, PLOT_W, 1)} />
          <span className={label} style={box(g.labelX, g.y - 8)}>
            {g.label}
          </span>
        </div>
      ))}
      {X_TICKS.map(([t, x]) => (
        <span key={t} className={label} style={box(x, 387)}>
          {t}
        </span>
      ))}
      <span className={label} style={box(315.62, 403)}>
        CVEs fixed
      </span>

      {/* Our model: shaded area + line */}
      <img alt="" src={src('area-our-model')} className="chart-draw absolute block max-w-none" style={box(PLOT_X - PLOT_W * 0.0013, 96.41 - 282.59 * 0.0018, PLOT_W * 1.0013, 282.59 * 1.0036)} />
      <img alt="" src={src('line-our-model')} className="chart-draw absolute block max-w-none" style={inset(PLOT_X, 96.41, PLOT_W, 282.59, 0.0025, 0.0053)} />
      {BASELINES.map(([file, y, h, dy, dx], i) => (
        <img key={file} alt="" src={src(file)} className="chart-draw absolute block max-w-none" style={{ ...inset(PLOT_X, y, PLOT_W, h, dx, dy), '--i': i + 1 }} />
      ))}

      {/* End-of-line labels */}
      <span className="absolute text-[1.1667em] leading-[1.5em] tracking-body font-semibold whitespace-nowrap text-ink" style={box(652.22, 89.16)}>
        {series[0].label} · {series[0].value}%
      </span>
      {series.slice(1).map((s, i) => (
        <span key={s.label} className={label} style={box(652.22, [252, 278.69, 305.38][i])}>
          {s.label} · {s.value}%
        </span>
      ))}

      {/* Top-500 reference line, marker and callout */}
      <img alt="" src={src('ref-top500')} className="absolute block max-w-none" style={box(107.84, 12 - 0.514, 1, 368.03)} />
      <img alt="" src={src('marker-top500')} className="chart-pop absolute block max-w-none" style={box(101.34, 260.09, 14, 14)} />
      <div
        className="absolute flex flex-col gap-[0.167em] rounded-[1em] bg-green-soft px-[1em] py-[0.667em] whitespace-nowrap text-green-ink"
        style={box(149.87, 29.37)}
      >
        <span className="text-[1em] leading-[1.333em] tracking-label">{top500.label}</span>
        <span className="text-[1.1667em] leading-[1.5em] tracking-body font-semibold">{top500.value}</span>
      </div>
      </div>
    </div>
  )
}
