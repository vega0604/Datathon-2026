import { Icon } from '../../lib/Icon'

// Segmented radial gauge, geometry measured from the Figma frame:
// 30 segments (13×46) on a 230° arc of radius 167 around (210, 204).
// Drawn as an SVG with a viewBox so it scales down to fit the card.
const SEGMENTS = 30
const SWEEP = 230
const CX = 210
const CY = 204
const RADIUS = 167

function SegmentedGauge({ pct }) {
  const filled = Math.round((pct / 100) * SEGMENTS)
  return (
    <svg
      viewBox="0 0 420 292"
      role="img"
      aria-label={`${pct}% of exploited CVEs caught by fixing our top 500`}
      className="block h-full max-h-[360px] w-full font-sans"
    >
      {Array.from({ length: SEGMENTS }, (_, i) => {
        const deg = -SWEEP / 2 + (i * SWEEP) / (SEGMENTS - 1)
        const rad = (deg * Math.PI) / 180
        const x = CX + RADIUS * Math.sin(rad)
        const y = CY - RADIUS * Math.cos(rad)
        return (
          <rect
            key={i}
            x={x - 6.5}
            y={y - 23}
            width="13"
            height="46"
            rx="6.5"
            transform={`rotate(${deg} ${x} ${y})`}
            className={i < filled ? 'gauge-fill fill-chart-1' : 'fill-subtle'}
            style={{ '--i': i }}
          />
        )
      })}
      <text x={CX} y="196" textAnchor="middle" dominantBaseline="central" className="fill-ink text-[88px] font-light">
        {pct}%
      </text>
    </svg>
  )
}

// Gauge (with the percent) on the left; what it means, the key and how it compares on
// the right. Kept short so the weakness chart below it has room for readable labels.
export function CoverageCard({ coverage }) {
  return (
    <section className="flex w-full min-w-0 shrink-0 items-center gap-6 rounded-[28px] bg-card p-6 shadow-float short:p-5">
      {/* Gauge height follows the window height so it stays large on big screens. */}
      <div className="flex h-[clamp(120px,17vh,200px)] w-[30%] shrink-0 items-center justify-center">
        <SegmentedGauge pct={coverage.caughtPct} />
      </div>
      <div className="flex min-w-0 flex-1 flex-col gap-2.5">
        <div className="flex w-full flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <div className="flex items-center gap-2.5">
            <Icon name="insights/card-target" className="size-5" />
            <h2 className="text-lg leading-7 whitespace-nowrap text-ink">Coverage overview</h2>
          </div>
          <div className="flex gap-4">
            <span className="flex items-center gap-1.5">
              <span className="h-3.5 w-2 rounded bg-chart-1" />
              <span className="type-label whitespace-nowrap text-ink-muted">Caught</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-3.5 w-2 rounded border border-line-strong bg-subtle" />
              <span className="type-label whitespace-nowrap text-ink-muted">Missed</span>
            </span>
          </div>
        </div>
        <p className="text-base leading-6 text-ink">of exploited CVEs caught by fixing our top {coverage.topN ?? 500}</p>
        {coverage.footer && (
          <div className="flex items-center gap-3 border-t border-line pt-2.5">
            {coverage.footerPill && (
              <span className="type-label shrink-0 rounded-full bg-blue px-2.5 py-1 font-semibold whitespace-nowrap text-white">
                {coverage.footerPill}
              </span>
            )}
            <p className="type-label min-w-0 text-ink-muted">{coverage.footer}</p>
          </div>
        )}
      </div>
    </section>
  )
}
