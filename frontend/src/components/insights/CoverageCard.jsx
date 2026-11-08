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
      className="block h-full max-h-[292px] w-full max-w-[420px] font-sans"
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
            className={i < filled ? 'fill-blue' : 'fill-subtle'}
          />
        )
      })}
      <text x={CX} y="175" textAnchor="middle" dominantBaseline="central" className="fill-ink text-[72px] font-light">
        {pct}%
      </text>
      <text x={CX} textAnchor="middle" className="fill-ink-muted text-sm tracking-body">
        <tspan x={CX} y="234">of exploited CVEs caught</tspan>
        <tspan x={CX} y="254">by fixing our top 500</tspan>
      </text>
    </svg>
  )
}

export function CoverageCard({ coverage }) {
  return (
    <section className="flex h-full min-w-0 flex-1 flex-col gap-4 overflow-hidden rounded-[28px] bg-card p-5 shadow-float xl:p-7">
      <div className="flex w-full shrink-0 items-center gap-2.5">
        <Icon name="insights/card-target" className="size-5" />
        <h2 className="min-w-px flex-1 text-lg leading-7 text-ink xl:text-xl">Coverage overview</h2>
      </div>
      <div className="flex min-h-0 w-full flex-1 items-center justify-center">
        <SegmentedGauge pct={coverage.caughtPct} />
      </div>
      <div className="flex w-full shrink-0 justify-center gap-4">
        <span className="flex items-center gap-1.5">
          <span className="h-3.5 w-2 rounded bg-blue" />
          <span className="type-label whitespace-nowrap text-ink-muted">Caught (filled)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-3.5 w-2 rounded border border-line-strong bg-subtle" />
          <span className="type-label whitespace-nowrap text-ink-muted">Missed (empty)</span>
        </span>
      </div>
    </section>
  )
}
