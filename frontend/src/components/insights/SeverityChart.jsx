import { iconUrl } from '../../lib/Icon'
import { useThemedIcon } from '../../lib/iconTheme'
import { ChartImg, PlotSurface, chartText, plotBox } from './ChartParts'
import { pct, severityText } from '../../data/ui'

// Severity vs exploitation chart (SHE-61), shown on Insights → Summary.

const svg = (name) => `insights/severity/${name}`

/* ── Left chart: share reaching KEV, by CVSS band ─────────────────────────
   Figma plot is 292×291; the band labels sit underneath, so the scaled
   block is 292×347 (plot + 16px gap + 40px axis). */
const SEV_W = 292
const SEV_H = 347
const sevBox = plotBox(SEV_W, SEV_H)
const TRACK = { y: 45.55, h: 245.452 }
const BASE = TRACK.y + TRACK.h // bars stand on the track's bottom
// The tallest bar is drawn at the design's Critical height (76% of the track), which
// leaves room for the callout above it. Heights scale linearly with the KEV share.
const MAX_BAR = 186.544
// Per band: x position, the Figma bar graphic (null = solid bar) and the label's x.
const SEV_BARS = {
  critical: { x: 13.5, file: null },
  high: { x: 86.5, file: 'bar-high', labelX: 92 },
  medium: { x: 159.5, file: 'bar-medium', labelX: 165 },
  low: { x: 232.5, file: 'bar-low', labelX: 233.5 },
}
const LABEL_ABOVE = 25.44 // design gap from a bar's top to its value label
const CALLOUT_ABOVE = 51.16 // design gap from the Critical bar's top to its callout

function StatusTag({ band }) {
  const themed = useThemedIcon()
  return (
    <span className="flex items-center gap-[0.333em] rounded-[1em] bg-subtle px-[0.667em] py-[0.333em]">
      <img alt="" src={iconUrl(themed(svg(`status-${band.key}`)))} className="block size-[1em] max-w-none" />
      <span className={`${chartText.label} text-[#161616] dark:text-ink`}>{band.label}</span>
    </span>
  )
}

/** bands: the API's severity_bands ({ band, cvss_min, cvss_max, kev_share }), Critical first. */
export function SeverityChart({ bands: apiBands }) {
  const bands = apiBands
    .filter((b) => SEV_BARS[b.band])
    .map((b) => ({
      key: b.band,
      label: severityText.labels[b.band],
      range: `${b.cvss_min.toFixed(1)} to ${b.cvss_max % 1 ? b.cvss_max.toFixed(1) : b.cvss_max}`,
      value: pct(b.kev_share),
      share: b.kev_share,
    }))
  const largest = Math.max(...bands.map((b) => b.share), 1e-9)
  const height = (b) => Math.max(2, (b.share / largest) * MAX_BAR)
  const critical = bands.find((b) => b.key === 'critical')
  return (
    <PlotSurface width={SEV_W} height={SEV_H}>
      {bands.map((b, i) => {
        const bar = SEV_BARS[b.key]
        const h = height(b)
        const y = BASE - h
        return (
          <div key={b.key}>
            <div className="absolute rounded-full bg-card" style={sevBox(bar.x, TRACK.y, 46, TRACK.h)} />
            {bar.file ? (
              <ChartImg file={svg(bar.file)} className="chart-grow-y" style={{ ...sevBox(bar.x, y, 46, h), '--i': i }} />
            ) : (
              <div className="chart-grow-y absolute rounded-full bg-purple" style={{ ...sevBox(bar.x, y, 46, h), '--i': i }} />
            )}
            {bar.labelX != null && (
              <span className={`chart-fade absolute text-ink ${chartText.value}`} style={{ ...sevBox(bar.labelX, y - LABEL_ABOVE), '--i': i }}>
                {b.value}
              </span>
            )}
          </div>
        )
      })}
      {/* Critical gets a callout instead of a plain label */}
      {critical && (
        <span
          className="chart-fade absolute rounded-[1em] bg-purple-soft px-[1em] py-[0.667em] text-purple-ink"
          style={sevBox(-13.5, BASE - height(critical) - CALLOUT_ABOVE)}
        >
          <span className={chartText.value}>{critical.value} reach KEV</span>
        </span>
      )}

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
