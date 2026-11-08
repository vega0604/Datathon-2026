import { iconUrl } from '../../lib/Icon'
import { useThemedIcon } from '../../lib/iconTheme'
import { ChartImg, PlotSurface, chartText, plotBox } from './ChartParts'

// Severity vs exploitation chart (SHE-61), shown on Insights → Summary.

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
  const themed = useThemedIcon()
  return (
    <span className="flex items-center gap-[0.333em] rounded-[1em] bg-subtle px-[0.667em] py-[0.333em]">
      <img alt="" src={iconUrl(themed(svg(`status-${band.key}`)))} className="block size-[1em] max-w-none" />
      <span className={`${chartText.label} text-[#161616] dark:text-ink`}>{band.label}</span>
    </span>
  )
}

export function SeverityChart({ bands }) {
  return (
    <PlotSurface width={SEV_W} height={SEV_H}>
      {bands.map((b, i) => {
        const bar = SEV_BARS[b.key]
        return (
          <div key={b.key}>
            <div className="absolute rounded-full bg-card" style={sevBox(bar.x, TRACK.y, 46, TRACK.h)} />
            {bar.file ? (
              <ChartImg file={svg(bar.file)} className="chart-grow-y" style={{ ...sevBox(bar.x, bar.y, 46, bar.h), '--i': i }} />
            ) : (
              <div className="chart-grow-y absolute rounded-full bg-purple" style={{ ...sevBox(bar.x, bar.y, 46, bar.h), '--i': i }} />
            )}
            {bar.labelX != null && (
              <span className={`chart-fade absolute text-ink ${chartText.value}`} style={{ ...sevBox(bar.labelX, bar.labelY), '--i': i }}>
                {b.value}
              </span>
            )}
          </div>
        )
      })}
      {/* Critical gets a callout instead of a plain label */}
      <span
        className="chart-fade absolute rounded-[1em] bg-purple-soft px-[1em] py-[0.667em] text-purple-ink"
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
