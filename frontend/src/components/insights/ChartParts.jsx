import { Icon, iconUrl } from '../../lib/Icon'

/**
 * Returns a helper that turns a box in design pixels (on a W×H Figma plot)
 * into a percentage style, so the plot scales as one unit.
 */
export function plotBox(W, H) {
  return (x, y, w, h) => ({
    left: `${(x / W) * 100}%`,
    top: `${(y / H) * 100}%`,
    width: w == null ? undefined : `${(w / W) * 100}%`,
    height: h == null ? undefined : `${(h / H) * 100}%`,
  })
}

/** Text sizes for chart labels, in em so they scale with the plot (1em = 12px at full size). */
export const chartText = {
  label: 'text-[1em] leading-[1.333em] tracking-label whitespace-nowrap',
  value: 'text-[1.1667em] leading-[1.5em] tracking-body font-semibold whitespace-nowrap',
}

/** Shrinks its child plot to fit both the available width and height. */
export function PlotFrame({ children, minH = 'min-h-[240px]' }) {
  // min-h keeps labels legible on short screens. Summary passes a smaller one: its
  // grid shrinks as a whole (useFitHeight) instead of scrolling.
  return (
    <div className={`flex w-full flex-1 items-center justify-center [container-type:size] ${minH}`}>{children}</div>
  )
}

/**
 * Plot surface sized to fit its PlotFrame while keeping the design's W×H aspect ratio.
 * Its font size scales with its width so em-based labels shrink with it.
 */
export function PlotSurface({ width, height, children }) {
  return (
    <div
      className="relative [container-type:inline-size]"
      style={{ aspectRatio: `${width} / ${height}`, width: `min(100cqw, calc(100cqh * ${width} / ${height}))` }}
    >
      <div className="absolute inset-0" style={{ fontSize: `clamp(8px, ${(12 / width) * 100}cqw, 12px)` }}>
        {children}
      </div>
    </div>
  )
}

/** Figma-exported chart graphic. */
export function ChartImg({ file, style, className = '' }) {
  return <img alt="" src={iconUrl(file)} className={`absolute block max-w-none ${className}`} style={style} />
}

/**
 * "Insights/Takeaway": the one-sentence takeaway that closes every insight chart.
 * tone: 'blue' (default), 'purple' (soft purple box) or 'ai' (white box on a purple card).
 */
// size 'sm' is the compact version used on Summary, where several charts share the page.
export function Takeaway({ tone = 'blue', size = 'md', children }) {
  const bg = { blue: 'bg-blue-soft', purple: 'bg-purple-soft', ai: 'bg-card' }[tone]
  const ai = tone === 'ai'
  return (
    <div className={`flex w-full shrink-0 items-start gap-3 rounded-xl ${size === 'sm' ? 'p-3.5' : 'p-4 short:p-3'} ${bg}`}>
      <Icon name={ai ? 'insights/model/takeaway-idea-purple' : 'insights/catch-rate/takeaway-idea'} className="size-4" />
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className={`type-label ${ai ? 'text-purple-ink' : 'text-blue-ink'}`}>Takeaway</span>
        <p className={size === 'sm' ? 'text-sm leading-5 text-ink' : 'text-base leading-6 text-ink short:text-sm short:leading-5'}>{children}</p>
      </div>
    </div>
  )
}
