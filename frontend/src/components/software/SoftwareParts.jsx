import { useRef } from 'react'
import { Icon } from '../../lib/Icon'
import { useFitHeight } from '../../lib/useFitHeight'

// Shared pieces for the "Your software" screens (Figma page V5, "Your software · …").

const SEV = {
  critical: { label: 'Critical', bg: 'bg-critical-soft', icon: 'software/sev-critical', bar: 'bg-sev-critical' },
  high: { label: 'High', bg: 'bg-high-soft', icon: 'software/sev-high', bar: 'bg-sev-high' },
  medium: { label: 'Medium', bg: 'bg-medium-soft', icon: 'software/sev-medium', bar: 'bg-sev-medium' },
  low: { label: 'Low', bg: 'bg-subtle', icon: 'insights/severity/status-low', bar: 'bg-sev-low' },
  none: { label: 'None', bg: 'bg-green-soft', icon: 'software/sev-none', bar: 'bg-track' },
}
export const sevBar = (s) => SEV[s]?.bar ?? 'bg-track'

/** Severity pill: always a shape plus a label, never colour alone. */
export function SevPill({ severity }) {
  if (!severity)
    return <span className="rounded-full bg-subtle px-2.5 py-0.5 text-xs whitespace-nowrap text-ink-muted">Not checked</span>
  const s = SEV[severity]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full py-0.5 pr-2.5 pl-2 ${s.bg}`}>
      <Icon name={s.icon} className="size-3" />
      <span className="text-xs font-medium whitespace-nowrap text-ink">{s.label}</span>
    </span>
  )
}

/** Stacked severity mix bar (critical → low), widths proportional to counts. */
export function SevMix({ sev, width = 231 }) {
  const total = Object.values(sev).reduce((a, b) => a + b, 0) || 1
  return (
    <span className="flex gap-0.5" style={{ width }} aria-hidden="true">
      {['critical', 'high', 'medium', 'low'].map((k) =>
        sev[k] ? <span key={k} className={`h-2.5 rounded-[3px] ${sevBar(k)}`} style={{ width: `${(sev[k] / total) * 100}%` }} /> : null,
      )}
    </span>
  )
}

const SHORT = { critical: 'crit', high: 'high', medium: 'med', low: 'low' }
export const sevText = (sev, short = false) =>
  ['critical', 'high', 'medium', 'low']
    .filter((k) => sev[k])
    .map((k) => `${sev[k].toLocaleString()} ${short ? SHORT[k] : k}`)
    .join(' · ')

export function FoundBy({ component }) {
  if (!component.cpe)
    return (
      <span className="rounded-full border border-dashed border-ai bg-purple-soft px-2 py-0.5 text-xs font-medium whitespace-nowrap text-purple-ink" title="No CPE name in your SBOM. Granite would read CVE text to find matches; that step isn’t run in this demo.">
        ✦ Needs Granite
      </span>
    )
  return <span className="rounded-full bg-blue-soft px-2 py-0.5 text-xs font-medium whitespace-nowrap text-blue-ink">NIST list</span>
}

/** Big blue "What to do" card from the Figma right panels. */
export function BlueCard({ children, action, onAction, grow = true }) {
  // No overflow-hidden on the card itself: it must never shrink below its text.
  return (
    <div className={`relative flex w-full flex-col justify-between gap-4 rounded-3xl bg-brand p-6 ${grow ? 'flex-1' : 'shrink-0'}`}>
      <div className="relative flex flex-col items-start gap-4">
        <span className="type-label rounded-full border border-white px-3 py-1.5 text-white">What to do</span>
        <p className="text-xl leading-7 text-white">{children}</p>
      </div>
      {action && (
        <button
          type="button"
          onClick={onAction}
          className="relative cursor-pointer self-start rounded-full bg-on-brand px-5 py-3 text-left text-base leading-6 font-semibold text-primary-strong hover:bg-on-brand-hover"
        >
          {action}
        </button>
      )}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden rounded-3xl">
        <Icon name="software/deco-ring-lg" className="absolute top-[-120px] left-[150px] size-[260px]" />
        <Icon name="software/deco-ring-sm" className="absolute top-[120px] left-[-70px] size-[160px]" />
        <Icon name="software/deco-dot-8" className="absolute top-[208px] left-[220px] size-2" />
        <Icon name="software/deco-dot-6" className="absolute top-[248px] left-[248px] size-1.5" />
      </div>
    </div>
  )
}

/** Tinted box with a chip icon and title (right panels). */
export function SideBox({ tone = 'teal', icon, title, children }) {
  const t = {
    // Chips go light in dark mode so the coloured icons keep strong contrast.
    teal: ['bg-green-soft', 'bg-card dark:bg-[#e9ecf3]', 'text-green-ink'],
    purple: ['bg-purple-soft', 'bg-card dark:bg-[#e9ecf3]', 'text-purple-ink'],
    grey: ['border border-line bg-subtle', 'bg-blue-soft dark:bg-[#e9ecf3]', 'text-ink'],
    red: ['bg-critical-soft', 'bg-card dark:bg-[#e9ecf3]', 'text-ink'],
  }[tone]
  return (
    <div className={`flex w-full shrink-0 flex-col gap-2.5 rounded-[20px] px-5 py-[18px] compact:gap-2 compact:px-4 compact:py-3.5 ${t[0]}`}>
      <div className="flex items-center gap-2.5">
        <span className={`flex size-7 shrink-0 items-center justify-center rounded-lg ${t[1]}`}>
          <Icon name={icon} className="size-[15px]" />
        </span>
        <p className={`text-base font-semibold whitespace-nowrap ${t[2]}`}>{title}</p>
      </div>
      {children}
    </div>
  )
}

export function FactRow({ label, value }) {
  return (
    <div className="flex w-full items-center gap-2 text-sm leading-5">
      <span className="min-w-px flex-1 text-ink-muted">{label}</span>
      <span className="text-right font-semibold whitespace-nowrap text-ink">{value}</span>
    </div>
  )
}

/** Right-hand column shared by every "Your software" screen. */
// Never scrolls: on short windows its sections shrink slightly instead (useFitHeight).
export function SidePanel({ children }) {
  const ref = useRef(null)
  useFitHeight(ref)
  return (
    <aside
      ref={ref}
      className="flex h-full w-[300px] shrink-0 flex-col gap-5 overflow-hidden rounded-3xl bg-card p-6 shadow-float wide:w-[320px] narrow:w-[260px] narrow:p-5 compact:gap-3 compact:p-5 [&>*]:[zoom:var(--fit,1)]"
    >
      {children}
    </aside>
  )
}

/** Main column that never scrolls or clips: shrinks its sections slightly to fit. */
export function FitMain({ className = '', children }) {
  const ref = useRef(null)
  useFitHeight(ref)
  return (
    <main ref={ref} className={`flex h-full min-w-0 flex-1 flex-col overflow-hidden pt-2 [&>*]:[zoom:var(--fit,1)] ${className}`}>
      {children}
    </main>
  )
}

export function PageTitle({ title, subtitle, children }) {
  return (
    <div className="flex w-full shrink-0 flex-col items-start gap-1.5">
      <h1 className="text-4xl leading-[44px] font-light text-ink compact:text-[32px] compact:leading-10">{title}</h1>
      {subtitle && <p className="text-[15px] text-ink-muted">{subtitle}</p>}
      {children}
    </div>
  )
}

export function Tabs({ value, onChange, items }) {
  return (
    <div role="tablist" className="flex shrink-0 gap-1 self-start rounded-full bg-subtle p-1">
      {items.map(([id, label]) => (
        <button
          key={id}
          type="button"
          role="tab"
          aria-selected={value === id}
          onClick={() => onChange(id)}
          className={`flex h-9 cursor-pointer items-center rounded-full px-[18px] text-sm whitespace-nowrap ${
            value === id ? 'bg-card font-semibold text-blue-ink' : 'text-ink-muted hover:text-ink'
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  )
}
