import { useRef } from 'react'
import { Icon } from '../../lib/Icon'
import { useFitHeight } from '../../lib/useFitHeight'
import { BlueCard } from '../software/SoftwareParts'
import { KpiSummary } from './KpiSummary'

/** Right-hand column shared by the Insights pages. */
// Never scrolls: on short windows its boxes shrink slightly to fit (useFitHeight).
export function SidePanel({ children }) {
  const ref = useRef(null)
  useFitHeight(ref)
  return (
    <aside ref={ref} className="flex h-full w-[272px] shrink-0 flex-col gap-4 overflow-hidden rounded-3xl bg-card p-4 shadow-float xl:w-[300px] xl:gap-5 xl:p-5 2xl:w-[320px] 2xl:p-6 short:gap-3 short:p-4 [&>*]:[zoom:var(--fit,1)]">
      {children}
    </aside>
  )
}

function BoxHead({ title, icon, chipClass, titleClass }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className={`flex size-7 shrink-0 items-center justify-center rounded-lg ${chipClass}`}>
        <Icon name={icon} className="size-[15px]" />
      </span>
      <p className={`text-base leading-6 font-semibold whitespace-nowrap ${titleClass}`}>{title}</p>
    </div>
  )
}

const boxBase = 'flex w-full shrink-0 flex-col gap-2 rounded-[20px] p-4 xl:gap-2.5 xl:p-5 short:gap-1.5 short:p-3.5'

/** A titled box with label/value rows. */
export function FactBox({ title, icon, chipClass, boxClass, titleClass, rows }) {
  return (
    <div className={`${boxBase} ${boxClass}`}>
      <BoxHead title={title} icon={icon} chipClass={chipClass} titleClass={titleClass} />
      {rows.map(([label, value]) => (
        <div key={label} className="type-body flex w-full items-center gap-2">
          <span className="min-w-px flex-1 text-ink-muted">{label}</span>
          <span className="font-semibold whitespace-nowrap text-ink">{value}</span>
        </div>
      ))}
    </div>
  )
}

/** A titled box with a short paragraph. */
export function NoteBox({ title, icon, chipClass, boxClass, titleClass, children }) {
  return (
    <div className={`${boxBase} ${boxClass}`}>
      <BoxHead title={title} icon={icon} chipClass={chipClass} titleClass={titleClass} />
      <p className="type-body text-ink">{children}</p>
    </div>
  )
}

/**
 * "What to do" call to action. Same full-height card as the Your software screens
 * (Figma: Card · What to do · blue): it grows to fill the spare height of the side
 * panel, text at the top, button at the bottom.
 */
export function WhatToDoCard({ onOpenFixFirst, children }) {
  return (
    <BlueCard action={'Open Fix first  →'} onAction={onOpenFixFirst}>
      {children}
    </BlueCard>
  )
}

export function AboutDataBox({ rows, chipClass = 'bg-card' }) {
  return (
    <FactBox
      title="About this data"
      icon="insights/about-data"
      // Purple in both themes, as in Figma (ai/soft background, ai/strong-text title).
      boxClass="bg-purple-soft"
      chipClass={chipClass}
      titleClass="text-purple-ink"
      rows={rows}
    />
  )
}

/** Right-hand panel for the Summary page. */
export function NextStepsPanel({ kpis, aboutData }) {
  return (
    // Sized to fit down to the 640px minimum height, so no scrolling.
    <SidePanel>
      <KpiSummary kpis={kpis} />
      <AboutDataBox rows={aboutData} chipClass="bg-card" />
    </SidePanel>
  )
}
