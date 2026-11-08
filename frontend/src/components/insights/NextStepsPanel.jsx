import { Icon } from '../../lib/Icon'
import { KpiSummary } from './KpiSummary'

/** Right-hand column shared by the Insights pages. */
export function SidePanel({ children, scroll = true }) {
  return (
    <aside className={`flex h-full w-[272px] shrink-0 flex-col gap-4 ${scroll ? 'overflow-y-auto' : 'overflow-hidden'} rounded-3xl bg-card p-4 shadow-float xl:w-[300px] xl:gap-5 xl:p-5 2xl:w-[320px] 2xl:p-6 short:gap-3 short:p-4`}>
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

/** Compact "What to do" call to action. */
export function WhatToDoCard({ onOpenFixFirst, children }) {
  return (
    <div className="relative flex w-full shrink-0 flex-col items-start gap-3 overflow-hidden rounded-3xl bg-blue p-4">
      <Icon name="insights/todo-deco-1" className="absolute top-[-170px] left-[140px] size-[260px]" />
      <Icon name="insights/todo-deco-4" className="absolute top-[22px] left-[200px] size-1.5" />

      <span className="type-label relative rounded-full border border-white px-3 py-1 whitespace-nowrap text-white">
        What to do
      </span>
      <p className="type-body relative text-white">{children}</p>
      <button
        type="button"
        onClick={onOpenFixFirst}
        className="relative cursor-pointer rounded-full bg-white px-4 py-2 text-sm leading-5 font-semibold whitespace-pre text-blue hover:bg-blue-soft"
      >
        {'Open Fix first  →'}
      </button>
    </div>
  )
}

export function AboutDataBox({ rows }) {
  return (
    <FactBox
      title="About this data"
      icon="insights/about-queue"
      boxClass="border border-line bg-subtle"
      chipClass="bg-blue-soft"
      titleClass="text-ink"
      rows={rows}
    />
  )
}

/** Right-hand panel for the Summary page. */
export function NextStepsPanel({ kpis, versusPublic, aboutData }) {
  return (
    // Sized to fit down to the 640px minimum height, so no scrolling.
    <SidePanel scroll={false}>
      <KpiSummary kpis={kpis} />
      <FactBox
        title="Versus public scores"
        icon="insights/versus-target"
        boxClass="bg-green-soft"
        chipClass="bg-card"
        titleClass="text-green-ink"
        rows={versusPublic}
      />
      <AboutDataBox rows={aboutData} />
    </SidePanel>
  )
}
