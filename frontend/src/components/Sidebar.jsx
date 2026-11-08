import { Icon } from '../lib/Icon'
import { totals } from '../data/queue'
import { insightsNav } from '../data/insights'

// One sidebar for every page (Figma V5 "Sidebar"), so its size, padding and the
// Upload / Fix first / Insights rows sit in exactly the same place on each page.
// `current` is 'fixFirst' or 'insights'; Insights also shows its sub-nav.

const ROW = 'flex h-[38px] w-full shrink-0 items-center gap-2 rounded-xl px-2.5 py-[9px] text-left wide:gap-2.5'
const PILL = 'type-label rounded-full px-1.5 py-0.5 wide:px-2'

function CurrentBar() {
  return <span className="h-5 w-[3px] shrink-0 rounded-[2px] bg-blue" />
}

// A top-level nav row: a plain marker when it's the current page, a button otherwise.
function NavRow({ current, onClick, children }) {
  return current ? (
    <div aria-current="page" className={`${ROW} bg-page`}>
      <CurrentBar />
      {children}
    </div>
  ) : (
    <button type="button" onClick={onClick} className={`${ROW} cursor-pointer hover:bg-page`}>
      {children}
    </button>
  )
}

function InsightsSubNav({ section, onSectionChange }) {
  return (
    <div className="flex w-full shrink-0 flex-col gap-0.5 pl-3">
      {insightsNav.map((item) => {
        const current = item.id === section
        return (
          <button
            key={item.id}
            type="button"
            aria-current={current ? 'page' : undefined}
            onClick={() => onSectionChange(item.id)}
            className={`flex w-full cursor-pointer items-center gap-2.5 rounded-xl px-2 py-1.5 text-left ${
              current ? 'bg-blue-soft' : 'hover:bg-page'
            }`}
          >
            <span className={`flex size-[26px] shrink-0 items-center justify-center rounded-[7.429px] ${item.chip}`}>
              <Icon name={item.icon} className="size-3.5" />
            </span>
            <span className={`type-body whitespace-nowrap ${current ? 'font-semibold text-blue-ink' : 'text-ink'}`}>
              {item.label}
            </span>
          </button>
        )
      })}
    </div>
  )
}

export function Sidebar({ current, section, onSectionChange, onOpenFixFirst, onOpenInsights }) {
  const onFixFirst = current === 'fixFirst'
  const onInsights = current === 'insights'
  return (
    <nav className="flex h-full w-[200px] shrink-0 flex-col gap-1 overflow-y-auto rounded-3xl bg-card px-3 py-4 shadow-float wide:w-[220px] wide:px-4 wide:py-5">
      <button
        type="button"
        className="flex h-[42px] w-full shrink-0 cursor-pointer items-center justify-center gap-2 rounded-full bg-blue px-5 hover:bg-primary-strong"
      >
        <Icon name="fixfirst/icon-plus" className="size-4" />
        <span className="text-sm leading-5 font-semibold whitespace-nowrap text-white">Upload SBOM</span>
      </button>
      <div className="h-3 shrink-0" />

      <NavRow current={onFixFirst} onClick={onOpenFixFirst}>
        <Icon name="fixfirst/nav-queue" className="size-[18px]" />
        <span className={`type-body-compact min-w-px flex-1 whitespace-nowrap text-ink ${onFixFirst ? 'font-semibold' : ''}`}>
          Fix first
        </span>
        <span className={`${PILL} bg-blue-soft text-blue-ink`} aria-label={`${totals.open} open`}>
          {totals.open}
        </span>
        <span className={`${PILL} bg-crit text-white`} aria-label={`${totals.critical} critical`}>
          {totals.critical}
        </span>
      </NavRow>

      <NavRow current={onInsights} onClick={onOpenInsights}>
        <Icon name="fixfirst/nav-target" className="size-[18px]" />
        <span className={`type-body-compact min-w-px flex-1 text-ink ${onInsights ? 'font-semibold' : ''}`}>Insights</span>
      </NavRow>

      {onInsights ? (
        <InsightsSubNav section={section} onSectionChange={onSectionChange} />
      ) : (
        <>
          <div className="h-px w-full shrink-0 bg-line" />
          <div className="min-h-3 flex-1" />
          <div className="flex w-full shrink-0 flex-col gap-2 rounded-[18px] bg-blue-soft p-4 whitespace-nowrap text-blue-ink">
            <p className="type-label">Benchmark run</p>
            <p className="text-base leading-6 font-semibold">Top 500 ready</p>
            <p className="type-label">top500.csv · 72,670 ranked</p>
          </div>
        </>
      )}
    </nav>
  )
}
