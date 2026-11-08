import { Icon } from '../../lib/Icon'
import { insightsNav } from '../../data/insights'
import { totals } from '../../data/queue'

export function InsightsSidebar({ section, onSectionChange, onOpenFixFirst }) {
  return (
    <nav className="flex h-full w-[200px] shrink-0 flex-col gap-1 overflow-y-auto rounded-3xl bg-card px-3 py-4 shadow-float xl:w-[220px] xl:px-4 xl:py-5">
      <button
        type="button"
        className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-full bg-blue px-5 py-[11px] hover:bg-blue-ink"
      >
        <Icon name="insights/icon-plus" className="size-4" />
        <span className="text-sm leading-5 font-semibold whitespace-nowrap text-white">Upload SBOM</span>
      </button>
      <div className="h-3 shrink-0" />

      <button
        type="button"
        onClick={onOpenFixFirst}
        className="flex h-[38px] w-full cursor-pointer items-center gap-2.5 rounded-xl px-2.5 py-[9px] text-left hover:bg-page"
      >
        <Icon name="insights/nav-queue" className="size-[18px]" />
        <span className="type-body-compact min-w-px flex-1 text-ink">Fix first</span>
        <span className="type-label rounded-full bg-blue-soft px-2 py-0.5 text-blue-ink">{totals.open}</span>
        <span className="type-label rounded-full bg-crit px-2 py-0.5 text-white">{totals.critical}</span>
      </button>

      <div aria-current="page" className="flex h-[38px] w-full items-center gap-2.5 rounded-xl bg-page px-2.5 py-[9px]">
        <span className="h-5 w-[3px] shrink-0 rounded-[2px] bg-blue" />
        <Icon name="insights/nav-target" className="size-[18px]" />
        <span className="type-body-compact min-w-px flex-1 font-semibold text-ink">Insights</span>
      </div>

      <div className="flex w-full flex-col gap-0.5 pl-3">
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
              <span
                className={`type-body whitespace-nowrap ${current ? 'font-semibold text-blue-ink' : 'text-ink'}`}
              >
                {item.label}
              </span>
            </button>
          )
        })}
      </div>
    </nav>
  )
}
