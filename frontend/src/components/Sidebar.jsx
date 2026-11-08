import { Icon } from '../lib/Icon'
import { totals } from '../data/queue'
import { insightsNav } from '../data/insights'

// One sidebar for every page (Figma V5 "Sidebar"), so its size, padding and the
// Upload / Fix first / Insights rows sit in exactly the same place on each page.
// `current` is 'fixFirst', 'insights' or 'software'. Insights also shows its
// sub-nav; Your software shows the uploaded SBOM and the last-upload card.
// Below 1200px wide (`narrow:`) it collapses to an icon rail: labels stay in the
// page for screen readers (sr-only) and show as tooltips.

const ROW = 'flex h-[38px] w-full shrink-0 items-center gap-2 rounded-xl px-2.5 py-[9px] text-left wide:gap-2.5 short:h-[34px] short:py-1.5 narrow:justify-center narrow:px-0'
const PILL = 'type-label rounded-full px-1.5 py-0.5 wide:px-2 narrow:hidden'

function CurrentBar() {
  return <span className="h-5 w-[3px] shrink-0 rounded-[2px] bg-blue narrow:hidden" />
}

// A top-level nav row: a plain marker when it's the current page, a button otherwise.
function NavRow({ current, onClick, title, children }) {
  return current ? (
    <div aria-current="page" title={title} className={`${ROW} bg-page`}>
      <CurrentBar />
      {children}
    </div>
  ) : (
    <button type="button" onClick={onClick} title={title} className={`${ROW} cursor-pointer hover:bg-page`}>
      {children}
    </button>
  )
}

function InsightsSubNav({ section, onSectionChange }) {
  return (
    <div className="flex w-full shrink-0 flex-col gap-0.5 pl-3 narrow:pl-0">
      {insightsNav.map((item) => {
        const current = item.id === section
        return (
          <button
            key={item.id}
            type="button"
            aria-current={current ? 'page' : undefined}
            onClick={() => onSectionChange(item.id)}
            title={item.label}
            className={`flex w-full cursor-pointer items-center gap-2.5 rounded-xl px-2 py-1.5 text-left short:py-1 narrow:justify-center narrow:px-0 ${
              current ? 'bg-blue-soft' : 'hover:bg-page'
            }`}
          >
            <span className={`flex size-[26px] shrink-0 items-center justify-center rounded-[7.429px] ${item.chip}`}>
              <Icon name={item.icon} className="size-3.5" />
            </span>
            <span className={`type-body whitespace-nowrap narrow:sr-only ${current ? 'font-semibold text-blue-ink' : 'text-ink'}`}>
              {item.label}
            </span>
          </button>
        )
      })}
    </div>
  )
}

// The "Your software" list: shown on every page so saved uploads are always one click away.
function SoftwareNav({ library = [], currentId, uploading, onSelect, onRemove }) {
  return (
    <>
      <div className="h-px w-full shrink-0 bg-line" />
      <p className="type-label shrink-0 pt-3 pb-1 pl-2.5 text-ink-muted short:pt-2 narrow:sr-only">Your software</p>
      {/* Saved uploads (kept in this browser between visits). */}
      <div className="flex min-h-0 w-full shrink flex-col gap-0.5 overflow-y-auto narrow:pt-2">
        {uploading && (
          <p className="flex w-full shrink-0 items-center gap-2 rounded-[10px] bg-page px-2.5 py-[7px]">
            <Icon name="software/dot-blue" className="size-2 animate-pulse" />
            <span className="type-body-compact min-w-px flex-1 font-semibold text-ink narrow:sr-only">{uploading.name}</span>
            <span className="type-label text-ink-muted narrow:hidden">…</span>
          </p>
        )}
        {library.map((s) => {
          const current = !uploading && s.id === currentId
          return (
            <div key={s.id} className={`group flex w-full shrink-0 items-center rounded-[10px] ${current ? 'bg-page' : 'hover:bg-page'}`}>
              <button
                type="button"
                aria-current={current ? 'page' : undefined}
                onClick={() => onSelect(s.id)}
                title={`${s.name} · ${s.components.length} components`}
                className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 py-[7px] pl-2.5 text-left short:py-1 narrow:justify-center narrow:pl-0"
              >
                <Icon name="software/dot-blue" className="size-2" />
                <span className={`type-body-compact min-w-px flex-1 text-ink narrow:sr-only ${current ? 'font-semibold' : ''}`}>{s.name}</span>
                <span className="type-label font-mono text-ink-muted narrow:hidden">{s.components.length}</span>
              </button>
              <button
                type="button"
                onClick={() => onRemove(s.id)}
                aria-label={`Remove ${s.name}`}
                title="Remove from this list"
                className="mr-1 flex size-6 shrink-0 cursor-pointer items-center justify-center rounded-full text-ink-muted opacity-0 group-hover:opacity-100 hover:bg-subtle hover:text-ink focus-visible:opacity-100 narrow:hidden"
              >
                ×
              </button>
            </div>
          )
        })}
      </div>
      {!library.length && !uploading && <p className="shrink-0 px-2.5 py-1.5 text-[13px] text-ink-muted narrow:sr-only">Nothing uploaded yet</p>}
    </>
  )
}

function LastUploadCard({ library = [], uploading }) {
  const latest = uploading ?? library[0]
  return (
    <>
      {latest?.uploadedAt && (
        <div className="flex w-full shrink-0 flex-col gap-2 rounded-[18px] bg-blue-soft p-4 text-blue-ink narrow:hidden">
          <p className="type-label">Last upload</p>
          <p className="text-base leading-6 font-semibold">{latest.components.length} components</p>
          <p className="type-label">
            <span className="[overflow-wrap:anywhere]">{latest.fileName}</span>
            <span className="whitespace-nowrap"> · {new Date(latest.uploadedAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}</span>
          </p>
        </div>
      )}
    </>
  )
}

export function Sidebar({ current, section, onSectionChange, onOpenFixFirst, onOpenInsights, onUpload, software }) {
  const onFixFirst = current === 'fixFirst'
  const onInsights = current === 'insights'
  return (
    <nav aria-label="Main" className="flex h-full w-[200px] shrink-0 flex-col gap-1 overflow-y-auto rounded-3xl bg-card px-3 py-4 shadow-float wide:w-[220px] wide:px-4 wide:py-5 short:py-3 narrow:w-[68px] narrow:px-2.5">
      <button
        type="button"
        onClick={onUpload}
        title="Upload SBOM"
        className="flex h-[42px] w-full shrink-0 cursor-pointer items-center justify-center gap-2 rounded-full bg-blue px-5 hover:bg-primary-strong short:h-[38px] narrow:px-0"
      >
        <Icon name="fixfirst/icon-plus" className="size-4" />
        <span className="text-sm leading-5 font-semibold whitespace-nowrap text-white narrow:sr-only">Upload SBOM</span>
      </button>
      <div className="h-3 shrink-0 short:h-2" />

      <NavRow current={onFixFirst} onClick={onOpenFixFirst} title={`Fix first · ${totals.open} open, ${totals.critical} critical`}>
        <Icon name="fixfirst/nav-queue" className="size-[18px]" />
        <span className={`type-body-compact min-w-px flex-1 whitespace-nowrap text-ink narrow:sr-only ${onFixFirst ? 'font-semibold' : ''}`}>
          Fix first
        </span>
        <span className={`${PILL} bg-blue-soft text-blue-ink`} aria-label={`${totals.open} open`}>
          {totals.open}
        </span>
        <span className={`${PILL} bg-crit text-white`} aria-label={`${totals.critical} critical`}>
          {totals.critical}
        </span>
      </NavRow>

      <NavRow current={onInsights} onClick={onOpenInsights} title="Insights">
        <Icon name="fixfirst/nav-target" className="size-[18px]" />
        <span className={`type-body-compact min-w-px flex-1 text-ink narrow:sr-only ${onInsights ? 'font-semibold' : ''}`}>Insights</span>
      </NavRow>

      {onInsights && <InsightsSubNav section={section} onSectionChange={onSectionChange} />}
      <SoftwareNav {...software} />
      <div className="min-h-3 flex-1" />
      {current === 'software' && <LastUploadCard {...software} />}
      {onFixFirst && (
        <div className="flex w-full shrink-0 flex-col gap-2 rounded-[18px] bg-blue-soft p-4 whitespace-nowrap text-blue-ink narrow:hidden">
          <p className="type-label">Benchmark run</p>
          <p className="text-base leading-6 font-semibold">Top 500 ready</p>
          <p className="type-label">top500.csv · 72,670 ranked</p>
        </div>
      )}
    </nav>
  )
}
