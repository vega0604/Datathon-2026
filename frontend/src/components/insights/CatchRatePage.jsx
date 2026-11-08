import { iconUrl } from '../../lib/Icon'
import { Takeaway } from './ChartParts'
import { CatchRateChart } from './CatchRateChart'
import { AboutDataBox, NoteBox, SidePanel, WhatToDoCard } from './NextStepsPanel'
import { aboutData, catchRate } from '../../data/insights'

function LegendPill({ file, height, children }) {
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <img alt="" src={iconUrl(`insights/catch-rate/${file}`)} className="block w-5 max-w-none" style={{ height }} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

export function CatchRatePage({ onOpenFixFirst }) {
  return (
    <>
      <main className="flex h-full min-w-0 flex-1 flex-col gap-4 xl:gap-5 xl:pt-2">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Catch rate</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            How many exploited bugs you catch as you fix more of the list.
          </p>
        </div>

        <section className="flex min-h-0 w-full flex-1 flex-col rounded-[32px] bg-card p-4 shadow-float xl:p-6 short:p-4">
          <div className="flex min-h-0 w-full flex-1 flex-col gap-4 overflow-hidden rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
            <h2 className="shrink-0 text-lg leading-7 text-ink xl:text-xl">{catchRate.headline}</h2>
            <div className="flex shrink-0 flex-wrap gap-2">
              {catchRate.series.map((s) => (
                <LegendPill key={s.label} file={s.legend} height={s.legendHeight}>
                  {s.label}
                </LegendPill>
              ))}
            </div>
            <div className="flex min-h-0 w-full flex-1 items-center justify-center [container-type:size]">
              <CatchRateChart series={catchRate.series} top500={catchRate.top500} />
            </div>
            <Takeaway>{catchRate.takeaway}</Takeaway>
          </div>
        </section>
      </main>

      <SidePanel>
        <WhatToDoCard onOpenFixFirst={onOpenFixFirst}>
          Work from the top of the list down. The first 0.7% you fix gives the biggest gain.
        </WhatToDoCard>
        <NoteBox
          title="How to read this"
          icon="insights/catch-rate/howto-eye"
          boxClass="bg-green-soft"
          chipClass="bg-card"
          titleClass="text-green-ink"
        >
          Each line shows how many exploited CVEs you catch (up) as you fix more of the list (right). Higher and
          further left is better.
        </NoteBox>
        <AboutDataBox rows={aboutData} />
      </SidePanel>
    </>
  )
}
