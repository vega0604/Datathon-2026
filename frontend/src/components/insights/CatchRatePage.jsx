import { useRef } from 'react'
import { iconUrl } from '../../lib/Icon'
import { useThemedIcon } from '../../lib/iconTheme'
import { useFitHeight } from '../../lib/useFitHeight'
import { EmbeddingCard } from './EmbeddingCard'
import { Takeaway } from './ChartParts'
import { CatchRateChart } from './CatchRateChart'
import { AboutDataBox, NoteBox, SidePanel, WhatToDoCard } from './NextStepsPanel'
import { aboutData, catchRate } from '../../data/insights'

function LegendPill({ file, height, children }) {
  const themed = useThemedIcon()
  return (
    <span className="flex shrink-0 items-center gap-2 rounded-full bg-card px-3 py-1.5">
      <img alt="" src={iconUrl(themed(`insights/catch-rate/${file}`))} className="block w-5 max-w-none" style={{ height }} />
      <span className="type-label whitespace-nowrap text-ink">{children}</span>
    </span>
  )
}

// Catch rate + the embedding map (merged in from the former Model check page).
export function CatchRatePage({ onOpenFixFirst }) {
  // Never scrolls or clips: on short windows both cards shrink slightly to fit.
  const ref = useRef(null)
  useFitHeight(ref)
  return (
    <>
      <main ref={ref} className="flex h-full min-w-0 flex-1 flex-col gap-4 overflow-hidden xl:gap-5 xl:pt-2 [&>*]:[zoom:var(--fit,1)]">
        <div className="flex shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">Catch rate</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            How many exploited bugs you catch as you fix more of the list, and why the model spots them.
          </p>
        </div>

        <section className="flex min-h-0 w-full flex-1 gap-4 rounded-[32px] bg-card p-4 shadow-float xl:gap-5 xl:p-6 short:p-4">
          <div className="flex min-h-0 min-w-0 flex-[2.3] flex-col gap-4 rounded-3xl bg-page p-4 xl:p-6 short:gap-3 short:p-4">
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
          <EmbeddingCard />
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
          Left: each line shows how many exploited CVEs you catch (up) as you fix more of the list (right); higher
          and further left is better. Right: similar CVEs sit close together, and diamonds are on KEV.
        </NoteBox>
        <AboutDataBox rows={aboutData} />
      </SidePanel>
    </>
  )
}
