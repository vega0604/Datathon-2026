import { useRef, useState } from 'react'
import { AppHeader } from '../components/insights/AppHeader'
import { Sidebar } from '../components/Sidebar'
import { IconDarkContext } from '../lib/iconTheme'
import { CoverageCard } from '../components/insights/CoverageCard'
import { FactBox, NextStepsPanel } from '../components/insights/NextStepsPanel'
import { CatchRatePage } from '../components/insights/CatchRatePage'
import { VendorsPage } from '../components/insights/VendorsPage'
import { aboutData, bugTypes, coverage, kpis, severity, versusPublic } from '../data/insights'
import { SeverityChart } from '../components/insights/SeverityChart'
import { BubbleChart } from '../components/insights/BubbleChart'
import { PlotFrame } from '../components/insights/ChartParts'
import { useFitHeight } from '../lib/useFitHeight'

export function InsightsSummary({ onHome, onOpenFixFirst, onUpload, software, theme = 'light', onThemeChange }) {
  const [section, setSection] = useState('summary')
  const dark = theme === 'dark'

  return (
    <IconDarkContext.Provider value={dark}>
    {/* Same shell as Fix first (theme classes, header, body spacing, sidebar) so
        nothing shifts when moving between the two pages. */}
    <div className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[560px] min-w-[1024px] flex-col bg-page font-sans`}>
      <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} onHome={onHome} />

      <div className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 wide:gap-5 wide:p-5 compact:py-3">
        <Sidebar current="insights" section={section} onSectionChange={setSection} onOpenFixFirst={onOpenFixFirst} onUpload={onUpload} software={software} />

        {section === 'summary' ? (
          <SummaryContent />
        ) : section === 'catch-rate' ? (
          <CatchRatePage onOpenFixFirst={onOpenFixFirst} />
        ) : section === 'vendors' ? (
          <VendorsPage onOpenFixFirst={onOpenFixFirst} />
        ) : (
          // Other Insights sections are intentionally empty for now.
          <main className="h-full min-w-0 flex-1" aria-label={section} />
        )}
      </div>
    </div>
    </IconDarkContext.Provider>
  )
}

// The Summary section: one page with the headline results. Coverage gauge and
// weakness types on the left, severity-vs-exploitation on the right, KPIs in the
// side panel.
// (Severity and Bug types used to be separate pages; their charts live here now.)
function SummaryContent() {
  // Never scrolls or clips: on short windows the charts shrink slightly to fit.
  const ref = useRef(null)
  useFitHeight(ref)
  return (
    <>
      <main ref={ref} className="flex h-full min-w-0 flex-1 flex-col gap-5 overflow-hidden xl:pt-2 [&>*]:[zoom:var(--fit,1)]">
        <div className="flex w-full shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">What predicts an attack</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            How well our ranking spots the bugs attackers actually use.
          </p>
        </div>

        {/* Two columns: gauge over the weakness chart on the left; the severity chart
            and the public-score comparison on the right. */}
        <div className="flex min-h-0 w-full flex-1 gap-5">
          <div className="flex min-h-0 min-w-0 flex-[1.5] flex-col gap-5">
            <CoverageCard coverage={coverage} />
            <section className={`${summaryCard} flex-1`}>
              <ChartHead title={bugTypes.title} subtitle={bugTypes.subtitle} />
              <BubbleChart data={bugTypes} minH="min-h-[150px]" />
            </section>
          </div>

          <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-5">
            <section className={`${summaryCard} flex-1`}>
              <ChartHead title={severity.bands.title} subtitle={severity.bands.subtitle} />
              <PlotFrame minH="min-h-[180px]">
                <SeverityChart bands={severity.bands.items} />
              </PlotFrame>
            </section>
            {/* Moved here from the side panel so the chart column isn't left half empty. */}
            <div className="shrink-0 rounded-[28px] bg-card p-2 shadow-float">
              <FactBox
                title="Versus public scores"
                icon="insights/versus-target"
                boxClass="bg-green-soft"
                chipClass="bg-card"
                titleClass="text-green-ink"
                rows={versusPublic}
              />
            </div>
          </div>
        </div>
      </main>

      <NextStepsPanel kpis={kpis} aboutData={aboutData} />
    </>
  )
}

const summaryCard = 'flex min-h-0 min-w-0 basis-0 flex-col gap-4 rounded-[28px] bg-card p-6 shadow-float short:p-5'

function ChartHead({ title, subtitle }) {
  return (
    <div className="flex shrink-0 flex-col gap-1">
      <h2 className="text-lg leading-7 text-ink short:text-base short:leading-6">{title}</h2>
      <p className="type-label text-ink-muted">{subtitle}</p>
    </div>
  )
}
