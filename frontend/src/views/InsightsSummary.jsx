import { useState } from 'react'
import { AppHeader } from '../components/insights/AppHeader'
import { Sidebar } from '../components/Sidebar'
import { IconDarkContext } from '../lib/iconTheme'
import { CoverageCard } from '../components/insights/CoverageCard'
import { NextStepsPanel } from '../components/insights/NextStepsPanel'
import { CatchRatePage } from '../components/insights/CatchRatePage'
import { SeverityPage } from '../components/insights/SeverityPage'
import { VendorsPage } from '../components/insights/VendorsPage'
import { aboutData, coverage, kpis, versusPublic } from '../data/insights'

export function InsightsSummary({ onOpenFixFirst, theme = 'light', onThemeChange }) {
  const [section, setSection] = useState('summary')
  const dark = theme === 'dark'

  return (
    <IconDarkContext.Provider value={dark}>
    {/* Same shell as Fix first (theme classes, header, body spacing, sidebar) so
        nothing shifts when moving between the two pages. */}
    <div className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[640px] min-w-[1024px] flex-col bg-page font-sans`}>
      <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} />

      <div className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 wide:gap-5 wide:p-5 compact:py-3">
        <Sidebar current="insights" section={section} onSectionChange={setSection} onOpenFixFirst={onOpenFixFirst} />

        {section === 'summary' ? (
          <SummaryContent />
        ) : section === 'catch-rate' ? (
          <CatchRatePage onOpenFixFirst={onOpenFixFirst} />
        ) : section === 'severity' ? (
          <SeverityPage onOpenFixFirst={onOpenFixFirst} />
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

// The Summary section: coverage gauge and the right panel (KPIs and facts).
function SummaryContent() {
  return (
    <>
      <main className="flex h-full min-w-0 flex-1 flex-col gap-4 xl:gap-5 xl:pt-2">
        <div className="flex w-full shrink-0 flex-col items-start gap-1 xl:gap-2">
          <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">What predicts an attack</h1>
          <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
            How well our ranking spots the bugs attackers actually use.
          </p>
        </div>

        <div className="flex min-h-0 w-full flex-1">
          <CoverageCard coverage={coverage} />
        </div>
      </main>

      <NextStepsPanel kpis={kpis} versusPublic={versusPublic} aboutData={aboutData} />
    </>
  )
}
