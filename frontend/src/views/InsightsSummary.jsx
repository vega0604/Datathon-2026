import { useRef, useState } from 'react'
import { AppHeader } from '../components/insights/AppHeader'
import { Sidebar } from '../components/Sidebar'
import { IconDarkContext } from '../lib/iconTheme'
import { CoverageCard } from '../components/insights/CoverageCard'
import { KpiSummary } from '../components/insights/KpiSummary'
import { Icon } from '../lib/Icon'
import { CatchRatePage } from '../components/insights/CatchRatePage'
import { VendorsPage } from '../components/insights/VendorsPage'
import { bugTypesText, severityText } from '../data/ui'
import { SeverityChart } from '../components/insights/SeverityChart'
import { BubbleChart } from '../components/insights/BubbleChart'
import { PlotFrame } from '../components/insights/ChartParts'
import { useFitHeight } from '../lib/useFitHeight'
import { useBenchmark, useSummary } from '../lib/api'
import { InsightsState } from '../components/insights/InsightsState'

export function InsightsSummary({ onHome, onOpenFixFirst, onUpload, software, totals, theme = 'light', onThemeChange }) {
  const [section, setSection] = useState('summary')
  const dark = theme === 'dark'

  return (
    <IconDarkContext.Provider value={dark}>
    {/* Same shell as Fix first (theme classes, header, body spacing, sidebar) so
        nothing shifts when moving between the two pages. */}
    <div className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[560px] min-w-[1024px] flex-col bg-page font-sans`}>
      <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} onHome={onHome} />

      <div className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 wide:gap-5 wide:p-5 compact:py-3">
        <Sidebar current="insights" section={section} onSectionChange={setSection} onOpenFixFirst={onOpenFixFirst} onUpload={onUpload} software={software} totals={totals} />

        {section === 'summary' ? (
          <SummaryContent />
        ) : section === 'catch-rate' ? (
          <CatchRatePage />
        ) : section === 'vendors' ? (
          <VendorsPage />
        ) : (
          // Other Insights sections are intentionally empty for now.
          <main className="h-full min-w-0 flex-1" aria-label={section} />
        )}
      </div>
    </div>
    </IconDarkContext.Provider>
  )
}

const fmt = (n) => n.toLocaleString('en-US')

function kpisFrom(s) {
  const { benchmark_cves: cves, nist_unreviewed: unreviewed, nist_unreviewed_share_this_year: share } = s.kpis
  const top = s.coverage.top_n
  const picked = (top / cves) * 100
  return [
    { id: 'benchmark', icon: 'insights/kpi-queue', label: 'Benchmark CVEs', value: fmt(cves), pill: `Top ${top} submitted`,
      share: { pct: picked, caption: `${top} of ${fmt(cves)} picked · ${picked.toFixed(1)}%`, tone: 'bg-chart-1' } },
    { id: 'nist', icon: 'insights/kpi-eye', label: 'Not reviewed by NIST', value: fmt(unreviewed), pill: `${Math.round(share * 100)}% of 2026`,
      share: { pct: share * 100, caption: `${Math.round(share * 100)}% of 2026 CVEs still unreviewed`, tone: 'bg-chart-2' } },
  ]
}

function coverageFrom(s) {
  const caught = s.coverage.caught_share
  const best = s.versus_public.best_public_caught_share
  const ratio = best ? caught / best : null
  const picked = ((s.coverage.top_n / s.kpis.benchmark_cves) * 100).toFixed(1)
  return {
    caughtPct: Math.round(caught * 100),
    footer:
      ratio && ratio > 1
        ? `Fixing ${picked}% of the queue beats every public baseline (${s.coverage.backtest_year} backtest)`
        : `Fixing ${picked}% of the queue (${s.coverage.backtest_year} backtest)`,
    footerPill: ratio ? `↗ ${ratio.toFixed(1)}× baseline` : null,
  }
}

// The Summary section: one page with the headline results. Coverage gauge and
// weakness types on the left, severity-vs-exploitation and the KPIs on the right.
function SummaryContent() {
  const summary = useSummary()
  const benchmark = useBenchmark()
  return <InsightsState query={summary}>{(s) => <SummaryBody s={s} benchmark={benchmark.data} />}</InsightsState>
}

function SummaryBody({ s, benchmark }) {
  // Never scrolls or clips: on short windows the charts shrink slightly to fit.
  const ref = useRef(null)
  useFitHeight(ref)
  const about = benchmark
    ? [
        ['Trained on', `${benchmark.train_years.join(', ')} CVEs`],
        ['Tested on', `${benchmark.test_years.join(', ')} CVEs`],
        ['CVEs scored', fmt(benchmark.cves_scored)],
      ]
    : []
  return (
      <main ref={ref} className="flex h-full min-w-0 flex-1 flex-col gap-5 overflow-hidden xl:pt-2 [&>*]:[zoom:var(--fit,1)]">
        <div className="flex w-full shrink-0 items-end justify-between gap-6">
          <div className="flex min-w-0 flex-col items-start gap-1 xl:gap-2">
            <h1 className="text-[clamp(30px,3vw,44px)] leading-[1.18] font-light text-ink">What predicts an attack</h1>
            <p className="text-sm leading-5 text-ink-muted xl:text-base xl:leading-6">
              How well our ranking spots the bugs attackers actually use.
            </p>
          </div>
          {about.length > 0 && <AboutStrip rows={about} />}
        </div>

        {/* Two columns: gauge over the weakness chart on the left; the severity chart
            and the public-score comparison on the right. */}
        <div className="flex min-h-0 w-full flex-1 gap-5">
          <div className="flex min-h-0 min-w-0 flex-[1.25] flex-col gap-5">
            <CoverageCard coverage={coverageFrom(s)} />
            <section className={`${summaryCard} flex-1`}>
              <ChartHead title={bugTypesText.title} subtitle={bugTypesText.subtitle} />
              <BubbleChart weaknesses={s.weaknesses} minH="min-h-[110px]" />
            </section>
          </div>

          <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-5">
            <section className={`${summaryCard} flex-1`}>
              <ChartHead title={severityText.title} subtitle={severityText.subtitle} />
              <PlotFrame minH="min-h-[140px]">
                <SeverityChart bands={s.severity_bands} />
              </PlotFrame>
            </section>
            <div className="flex w-full shrink-0 gap-5">
              <KpiSummary kpis={kpisFrom(s)} />
            </div>
          </div>
        </div>
      </main>
  )
}

const summaryCard = 'flex min-h-0 min-w-0 basis-0 flex-col gap-4 rounded-[28px] bg-card p-6 shadow-float short:p-5'

// "About this data" as one compact strip beside the page title.
function AboutStrip({ rows }) {
  return (
    <div className="flex shrink-0 items-center gap-5 rounded-[20px] bg-purple-soft px-4 py-2.5">
      <div className="flex items-center gap-2.5">
        <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-card">
          <Icon name="insights/about-data" className="size-[15px]" />
        </span>
        <p className="type-body font-semibold whitespace-nowrap text-purple-ink">About this data</p>
      </div>
      {rows.map(([label, value]) => (
        <div key={label} className="flex flex-col whitespace-nowrap">
          <span className="type-label text-ink-muted">{label}</span>
          <span className="type-body font-semibold text-ink">{value}</span>
        </div>
      ))}
    </div>
  )
}

function ChartHead({ title, subtitle }) {
  return (
    <div className="flex shrink-0 flex-col gap-1">
      <h2 className="text-lg leading-7 text-ink short:text-base short:leading-6">{title}</h2>
      <p className="type-label text-ink-muted">{subtitle}</p>
    </div>
  )
}
