import { Icon } from '../lib/Icon'
import { totals } from '../data/queue'

function TopTicketCard({ item, onOpen }) {
  return (
    <div className="relative h-[188px] w-[280px] shrink-0 overflow-hidden rounded-[28px] bg-primary shadow-card">
      <Icon name="deco-ring-1" className="absolute top-[-180px] left-[140px] size-[260px]" />
      <Icon name="deco-ring-2" className="absolute top-[60px] left-[-120px] size-[320px]" />
      <Icon name="deco-dot" className="absolute top-[30px] left-[190px] size-1.5" />
      <Icon name="deco-dot" className="absolute top-[100px] left-6 size-1.5" />

      <span className="absolute top-5 left-5 flex items-center gap-1.5 rounded-full border border-white py-[5px] pr-3 pl-2.5">
        <Icon name="icon-ticket-white" className="size-3.5" />
        <span className="type-label whitespace-nowrap text-white">Fix first</span>
      </span>
      <button
        type="button"
        onClick={onOpen}
        aria-label={`Open ${item.cveId}`}
        className="absolute top-4 left-[220px] flex size-10 cursor-pointer items-center justify-center rounded-full border border-white hover:bg-white/10"
      >
        <Icon name="icon-arrow-up-right" className="size-[18px]" />
      </button>

      <p className="absolute top-[46px] left-5 text-[56px] leading-[64px] font-light whitespace-nowrap text-white">
        #{item.rank}
      </p>
      <span className="type-label absolute top-[66px] left-[104px] rounded-full bg-white px-3 py-1 whitespace-nowrap text-primary-strong">
        CVSS would rank it #{item.cvssRank}
      </span>
      <p className="absolute top-[142px] left-5 w-[240px] text-xl leading-7 text-white">
        Patch the {item.shortName ?? item.component} first.
      </p>
    </div>
  )
}

function RiskCard() {
  return (
    <div className="flex h-[188px] min-w-px flex-1 flex-col items-center overflow-hidden rounded-[28px] bg-layer px-2 pt-4 pb-3 shadow-card">
      <div className="flex w-full items-center gap-2">
        <span className="flex size-8 items-center justify-center rounded-full bg-background">
          <Icon name="icon-shield" className="size-4" />
        </span>
        <p className="type-body font-semibold whitespace-nowrap text-text-primary">Risk in your top 10</p>
      </div>
      <div className="relative h-32 w-[210px] shrink-0 overflow-hidden">
        <Icon name="gauge-67" className="absolute top-2 left-0 h-[106px] w-[210px]" />
        <p className="absolute top-[58px] left-[62.5px] text-[40px] leading-[64px] font-light whitespace-nowrap text-text-primary">
          67%
        </p>
        <p className="type-label absolute top-[110px] left-[37.5px] whitespace-nowrap text-text-secondary">
          of predicted exploit risk
        </p>
      </div>
    </div>
  )
}

// Decorative mini bar chart in the critical card (positions from Figma).
const BARS = [
  { left: 20, top: 152, h: 18, hatch: 'hatch-1' },
  { left: 56, top: 142, h: 28, hatch: 'hatch-2' },
  { left: 92, top: 148, h: 22, hatch: 'hatch-3' },
  { left: 128, top: 132, h: 38, hatch: 'hatch-4' },
  { left: 164, top: 138, h: 32, hatch: 'hatch-5' },
]

function CriticalCard() {
  return (
    <div className="relative h-[188px] w-64 shrink-0 overflow-hidden rounded-[28px] bg-critical shadow-card">
      <p className="type-body absolute top-5 left-5 font-semibold whitespace-nowrap text-white">Critical tickets</p>
      <p className="absolute top-10 left-5 text-[56px] leading-[64px] font-light text-white">{totals.critical}</p>
      <p className="absolute top-[74px] left-[62px] text-base leading-6 whitespace-nowrap text-white">of {totals.open}</p>
      <span className="absolute top-[18px] left-[168px] flex items-center gap-1 rounded-full bg-white py-1 pr-2.5 pl-2">
        <Icon name="icon-arrow-up-red" className="size-3" />
        <span className="type-label whitespace-nowrap text-critical-strong">{totals.criticalNew} new</span>
      </span>

      {BARS.map((b) => (
        <div key={b.left} className="absolute w-7" style={{ left: b.left, top: b.top, height: b.h }}>
          <div className="absolute inset-0 rounded-lg border border-white/70" />
          <Icon name={b.hatch} className="absolute inset-0 size-full" />
        </div>
      ))}
      <div className="absolute top-[116px] left-[200px] h-[54px] w-7 rounded-lg bg-white" />
    </div>
  )
}

export function Highlights({ topItem, onOpenTop }) {
  return (
    <div className="flex w-full shrink-0 items-start gap-4">
      <TopTicketCard item={topItem} onOpen={onOpenTop} />
      <RiskCard />
      <CriticalCard />
    </div>
  )
}
