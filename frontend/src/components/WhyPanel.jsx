import { useState } from 'react'
import { Icon } from '../lib/Icon'

function IconButton({ icon, label, onClick }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-full border border-border-subtle hover:bg-background"
    >
      <Icon name={icon} className="size-4" />
    </button>
  )
}

function RankContrast({ item }) {
  const shift = item.cvssRank - item.rank
  return (
    <div className="flex w-full items-start gap-2.5">
      <div className="relative h-24 min-w-px flex-1 overflow-hidden rounded-[20px] bg-background">
        <Icon name="hatch-cvss-card" className="absolute top-0 left-0 h-24 w-[230px]" />
        <p className="type-label absolute top-3 left-4 whitespace-nowrap text-text-secondary">CVSS would rank this</p>
        <p className="absolute top-7 left-4 text-5xl leading-[64px] font-light whitespace-nowrap text-text-secondary">
          #{item.cvssRank}
        </p>
      </div>
      <div className="relative h-24 min-w-px flex-1 overflow-hidden rounded-[20px] bg-primary">
        <Icon name="rank-ellipse" className="absolute top-[-50px] left-[93px] size-[170px]" />
        <p className="type-label absolute top-3 left-4 whitespace-nowrap text-white">We rank it</p>
        <p className="absolute top-7 left-4 text-5xl leading-[64px] font-light whitespace-nowrap text-white">#{item.rank}</p>
        {shift > 0 && (
          <span className="absolute top-14 left-[79px] flex items-center gap-1 rounded-full bg-white py-1 pr-2.5 pl-2">
            <Icon name="arrow-up-blue" className="size-3" />
            <span className="type-body-compact font-semibold whitespace-nowrap text-primary-strong">
              {shift} {shift === 1 ? 'place' : 'places'}
            </span>
          </span>
        )}
      </div>
    </div>
  )
}

function Reasons({ reasons }) {
  return (
    <div className="flex w-full flex-col gap-2">
      <div className="flex items-center gap-2">
        <p className="text-base leading-6 font-semibold whitespace-nowrap text-text-primary">Top 3 reasons</p>
        <span className="type-label rounded-full bg-background px-2 py-0.5 font-mono text-text-secondary">SHAP</span>
      </div>
      {reasons.map((r) => (
        <div key={r.label} className="flex w-full items-center gap-2.5">
          <span className="flex size-[30px] shrink-0 items-center justify-center rounded-full bg-background">
            <Icon name={r.icon} className="size-3.5" />
          </span>
          <div className="flex min-w-px flex-1 flex-col gap-[5px] overflow-hidden">
            <p className="type-body whitespace-nowrap text-text-primary">{r.label}</p>
            <div className="relative h-2 w-full shrink-0 overflow-hidden rounded-full">
              <Icon name="hatch-bar" className="absolute top-0 left-0 h-2 w-[404px]" />
              <span
                className={`absolute top-0 left-0 h-2 rounded-full ${r.tone === 'primary' ? 'bg-primary' : 'bg-inverse'}`}
                style={{ width: r.barPx }}
              />
            </div>
          </div>
          <p className="shrink-0 font-mono text-sm leading-5 tracking-label whitespace-nowrap text-text-primary">
            +{r.value.toFixed(2)}
          </p>
        </div>
      ))}
    </div>
  )
}

function GraniteExplanation({ text }) {
  return (
    <div className="flex w-full flex-col gap-2 rounded-[20px] bg-inverse px-4 py-3.5">
      <div className="flex items-center gap-2">
        <span className="flex size-[26px] items-center justify-center rounded-full bg-white">
          <Icon name="icon-idea-dark" className="size-3.5" />
        </span>
        <p className="type-body font-semibold whitespace-nowrap text-white">Granite explanation</p>
      </div>
      <p className="type-body text-white">{text}</p>
      <p className="type-label text-white">Written by IBM Granite from the CVE text. Check before acting.</p>
    </div>
  )
}

function XForce({ data, cveId }) {
  const facts = [
    ['Risk score', data.riskScore],
    ['Exploit', data.exploit],
    ['Attacks seen', data.attacksSeen],
  ]
  return (
    <div className="flex w-full flex-col gap-2 rounded-[20px] border border-dashed border-border-strong px-4 py-3">
      <div className="flex w-full items-center gap-2">
        <p className="type-body font-semibold whitespace-nowrap text-text-primary">IBM X-Force Exchange</p>
        <span className="type-label rounded-full bg-background px-2 py-0.5 whitespace-nowrap text-text-secondary">
          Stretch · sample
        </span>
        <div className="h-px min-w-px flex-1" />
        <a
          href={`https://exchange.xforce.ibmcloud.com/vulnerabilities/search/${cveId}`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1 hover:underline"
        >
          <span className="type-label whitespace-nowrap text-primary">Open</span>
          <Icon name="icon-launch" className="size-3" />
        </a>
      </div>
      <div className="flex w-full items-center gap-2 whitespace-nowrap">
        {facts.map(([label, value]) => (
          <div key={label} className="flex min-w-px flex-1 flex-col rounded-xl bg-background px-2.5 py-1.5">
            <p className="type-label text-text-secondary">{label}</p>
            <p className="text-base leading-6 font-semibold text-text-primary">{value}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

export function WhyPanel({ item, onClose, onStatusChange, onPushToLinear }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(item.cveId)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <aside className="flex h-full w-[420px] shrink-0 flex-col gap-3.5 overflow-y-auto rounded-[28px] bg-layer px-[22px] pt-[18px] pb-5 shadow-panel">
      <div className="flex w-full shrink-0 items-center gap-2">
        <Icon name="icon-ticket" className="size-4" />
        <p className="type-label whitespace-pre text-text-secondary">{`Fix-First queue  /  #${item.rank}`}</p>
        <div className="h-px min-w-px flex-1" />
        {copied && <span className="type-label text-text-secondary">Copied</span>}
        <IconButton icon="icon-copy" label="Copy CVE ID" onClick={copy} />
        <IconButton icon="icon-close" label="Close" onClick={onClose} />
      </div>

      <div className="flex shrink-0 items-center gap-3">
        <span className="flex size-12 shrink-0 items-center justify-center rounded-full bg-inverse text-base leading-6 font-semibold text-white">
          {item.vendorInitials ?? item.component.slice(0, 2).toUpperCase()}
        </span>
        <div className="flex flex-col whitespace-nowrap">
          <p className="text-[32px] leading-10 text-text-primary">{item.cveId}</p>
          <p className="type-label text-text-secondary">{item.subtitle ?? item.component}</p>
        </div>
      </div>

      <div className="flex w-full shrink-0 items-center gap-2 rounded-[20px] bg-background p-2.5">
        <label className="relative flex h-10 cursor-pointer items-center gap-1.5 rounded-xl border border-border-strong bg-layer pr-2.5 pl-3">
          <span className="type-body whitespace-nowrap text-text-primary">{item.status}</span>
          <Icon name="chevron-down-lg" className="size-3.5" />
          <select
            aria-label="Status"
            value={item.status}
            onChange={(e) => onStatusChange(item.cveId, e.target.value)}
            className="absolute inset-0 cursor-pointer opacity-0"
          >
            <option>To do</option>
            <option>In progress</option>
            <option>Done</option>
          </select>
        </label>
        <div className="h-px min-w-px flex-1" />
        <button
          type="button"
          disabled={!!item.ticket}
          onClick={() => onPushToLinear(item.cveId)}
          className="flex h-10 shrink-0 cursor-pointer items-center gap-2 rounded-full bg-primary pr-4 pl-[18px] hover:bg-primary-strong disabled:cursor-default disabled:bg-inverse"
        >
          <span className="type-body font-semibold whitespace-nowrap text-white">
            {item.ticket ? `In Linear · ${item.ticket}` : 'Push to Linear'}
          </span>
          {!item.ticket && <Icon name="arrow-up-white" className="size-4" />}
        </button>
      </div>

      <RankContrast item={item} />
      <p className="type-body shrink-0 whitespace-nowrap text-text-primary">
        CVSS would rank this #{item.cvssRank}; we rank it #{item.rank}.
      </p>

      {item.reasons && <Reasons reasons={item.reasons} />}
      {item.explanation ? (
        <GraniteExplanation text={item.explanation} />
      ) : (
        <p className="type-body rounded-[20px] bg-background px-4 py-3.5 text-text-secondary">
          Explanation not generated yet for this sample row.
        </p>
      )}
      {item.xforce && <XForce data={item.xforce} cveId={item.cveId} />}
    </aside>
  )
}
