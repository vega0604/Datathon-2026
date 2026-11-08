import { useState } from 'react'
import { Icon } from '../lib/Icon'

/**
 * Keeps a slot the same size for every row: all rows' versions are stacked in one
 * grid cell and only the selected one is visible (the rest are visibility:hidden,
 * so they take space but aren't seen, clicked or read out). The slot is always as
 * tall as the longest version, so nothing below it moves when you change rows.
 */
function Stable({ items, current, render, className = '' }) {
  return (
    <div className={`grid ${className}`}>
      {items.map((it) => (
        <div key={it.cveId} className={`col-start-1 row-start-1 min-w-0 ${it.cveId === current.cveId ? '' : 'invisible'}`}>
          {render(it)}
        </div>
      ))}
    </div>
  )
}

// Disabled while the request runs, so one click creates one issue; clickable again
// if it fails.
function LinearButton({ onPush }) {
  const [busy, setBusy] = useState(false)
  const push = async () => {
    setBusy(true)
    try {
      await onPush()
    } finally {
      setBusy(false)
    }
  }
  return (
    <button
      type="button"
      disabled={busy}
      onClick={push}
      className="flex h-10 shrink-0 cursor-pointer items-center gap-2 rounded-full bg-blue pr-4 pl-[18px] hover:bg-primary-strong disabled:cursor-wait disabled:opacity-80"
    >
      <span className="type-body font-semibold whitespace-nowrap text-white">{busy ? 'Sending…' : 'Push to Linear'}</span>
      {!busy && <Icon name="fixfirst/arrow-up-white" className="size-4" />}
    </button>
  )
}

function CloseButton({ onClose }) {
  return (
    <button
      type="button"
      aria-label="Close details"
      title="Close"
      onClick={onClose}
      className="flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-full border border-line hover:bg-page"
    >
      <Icon name="fixfirst/icon-close" className="size-4" />
    </button>
  )
}

function RankContrast({ item }) {
  const shift = item.cvssRank - item.rank
  return (
    <div className="flex w-full shrink-0 items-start gap-2.5">
      <div className="relative h-[104px] min-w-px flex-1 overflow-hidden rounded-[20px] bg-page">
        <Icon name="fixfirst/hatch-cvss-card" className="absolute top-0 left-0 h-[104px] w-[230px]" />
        <p className="type-label absolute top-3 left-4 whitespace-nowrap text-ink-muted">CVSS would rank this</p>
        <p className="absolute top-[34px] left-4 text-5xl leading-[64px] font-light whitespace-nowrap text-ink-muted">
          #{item.cvssRank}
        </p>
      </div>
      <div className="relative h-[104px] min-w-px flex-1 overflow-hidden rounded-[20px] bg-brand">
        {/* Label and shift pill share a row so a wider pill can't cover the label.
            At the design width this puts the pill exactly where Figma has it. */}
        <div className="absolute top-3 right-3 left-4 flex items-center justify-between gap-1">
          <p className="type-label whitespace-nowrap text-white">We rank it</p>
          {shift > 0 && (
            <span className="flex shrink-0 items-center gap-1 rounded-full bg-on-brand py-0.5 pr-2 pl-1.5">
              <Icon name="fixfirst/arrow-up-blue" className="size-2.5" />
              <span className="type-label font-semibold whitespace-nowrap text-primary-strong">
                {shift}
                <span className="hidden wide:inline"> {shift === 1 ? 'place' : 'places'}</span>
                <span className="sr-only wide:hidden"> {shift === 1 ? 'place' : 'places'} higher</span>
              </span>
            </span>
          )}
        </div>
        <p className="absolute top-[34px] left-4 text-5xl leading-[64px] font-light whitespace-nowrap text-white">#{item.rank}</p>
      </div>
    </div>
  )
}

// Where the plain-words text came from. Never credit Granite for text it didn't write.
const SOURCE_NOTE = {
  granite: 'Written by IBM Granite. Check before acting.',
  nvd: 'Summarised from NVD and CISA KEV.',
}

function PlainWords({ item, items }) {
  return (
    <div className="flex w-full shrink-0 flex-col gap-2 rounded-[20px] bg-blue-soft px-4 py-3.5">
      <div className="flex items-center gap-2">
        <span className="flex size-[26px] items-center justify-center rounded-full bg-blue-ink">
          <Icon name="fixfirst/icon-idea" className="size-3.5" />
        </span>
        <p className="type-body font-semibold whitespace-nowrap text-blue-ink">In plain words</p>
      </div>
      <Stable
        items={items}
        current={item}
        render={(it) => (
          <div className="flex flex-col gap-2">
            <p className="type-body text-ink">{it.explanation}</p>
            <p className="type-label text-blue-ink">{SOURCE_NOTE[it.explanationSource ?? 'nvd']}</p>
          </div>
        )}
      />
    </div>
  )
}

// Bar track width in the design. The API's values are SHAP contributions in log-odds
// (often 1-3), so the largest value among the shown rows fills the track; the
// design's fixed scale (0.31 = full) would clip almost every bar.
const TRACK_PX = 404

function Reasons({ item, items }) {
  const { rank, reasons } = item
  const largest = Math.max(0.0001, ...items.flatMap((it) => (it.reasons ?? []).map((r) => Math.abs(r.value))))
  // Every reason label from every row, so all three reason rows share one height
  // (the tallest label anywhere): even spacing, and nothing moves between ranks.
  const allLabels = items.flatMap((it) => (it.reasons ?? []).map((r, k) => ({ cveId: `${it.cveId}#${k}`, label: r.label })))
  return (
    <div className="flex w-full shrink-0 flex-col gap-3">
      <div className="flex items-center gap-2">
        <p className="text-base leading-6 font-semibold text-ink">Why it ranks #{rank}</p>
        {item.reasonsAreSample && (
          <span
            className="type-label rounded-full bg-subtle px-2 py-0.5 text-ink-muted"
            title="The model's scores aren't built on the server yet, so there are no model reasons."
          >
            Sample ranking
          </span>
        )}
      </div>
      {!reasons.length && (
        <p className="type-body text-ink-muted">No model reasons yet: ranked by CISA KEV, EPSS and CVSS.</p>
      )}
      {reasons.map((r, i) => (
        <div key={r.label} className="flex w-full items-center gap-2.5">
          <span className="flex size-[26px] shrink-0 items-center justify-center rounded-full bg-page">
            <Icon name={r.icon} className="size-3.5" />
          </span>
          <div className="flex min-w-px flex-1 flex-col gap-1.5">
            <Stable
              items={allLabels}
              current={{ cveId: `${item.cveId}#${i}` }}
              className="items-end"
              render={(l) => <p className="text-[13px] leading-[18px] tracking-body text-pretty text-ink">{l.label}</p>}
            />
            <div className="relative h-2 w-full shrink-0 overflow-hidden rounded-full">
              <Icon name="fixfirst/hatch-bar" className="absolute top-0 left-0 h-2 w-[404px]" />
              {/* Negative weights (factors that lower the rank) are grey, never colour alone: the value shows the sign. */}
              <span
                className={`absolute top-0 left-0 h-2 rounded-full ${r.value < 0 ? 'bg-line-strong' : i === 0 ? 'bg-blue' : 'bg-chart-seq-4'}`}
                style={{ width: (Math.abs(r.value) / largest) * TRACK_PX }}
              />
            </div>
          </div>
          <p className="shrink-0 font-mono text-[13px] leading-[18px] tracking-label whitespace-nowrap text-ink">
            {r.value < 0 ? '−' : '+'}
            {Math.abs(r.value).toFixed(2)}
          </p>
        </div>
      ))}
    </div>
  )
}

const formatDate = (iso) =>
  iso ? new Date(`${iso.slice(0, 10)}T00:00:00Z`).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : '—'

// Teal fact box content: IBM X-Force (never sent by the backend today), CISA KEV for
// CVEs on the list, otherwise the public facts we have (EPSS, weakness, exploit code).
function factsFor(it) {
  if (!it.xforce && !it.kev)
    return {
      title: 'Not on CISA KEV',
      link: `https://nvd.nist.gov/vuln/detail/${it.cveId}`,
      linkLabel: 'the NVD record',
      facts: [
        ['Chance of attack (EPSS)', it.facts.epss == null ? 'No score yet' : it.facts.epss.toFixed(2)],
        ['Public exploit code', it.facts.exploitCode ? 'Yes' : 'Not seen'],
        ['Weakness', it.facts.weakness ?? 'Not given'],
      ],
    }
  if (it.xforce)
    return {
      title: 'IBM X-Force',
      link: `https://exchange.xforce.ibmcloud.com/vulnerabilities/search/${it.cveId}`,
      linkLabel: 'IBM X-Force Exchange',
      facts: [
        ['Risk score', it.xforce.riskScore],
        ['Attacks seen', it.xforce.attacksSeen],
      ],
    }
  return {
    title: 'CISA KEV',
    link: `https://nvd.nist.gov/vuln/detail/${it.cveId}`,
    linkLabel: 'the NVD record',
    facts: [
      ['Added to KEV', formatDate(it.kev.added)],
      ['Used in ransomware', it.kev.ransomware ? 'Yes, per CISA' : 'Not known'],
      ['Weakness', it.kev.weakness ?? 'Not given'],
    ],
  }
}

function FactBox({ item, items }) {
  return (
    <Stable
      items={items}
      current={item}
      className="w-full shrink-0 rounded-[20px] bg-green-soft p-[18px]"
      render={(it) => <FactContent {...factsFor(it)} />}
    />
  )
}

function FactContent({ title, link, linkLabel, facts }) {
  return (
    <div className="flex w-full flex-col gap-2.5">
      <div className="flex w-full items-center gap-2.5">
        <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-card">
          <Icon name="fixfirst/xforce-shield" className="size-[15.12px]" />
        </span>
        <p className="min-w-px flex-1 text-base leading-6 font-semibold text-green-ink">{title}</p>
        <a
          href={link}
          target="_blank"
          rel="noreferrer"
          className="text-sm leading-5 font-semibold whitespace-nowrap text-blue-ink hover:underline"
        >
          Details<span className="sr-only"> on {linkLabel} (opens in a new tab)</span>
        </a>
      </div>
      {facts.map(([label, value]) => (
        <div key={label} className="flex w-full items-start gap-2 text-sm leading-5">
          <p className="min-w-px flex-1 text-ink-muted">{label}</p>
          <p className="shrink-0 text-right font-semibold text-ink">{value}</p>
        </div>
      ))}
    </div>
  )
}

export function WhyPanel({ item, items, error, onClose, onStatusChange, onPushToLinear }) {
  return (
    // Design sizes on every screen; on short windows the panel scrolls instead of squashing its sections.
    // `relative` keeps hidden link labels (sr-only) inside the panel so the window itself never scrolls.
    <aside
      aria-label={`Details for ${item.cveId}`}
      className={`relative flex h-full w-[400px] shrink-0 flex-col justify-between gap-2 overflow-y-auto rounded-[28px] bg-card px-[22px] pt-[18px] pb-5 shadow-float wide:w-[420px]`}
    >
            <div className="flex w-full shrink-0 items-center gap-2">
        <Icon name="fixfirst/icon-ticket" className="size-4" />
        <p className="type-label whitespace-pre text-ink-muted">{`Fix first  /  #${item.rank}`}</p>
        <div className="h-px min-w-px flex-1" />
        <CloseButton onClose={onClose} />
      </div>

      <div className="flex w-full shrink-0 items-center gap-3">
        <span className="flex size-12 shrink-0 items-center justify-center rounded-full bg-blue-soft text-base leading-6 font-semibold text-blue-ink">
          {item.vendorInitials ?? item.component.slice(0, 2).toUpperCase()}
        </span>
        <div className="flex min-w-0 flex-1 flex-col">
          <h2 className="text-[32px] leading-10 font-normal whitespace-nowrap text-ink">{item.cveId}</h2>
          <Stable
            items={items}
            current={item}
            render={(it) => <p className="type-label text-pretty text-ink-muted">{it.subtitle ?? it.component}</p>}
          />
        </div>
      </div>

      <div className="flex w-full shrink-0 items-center gap-2 rounded-[20px] bg-page p-2.5">
        <label className="relative flex h-10 cursor-pointer items-center gap-1.5 rounded-xl border border-line-strong bg-card pr-2.5 pl-3 focus-within:ring-2 focus-within:ring-blue/40">
          <span className="type-body whitespace-nowrap text-ink">{item.status}</span>
          <Icon name="fixfirst/chevron-down" className="size-3.5" />
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
        {item.ticket ? (
          // Already sent: links to the Linear issue.
          <a
            href={item.ticketUrl ?? undefined}
            target="_blank"
            rel="noreferrer"
            className="flex h-10 shrink-0 items-center gap-2 rounded-full bg-primary-strong pr-4 pl-[18px]"
          >
            <span className="type-body font-semibold whitespace-nowrap text-white">In Linear · {item.ticket}</span>
          </a>
        ) : (
          <LinearButton key={item.cveId} onPush={() => onPushToLinear(item.cveId)} />
        )}
      </div>
      {error && (
        <p role="alert" className="type-label w-full shrink-0 text-sev-critical">
          {error}
        </p>
      )}

      <RankContrast item={item} />

      <PlainWords item={item} items={items} />
      <Reasons item={item} items={items} />
      <FactBox item={item} items={items} />
    </aside>
  )
}
