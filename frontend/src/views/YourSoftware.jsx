import { useEffect, useMemo, useRef, useState } from 'react'
import { AppHeader } from '../components/insights/AppHeader'
import { Sidebar } from '../components/Sidebar'
import { Icon } from '../lib/Icon'
import { IconDarkContext } from '../lib/iconTheme'
import { DEMO_FILE, DEMO_URL, MAX_BYTES, previewSbom, rankComponents, summarize, toCsv, worstSeverity } from '../lib/sbom'
import { uploadSbom, useSbom } from '../lib/api'
import { useApi } from '../lib/useApi'
import { byProductList, isExact, matchMethods, methodText } from '../lib/matching'
import { BlueCard, FactRow, FitMain, FoundBy, PageTitle, SevMix, SevPill, SidePanel, SideBox, Tabs, sevBar, sevText } from '../components/software/SoftwareParts'

// "Your software" flow (Figma V5): Empty → Uploading → Overview ⇄ All components
// → Component → Ask why. `screen` lives in App so it survives page switches.

// Date-only strings (YYYY-MM-DD) are read as local dates, not UTC midnight.
const fmtDate = (d) => new Date(d.length === 10 ? `${d}T12:00:00` : d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
const fmtTime = (d) => d.toLocaleTimeString('en-GB', { hour12: false })

export function YourSoftware({ onHome, sbomId, library = [], onUploaded, onSelect, onRemove, screen, onScreen, onOpenFixFirst, onOpenInsights, software, totals, theme = 'light', onThemeChange }) {
  const dark = theme === 'dark'
  const [job, setJob] = useState(null) // the upload in progress
  const [error, setError] = useState(null)
  // The selected SBOM with every component and its risk (cached per SBOM).
  const detail = useSbom(sbomId)
  const sbom = detail.data ?? null

  // Reads the file for the preview, then uploads it. The preview animation and the
  // request run together; the Uploading screen finishes when both are done.
  const start = async (file) => {
    setError(null)
    try {
      if (file.size > MAX_BYTES) throw new Error('That file is over 10 MB.')
      const preview = previewSbom(await file.text(), file.name)
      const id = Date.now()
      const cancel = new AbortController()
      setJob({
        id,
        sbom: { ...preview, sizeKB: Math.max(1, Math.round(file.size / 1024)), uploadedAt: new Date().toISOString(), componentCount: preview.components.length },
        startedAt: new Date(),
        cancel,
        request: uploadSbom(file, cancel.signal),
      })
      onScreen({ name: 'uploading' })
    } catch (e) {
      setError(e instanceof SyntaxError ? 'We couldn’t read that file. Is it CycloneDX JSON or XML?' : e.message)
    }
  }
  const chooseFile = (file) => file && start(file)
  const tryDemo = async () => {
    try {
      const res = await fetch(DEMO_URL)
      const blob = await res.blob()
      start(new File([blob], DEMO_FILE, { type: 'application/json' }))
    } catch {
      setError('We couldn’t load the demo file.')
    }
  }

  const finish = (uploaded) => {
    setJob(null)
    onUploaded(uploaded.id)
    onScreen({ name: 'overview' })
  }
  const fail = (message) => {
    setJob(null)
    setError(message)
    onScreen({ name: 'empty' })
  }

  const ranked = useMemo(() => (sbom ? rankComponents(sbom.components) : []), [sbom])
  const open = (c) => onScreen({ name: 'component', id: c.id })

  let content
  if (screen.name === 'uploading' && job) content = <Uploading key={job.id} job={job} onDone={finish} onFail={fail} onCancel={() => (job.cancel.abort(), setJob(null), onScreen({ name: 'empty' }))} onOpenFixFirst={onOpenFixFirst} />
  else if (screen.name !== 'empty' && screen.name !== 'uploading' && sbomId && !sbom)
    content = <Loading error={detail.error} onRetry={detail.reload} />
  else if (!sbom || screen.name === 'empty' || screen.name === 'uploading') content = <Empty onFile={chooseFile} onDemo={tryDemo} error={error} />
  else if (screen.name === 'all') content = <AllComponents sbom={sbom} ranked={ranked} onScreen={onScreen} onOpen={open} />
  else if (screen.name === 'component') content = <ComponentDetail sbom={sbom} ranked={ranked} id={screen.id} onScreen={onScreen} onOpenFixFirst={onOpenFixFirst} />
  else if (screen.name === 'ask') content = <AskWhy ranked={ranked} focusId={screen.id} onScreen={onScreen} onOpenFixFirst={onOpenFixFirst} />
  else content = <Overview sbom={sbom} ranked={ranked} onScreen={onScreen} onOpen={open} onOpenFixFirst={onOpenFixFirst} />

  return (
    <IconDarkContext.Provider value={dark}>
      <div className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[560px] min-w-[1024px] flex-col bg-page font-sans`}>
        <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} onHome={onHome} />
        <div className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 wide:gap-5 wide:p-5 compact:py-3">
          <Sidebar
            current="software"
            onOpenFixFirst={onOpenFixFirst}
            onOpenInsights={onOpenInsights}
            onUpload={() => onScreen({ name: 'empty' })}
            totals={totals}
            software={{ ...software, library, currentId: sbomId, uploading: job?.sbom, onSelect, onRemove }}
          />
          {content}
        </div>
      </div>
    </IconDarkContext.Provider>
  )
}

/* ── Loading a saved SBOM ──────────────────────────────────────────────── */
function Loading({ error, onRetry }) {
  return (
    <FitMain className="items-center justify-center">
      <div className="flex flex-col items-center gap-3 rounded-[28px] bg-card p-10 text-center shadow-float" role="status">
        {error ? (
          <>
            <p className="text-lg text-ink">We couldn’t load this SBOM</p>
            <p className="text-sm text-ink-muted">{error.message}</p>
            <button type="button" onClick={onRetry} className="cursor-pointer rounded-full bg-blue px-5 py-2.5 text-sm font-semibold text-white hover:bg-primary-strong">
              Try again
            </button>
          </>
        ) : (
          <p className="text-sm text-ink-muted">Loading your software…</p>
        )}
      </div>
    </FitMain>
  )
}

/* ── Empty: choose a file ──────────────────────────────────────────────── */
// The bundled demo file's name and component count, read once from the file itself.
const useDemoPreview = () =>
  useApi(DEMO_URL, async () => previewSbom(await (await fetch(DEMO_URL)).text(), DEMO_FILE), { ttl: Infinity })

function Empty({ onFile, onDemo, error }) {
  const demo = useDemoPreview().data
  const input = useRef(null)
  const [dragging, setDragging] = useState(false)
  const pick = () => input.current?.click()
  return (
    <>
      <FitMain className="gap-5">
        <PageTitle title="Your software" subtitle="Upload an SBOM to see what’s inside and what’s at risk." />
        <div className="flex min-h-0 w-full flex-1 flex-col items-center justify-center gap-6 compact:gap-4">
          <div
            onDragOver={(e) => (e.preventDefault(), setDragging(true))}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => (e.preventDefault(), setDragging(false), onFile(e.dataTransfer.files[0]))}
            className={`flex w-full max-w-[640px] flex-col items-center gap-4 rounded-[28px] border-2 border-dashed border-blue px-12 pt-12 pb-10 compact:gap-3 compact:pt-8 compact:pb-7 ${dragging ? 'bg-blue-soft' : 'bg-card'}`}
          >
            <span className="flex size-[72px] items-center justify-center rounded-full bg-blue compact:size-14">
              <Icon name="software/upload-white" className="size-[30px]" />
            </span>
            <p className="text-[28px] font-light text-ink">Choose your SBOM file</p>
            <p className="text-[15px] text-ink-muted">CycloneDX, as .json or .xml, up to 10 MB</p>
            <div className="flex items-center gap-3 pt-2">
              <button type="button" onClick={pick} className="cursor-pointer rounded-full bg-blue px-[26px] py-3.5 text-base font-semibold text-white hover:bg-primary-strong">
                Choose a file
              </button>
              <button type="button" onClick={onDemo} className="cursor-pointer rounded-full border border-line-strong bg-card px-6 py-3.5 text-base font-medium text-blue-ink hover:bg-blue-soft">
                Try the demo file
              </button>
              <input ref={input} type="file" accept=".json,.xml,application/json,text/xml" className="hidden" onChange={(e) => onFile(e.target.files[0])} />
            </div>
            {error ? (
              <p role="alert" className="text-[13px] font-medium text-sev-critical">{error}</p>
            ) : (
              <p className="text-[13px] text-ink-muted">
                {demo ? `The demo is ${demo.name}: ${demo.components.length} components, ready to explore.` : 'The demo SBOM is ready to explore.'}
              </p>
            )}
          </div>
          <div className="flex gap-4">
            {[
              ['1', 'Upload', 'We list every component', 'bg-blue-soft', 'text-blue-ink'],
              ['2', 'Match', 'We find known CVEs for each', 'bg-purple-soft', 'text-purple-ink'],
              ['3', 'Fix', 'We tell you what to fix first', 'bg-green-soft', 'text-ink'],
            ].map(([n, t, d, bg, ink]) => (
              <div key={n} className={`flex w-[202px] flex-col gap-1.5 rounded-[20px] px-5 py-[18px] ${bg}`}>
                <div className="flex items-center gap-2">
                  <span className={`flex size-[26px] items-center justify-center rounded-full bg-card text-[13px] font-semibold ${ink}`}>{n}</span>
                  <span className={`text-base font-semibold ${ink}`}>{t}</span>
                </div>
                <p className="text-[13px] leading-[18px] text-ink-muted">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </FitMain>
      <SidePanel>
        <BlueCard action={'Choose a file  →'} onAction={pick}>
          Export a CycloneDX SBOM from your build tool, then choose it here. No file? Try the demo.
        </BlueCard>
        <SideBox tone="teal" icon="software/eye-teal" title="What we read">
          <FactRow label="Vendor" value="e.g. Fortinet" />
          <FactRow label="Product" value="e.g. FortiOS" />
          <FactRow label="Version" value="e.g. 7.4.2" />
          <FactRow label="CPE name" value="if it’s there" />
        </SideBox>
        <SideBox tone="purple" icon="software/target-purple" title="Where Granite helps">
          <p className="text-[13px] leading-[19px] text-ink-muted">
            Some CVEs in NIST have no product list yet. We also look for your products in the CVE text, and IBM Granite can confirm those matches, so fewer slip through.
          </p>
        </SideBox>
      </SidePanel>
    </>
  )
}

/* ── Uploading: steps through the real file while the server matches it ── */
function Uploading({ job, onDone, onFail, onCancel, onOpenFixFirst }) {
  const total = job.sbom.components.length
  const noCpe = job.sbom.components.filter((c) => !c.cpe)
  const [checked, setChecked] = useState(0)
  const [result, setResult] = useState(null) // the stored SBOM once POST /api/sboms answers
  useEffect(() => {
    let live = true
    job.request.then(
      (sbom) => live && setResult(sbom),
      (e) => live && onFail(e.message),
    )
    return () => {
      live = false
    }
    // Runs once per upload job.
  }, [job]) // eslint-disable-line react-hooks/exhaustive-deps
  // What happened while reading the file (all real: counts come from the file).
  const [log] = useState(() => {
    const t = job.startedAt
    return [
      [t, 'Opened the file', 'software/dot-teal'],
      [t, `Valid CycloneDX ${job.sbom.specVersion ?? ''}`.trim(), 'software/dot-teal'],
      [t, `Found ${total} components`, 'software/dot-teal'],
      [t, `${total - noCpe.length} have a CPE name`, 'software/dot-teal'],
      ...(noCpe.length ? [[t, `${noCpe.length} have no CPE name`, 'software/dot-purple']] : []),
    ]
  })

  // Steps through the components; the last one waits for the server's answer.
  useEffect(() => {
    let n = 0
    const id = setInterval(() => {
      n = Math.min(n + 1, total - 1)
      setChecked(n)
      if (n >= total - 1) clearInterval(id)
    }, 160)
    return () => clearInterval(id)
    // Runs once per upload job.
  }, [job]) // eslint-disable-line react-hooks/exhaustive-deps
  // All steps shown and the server answered: complete, then hand over the result.
  const done = Boolean(result) && checked >= total - 1
  useEffect(() => {
    if (!done) return
    const t = setTimeout(() => onDone(result), 500)
    return () => clearTimeout(t)
  }, [done]) // eslint-disable-line react-hooks/exhaustive-deps

  const step = done ? total : checked
  const pct = Math.round((step / total) * 100)
  return (
    <>
      <FitMain className="gap-5">
        <PageTitle title="Uploading" subtitle="This takes a few seconds. You can leave this page." />
        <div className="flex min-h-0 w-full flex-1 items-center justify-center">
          <div className="relative w-full max-w-[620px] overflow-hidden rounded-[28px] bg-card shadow-float" role="status" aria-live="polite">
            <div className="relative h-[170px] overflow-hidden bg-blue">
              <Icon name="software/band-ring-1" className="absolute top-[-120px] left-[430px] size-[280px]" />
              <Icon name="software/band-ring-2" className="absolute top-[60px] left-[500px] size-[200px]" />
              <Icon name="software/band-ring-3" className="absolute top-[70px] left-[-70px] size-[180px]" />
              <span className="absolute top-6 left-7 flex items-center gap-2 rounded-full border border-white py-1.5 pr-3.5 pl-2.5">
                <Icon name="software/upload-chip" className="size-4" />
                <span className="text-[13px] text-white">
                  {job.sbom.fileName} · {job.sbom.sizeKB} KB
                </span>
              </span>
              <p className="absolute top-[68px] left-6 text-[72px] leading-[76px] font-light text-white">{pct}%</p>
            </div>
            <div className="flex flex-col gap-3.5 px-7 pt-6 pb-6">
              <div className="flex gap-1" aria-hidden="true">
                {job.sbom.components.map((c, i) => (
                  <span key={c.id} className={`h-3 min-w-0 flex-1 rounded-[3px] ${i < step ? 'bg-blue' : 'bg-track'}`} />
                ))}
              </div>
              <Step state="done">File is a valid CycloneDX SBOM</Step>
              <Step state="done">Found {total} components</Step>
              <Step state={done ? 'done' : 'active'}>
                Checking for known vulnerabilities · {step} of {total}
              </Step>
              {noCpe.length > 0 && (
                <Step state="next">
                  Next: matching {noCpe.length} component{noCpe.length === 1 ? '' : 's'} with no CPE name by name and CVE text
                </Step>
              )}
              <div className="flex items-center justify-between pt-3">
                <button type="button" onClick={onCancel} className="flex cursor-pointer items-center gap-1.5 text-sm font-medium text-blue-ink hover:underline">
                  <Icon name="software/close-blue" className="size-3.5" />
                  Cancel
                </button>
                <span className="flex items-center gap-1.5 rounded-full bg-purple-soft py-1 pr-3 pl-2.5">
                  <Icon name="software/idea-purple" className="size-3.5" />
                  <span className="text-xs text-ink">We also read the CVE text where NIST has no product list</span>
                </span>
              </div>
            </div>
          </div>
        </div>
      </FitMain>
      <SidePanel>
        <BlueCard action={'Go to Fix first  →'} onAction={onOpenFixFirst}>
          You can leave this page. We’ll send you an alert when the results are ready.
        </BlueCard>
        <SideBox tone="grey" icon="software/queue-blue" title="Activity log">
          {[...log, ...(done ? [] : [[new Date(), `Checking NIST · ${checked} of ${total}`, 'software/dot-blue']])].map(([t, text, dot], i) => (
            <div key={i} className="flex items-center gap-2">
              <Icon name={dot} className="size-2" />
              <span className="font-mono text-xs text-ink-muted">{fmtTime(t)}</span>
              <span className="min-w-px flex-1 text-[13px] leading-[18px] text-ink">{text}</span>
            </div>
          ))}
        </SideBox>
        <SideBox tone="teal" icon="software/eye-teal" title="What we read">
          <FactRow label="Product name" value={`✓ All ${total}`} />
          <FactRow label="Version" value={`✓ ${job.sbom.components.filter((c) => c.version).length} of ${total}`} />
          <FactRow label="CPE name" value={`${total - noCpe.length} of ${total}`} />
        </SideBox>
      </SidePanel>
    </>
  )
}

function Step({ state, children }) {
  const icon = state === 'done' ? (
    <span className="flex size-7 items-center justify-center rounded-full bg-green-soft">
      <Icon name="software/check-teal" className="size-4" />
    </span>
  ) : (
    <Icon name={state === 'active' ? 'software/step-active' : 'software/step-next'} className="size-7" />
  )
  return (
    <div className="flex items-center gap-3">
      {icon}
      <p className={`text-[15px] ${state === 'active' ? 'font-semibold text-ink' : state === 'next' ? 'text-ink-muted' : 'text-ink'}`}>{children}</p>
    </div>
  )
}

/* ── Overview ──────────────────────────────────────────────────────────── */
function SoftwareHeader({ sbom, tab, onScreen }) {
  return (
    <>
      <PageTitle title="Your software" subtitle={`${sbom.components.length} components from ${sbom.fileName} · uploaded ${fmtDate(sbom.uploadedAt)}`}>
        <span className="mt-0.5 flex items-center gap-2 rounded-full bg-card px-3 py-1.5">
          <Icon name="software/dot-blue" className="size-2" />
          <span className="text-xs text-ink-muted">
            Components are from your file. CVEs from NIST NVD and CISA KEV, checked {fmtDate(sbom.riskChecked)}.
          </span>
        </span>
      </PageTitle>
      <Tabs value={tab} onChange={(id) => onScreen({ name: id })} items={[['overview', 'Overview'], ['all', 'All components']]} />
    </>
  )
}

function Overview({ sbom, ranked, onScreen, onOpen, onOpenFixFirst }) {
  const s = summarize(sbom)
  const top = ranked[0]
  const byCount = sbom.components.filter((c) => c.risk?.cveCount).sort((a, b) => b.risk.cveCount - a.risk.cveCount).slice(0, 8)
  const max = byCount[0]?.risk.cveCount ?? 1
  const scale = (n) => `${Math.max(3, (Math.log10(n + 1) / Math.log10(max + 1)) * 100)}%`
  return (
    <>
      <FitMain className="gap-5 compact:gap-3">
        <SoftwareHeader sbom={sbom} tab="overview" onScreen={onScreen} />
        <div className="flex w-full shrink-0 gap-5 compact:gap-4">
          <div className="flex min-h-[156px] min-w-0 flex-1 flex-col gap-1.5 rounded-[20px] bg-card px-[22px] py-5">
            <p className="text-sm text-ink-muted">Affected components</p>
            <p className="flex items-baseline gap-2">
              <span className="text-5xl leading-[52px] font-light text-ink">{s.affected}</span>
              <span className="text-lg text-ink-muted">of {s.total}</span>
            </p>
            <span className="flex gap-[3px]" aria-hidden="true">
              {sbom.components.map((c) => (
                <span key={c.id} className={`h-3 w-[9px] rounded-[2px] ${c.risk?.cveCount ? 'bg-blue' : 'bg-track'}`} />
              ))}
            </span>
            {s.total - s.checked > 0 && <p className="text-xs text-ink-muted">{s.total - s.checked} not checked</p>}
          </div>
          <div className="flex min-h-[156px] min-w-0 flex-1 flex-col gap-1.5 rounded-[20px] bg-card px-[22px] py-5">
            <p className="text-sm text-ink-muted">Known vulnerabilities (CVEs)</p>
            <p className="text-5xl leading-[52px] font-light text-ink">{s.cves.toLocaleString()}</p>
            <SevMix sev={s.sev} />
            <p className="text-xs text-ink-muted">{sevText(s.sev, true)}</p>
          </div>
          <div className="flex min-h-[156px] min-w-0 flex-1 flex-col gap-1.5 rounded-[20px] bg-brand px-[22px] py-5">
            <p className="text-sm font-medium text-white">Fix these first</p>
            <p className="flex items-baseline gap-2.5 text-white">
              <span className="text-5xl leading-[52px] font-light">{s.exploitedComponents}</span>
              <span className="text-sm">have bugs in active attacks</span>
            </p>
            <button type="button" onClick={onOpenFixFirst} className="flex h-[34px] cursor-pointer items-center gap-2 self-start rounded-full bg-on-brand px-3.5 text-sm font-medium text-primary-strong hover:bg-on-brand-hover">
              Open Fix first
              <Icon name="software/arrow-up-right-blue" className="size-3.5" />
            </button>
          </div>
        </div>
        <section className="flex min-h-0 w-full flex-1 flex-col items-start rounded-[20px] bg-card px-6 pt-[22px] pb-[18px]">
          <h2 className="text-xl leading-7 text-ink">Known vulnerabilities by component</h2>
          <p className="pt-1.5 pb-3 text-[13px] text-ink-muted">
            Longer bar = more CVEs (log scale). Colour and shape show the worst one (key on the right). Click a name for details.
          </p>
          {/* Rows keep their design height (44px); on short screens this list scrolls instead of squashing them. */}
          <div data-fit-scroll className="relative flex min-h-0 w-full flex-1 flex-col overflow-y-auto">
            {byCount.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => onOpen(c)}
                className="flex h-11 w-full shrink-0 cursor-pointer items-center gap-3.5 border-b border-line text-left hover:bg-page"
              >
                <span className="flex w-44 shrink-0 flex-col">
                  <span className="truncate text-sm font-semibold text-ink">{c.name}</span>
                  <span className="truncate text-xs text-ink-muted">
                    {c.vendor} · {c.version}
                  </span>
                </span>
                <span className="relative h-3.5 w-[300px] min-w-0 shrink overflow-hidden rounded-[7px] bg-track">
                  <span className={`absolute inset-y-0 left-0 rounded-[7px] ${sevBar(worstSeverity(c.risk))}`} style={{ width: scale(c.risk.cveCount) }} />
                </span>
                <span className="w-14 shrink-0 text-right text-lg font-semibold text-ink">{c.risk.cveCount.toLocaleString()}</span>
                <span className="min-w-px flex-1" />
                <SevPill severity={worstSeverity(c.risk)} />
              </button>
            ))}
          </div>
          <button type="button" onClick={() => onScreen({ name: 'all' })} className="flex shrink-0 cursor-pointer items-center gap-1.5 self-start pt-2.5 text-sm font-medium text-blue-ink hover:underline">
            See all {s.total} components
            <Icon name="software/chevron-right-blue" className="size-3.5" />
          </button>
        </section>
      </FitMain>
      <SidePanel>
        <BlueCard action={'Open Fix first  →'} onAction={onOpenFixFirst}>
          {top?.risk
            ? `Start with ${top.name}. It has ${top.risk.cveCount.toLocaleString()} known CVEs and ${top.risk.kev.length} ${top.risk.kev.length === 1 ? 'is' : 'are'} being used in attacks right now.`
            : 'None of these components are on NIST’s list yet.'}
        </BlueCard>
        <SideBox tone="purple" icon="software/eye-purple" title="How we found them">
          <div className="flex flex-col gap-1.5">
            <FactRow label="Matched CVEs" value={<span className="text-base text-purple-ink">{s.cves.toLocaleString()}</span>} />
            <span className="h-2 overflow-hidden rounded bg-card">
              <span className="block h-2 w-full rounded bg-ai" />
            </span>
          </div>
          <p className="text-[13px] leading-[19px] text-ink-muted">
            Most come from the product and version in NIST’s list. Where NIST has no product list yet, we also match the CVE text, and IBM Granite can confirm those matches. Fix first shows how each CVE was matched.
          </p>
        </SideBox>
        <SideBox tone="grey" icon="software/target-blue" title="How to read colours">
          {[
            ['critical', 'Fix today'],
            ['high', 'Fix this week'],
            ['medium', 'Plan a fix'],
            ['none', `${s.clear} component${s.clear === 1 ? ' is' : 's are'} clear`],
          ].map(([k, t]) => (
            <div key={k} className="flex items-center gap-2.5">
              <SevPill severity={k} />
              <span className="min-w-px flex-1 text-right text-sm text-ink-muted">{t}</span>
            </div>
          ))}
        </SideBox>
      </SidePanel>
    </>
  )
}

/* ── All components ────────────────────────────────────────────────────── */
function AllComponents({ sbom, ranked, onScreen, onOpen }) {
  const s = summarize(sbom)
  const rows = [...sbom.components].sort((a, b) => (b.risk?.cveCount ?? -1) - (a.risk?.cveCount ?? -1))
  const max = Math.max(1, ...rows.map((c) => c.risk?.cveCount ?? 0))
  const top = ranked[0]
  const download = () => {
    const url = URL.createObjectURL(new Blob([toCsv(sbom)], { type: 'text/csv' }))
    const a = Object.assign(document.createElement('a'), { href: url, download: `${sbom.fileName.replace(/\.(cdx\.)?(json|xml)$/i, '')}-components.csv` })
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <>
      <FitMain className="gap-5 compact:gap-3">
        <SoftwareHeader sbom={sbom} tab="all" onScreen={onScreen} />
        <section className="flex min-h-0 w-full flex-1 flex-col rounded-[20px] bg-card px-6 py-3" aria-label="All components">
          <div className="flex h-[38px] w-full shrink-0 items-center gap-3 border-b border-line text-xs font-medium text-ink-muted">
            <span className="min-w-0 flex-1 wide:w-[165px] wide:flex-none">Component</span>
            <span className="w-[118px] shrink-0 wide:w-[128px]">Vendor</span>
            <span className="w-[110px] shrink-0 wide:w-[128px]">Version</span>
            <span className="w-[110px] shrink-0 narrow:hidden">Found by</span>
            <span className="w-11 shrink-0 text-right">CVEs</span>
            <span className="hidden w-[80px] shrink-0 wide:block" />
            <span className="hidden min-w-0 flex-1 wide:block" />
            <span className="w-[96px] shrink-0">Worst severity</span>
          </div>
          <div className="flex min-h-0 flex-1 flex-col">
            {rows.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => onOpen(c)}
                className="flex max-h-[30px] min-h-[26px] w-full flex-1 basis-0 cursor-pointer items-center gap-3 border-b border-line text-left hover:bg-page"
              >
                <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink wide:w-[165px] wide:flex-none" title={c.name}>{c.name}</span>
                <span className="w-[118px] shrink-0 truncate text-[13px] text-ink-muted wide:w-[128px] wide:text-sm" title={c.vendor ?? undefined}>{c.vendor ?? '—'}</span>
                <span className="w-[110px] shrink-0 truncate font-mono text-xs text-ink wide:w-[128px] wide:text-[13px]" title={c.version}>{c.version}</span>
                <span className="w-[110px] shrink-0 narrow:hidden">
                  <FoundBy component={c} />
                </span>
                <span className={`w-11 shrink-0 text-right text-sm font-semibold ${c.risk?.cveCount ? 'text-ink' : 'text-ink-muted'}`}>{c.risk ? c.risk.cveCount.toLocaleString() : '—'}</span>
                <span className="relative hidden h-2 w-[80px] shrink-0 overflow-hidden rounded bg-track wide:block">
                  {c.risk?.cveCount > 0 && (
                    <span className={`absolute inset-y-0 left-0 rounded ${sevBar(worstSeverity(c.risk))}`} style={{ width: `${Math.max(4, (Math.log10(c.risk.cveCount + 1) / Math.log10(max + 1)) * 100)}%` }} />
                  )}
                </span>
                <span className="hidden min-w-0 flex-1 wide:block" />
                <span className="w-[96px] shrink-0">
                  <SevPill severity={worstSeverity(c.risk)} />
                </span>
              </button>
            ))}
          </div>
        </section>
      </FitMain>
      <SidePanel>
        <BlueCard action={top ? (top.name.length <= 14 ? `Open ${top.name}  →` : 'Open the riskiest  →') : null} onAction={() => top && onOpen(top)}>
          Click a component to see its CVEs and how we matched them. {top ? `${top.name} is the riskiest.` : ''}
        </BlueCard>
        <SideBox tone="teal" icon="software/queue-blue" title="About this file">
          <FactRow label="Format" value={`CycloneDX ${sbom.specVersion ?? ''}`.trim()} />
          <FactRow label="Components" value={s.total} />
          <FactRow label="With a CPE name" value={s.withCpe} />
          <FactRow label="Without a CPE name" value={s.total - s.withCpe} />
          <p className="text-[13px] leading-[19px] text-ink-muted">A CPE is a standard product ID. Without one, we match the package URL or name, and the CVE text.</p>
        </SideBox>
        <SideBox tone="purple" icon="software/eye-purple" title="Found by">
          <div className="flex items-start gap-3">
            <span className="shrink-0">
              <FoundBy component={{}} methods={['cpe']} />
            </span>
            <p className="text-[13px] leading-[18px] text-ink-muted">Its CPE name is in NIST’s CVE records: an exact match.</p>
          </div>
          <div className="flex items-start gap-3">
            <span className="shrink-0">
              <FoundBy component={{}} methods={['description']} />
            </span>
            <p className="text-[13px] leading-[18px] text-ink-muted">Matched by package URL, name or CVE text instead; IBM Granite can confirm. Dashed outline.</p>
          </div>
        </SideBox>
        <button type="button" onClick={download} className="w-full shrink-0 cursor-pointer rounded-full border border-line-strong bg-card py-3.5 text-base font-semibold text-ink hover:bg-page">
          Download as CSV
        </button>
      </SidePanel>
    </>
  )
}

/* ── Component detail ──────────────────────────────────────────────────── */
// The "How it matched" steps, from the methods the backend actually used.
function matchSteps(c, methods) {
  const n = c.risk?.cveCount ?? 0
  const steps = []
  if (methods.includes('cpe'))
    steps.push(
      <>
        Your SBOM names it with a CPE <code className="rounded-md bg-card px-2 py-0.5 font-mono text-xs text-ink">{c.cpe.split(':').slice(0, 6).join(':')}</code>, and NIST lists it in the CVE records
      </>,
    )
  else if (!c.cpe) steps.push('Your SBOM has no CPE name for it')
  const byName = byProductList(methods)
  if (byName.length) steps.push(`We matched its ${methodText(byName)} to NIST’s product list`)
  if (methods.includes('description')) steps.push('Where NIST has no product list yet, we found it named in the CVE text. IBM Granite can confirm those matches')
  if (!methods.length) steps.push('No CVE record matched its CPE name, package URL, name or the CVE text')
  else steps.push(isExact(methods) ?`${n.toLocaleString()} CVEs in all. No AI guesswork needed, so this match is exact` : `${n.toLocaleString()} CVEs found in all`)
  return steps
}

function ComponentDetail({ sbom, ranked, id, onScreen, onOpenFixFirst }) {
  const c = sbom.components.find((x) => x.id === id) ?? ranked[0]
  const r = c.risk
  const methods = matchMethods(c)
  const rank = ranked.indexOf(c) + 1
  const worst = worstSeverity(r)
  const rest = r ? { ...r.severity } : null
  if (r) for (const t of r.top) rest[t.severity] -= 1
  const kevSince = r?.kev.map((k) => k.added).sort()[0]
  const nvdLink = c.cpe ? `https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&isCpeNameSearch=true&search_type=all&cpe_version=${encodeURIComponent(c.cpe)}` : null
  return (
    <>
      <FitMain className="gap-4 compact:gap-3">
        <button type="button" onClick={() => onScreen({ name: 'all' })} className="flex shrink-0 cursor-pointer items-center gap-1.5 self-start rounded-full border border-line bg-card py-2 pr-3.5 pl-2.5 font-medium text-blue-ink hover:bg-blue-soft">
          <span className="text-sm">←</span>
          <span className="text-[13px]">All components</span>
        </button>
        <PageTitle title={`${c.name} ${c.version}`} subtitle={[c.vendor, c.part].filter(Boolean).join(' · ')} />
        <div className="flex w-full shrink-0 gap-4">
          <div className="flex min-w-0 flex-1 flex-col gap-1.5 rounded-[20px] bg-card px-5 py-[18px]">
            <p className="text-[13px] text-ink-muted">Known CVEs</p>
            <p className="text-[40px] leading-tight font-light text-ink">{r ? r.cveCount.toLocaleString() : '—'}</p>
            <p className="text-xs text-ink-muted">{!r ? 'Not checked' : methods.length ? `Matched by its ${methodText(methods)}` : 'No matches found'}</p>
          </div>
          <div className="flex min-w-0 flex-1 flex-col gap-1.5 rounded-[20px] bg-card px-5 py-[18px]">
            <p className="text-[13px] text-ink-muted">Worst severity</p>
            <p className="flex items-center gap-2.5">
              {worst === 'critical' && <Icon name="software/sev-critical-lg" className="size-[18px]" />}
              <span className="text-[40px] leading-tight font-light text-ink capitalize">{worst ?? '—'}</span>
            </p>
            <p className="text-xs text-ink-muted">{r ? `CVSS ${r.maxCvss} out of 10` : 'Not checked'}</p>
          </div>
          <div className={`flex min-w-0 flex-1 flex-col gap-1.5 rounded-[20px] px-5 py-[18px] ${r?.kev.length ? 'border-2 border-sev-critical bg-critical-soft' : 'bg-card'}`}>
            <p className="text-[13px] text-ink-muted">Used in attacks now</p>
            <p className={`text-[40px] leading-tight font-light ${r?.kev.length ? 'text-sev-critical' : 'text-ink'}`}>{r ? r.kev.length : '—'}</p>
            <p className="text-xs text-ink">On CISA’s exploited list (KEV)</p>
          </div>
        </div>
        <div className="flex w-full shrink-0 flex-col gap-3 rounded-[20px] bg-blue-soft px-6 py-5 compact:gap-2 compact:py-4">
          <div className="flex items-center gap-2.5">
            <p className="text-lg font-medium text-blue-ink">How it matched</p>
            <FoundBy component={c} />
          </div>
          {matchSteps(c, methods).map((step, i) => (
            <MatchStep key={i} n={i + 1}>
              {step}
            </MatchStep>
          ))}
        </div>
        {r?.cveCount > 0 && (
          <section className="flex w-full flex-1 flex-col rounded-[20px] bg-card px-6 pt-[18px] pb-3.5">
            <h2 className="text-lg font-medium text-ink">Top known vulnerabilities</h2>
            <div className="flex w-full shrink-0 items-center gap-4 border-b border-line pt-3.5 pb-2 text-xs font-medium text-ink-muted">
              <span className="w-[140px] shrink-0">CVE</span>
              <span className="min-w-0 flex-1">What it is</span>
              <span className="w-[50px] shrink-0 text-right">CVSS</span>
              <span className="w-[150px] shrink-0">Being attacked?</span>
              <span className="w-[100px] shrink-0">Severity</span>
            </div>
            {r.top.map((v) => (
              <div key={v.id} className="flex w-full items-center gap-4 border-b border-line py-2.5">
                <a href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer" className="w-[140px] shrink-0 font-mono text-sm text-ink hover:underline">
                  {v.id}
                </a>
                <span className="line-clamp-2 min-w-0 flex-1 text-sm text-ink-muted">{v.kev?.name ?? v.summary}</span>
                <span className="w-[50px] shrink-0 text-right text-sm font-semibold text-ink">{v.cvss ?? '—'}</span>
                <span className="w-[150px] shrink-0">
                  {v.kev ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-critical-soft py-0.5 pr-2.5 pl-2">
                      <Icon name="software/bell-red" className="size-3" />
                      <span className="text-xs font-medium text-ink">Yes · CISA KEV</span>
                    </span>
                  ) : (
                    <span className="text-xs text-ink-muted">Not on KEV</span>
                  )}
                </span>
                <span className="w-[100px] shrink-0">
                  <SevPill severity={v.severity} />
                </span>
              </div>
            ))}
            {r.cveCount > r.top.length && (
              <div className="mt-3 flex shrink-0 items-center gap-3 rounded-xl bg-subtle px-4 py-3">
                <span className="text-sm font-medium whitespace-nowrap text-ink">The other {(r.cveCount - r.top.length).toLocaleString()}</span>
                <SevMix sev={rest} width={240} />
                <span className="truncate text-[13px] text-ink-muted">{sevText(rest)}</span>
              </div>
            )}
            <a href={nvdLink} target="_blank" rel="noreferrer" className="shrink-0 self-start pt-3.5 text-sm font-medium text-blue-ink hover:underline">
              See all {r.cveCount.toLocaleString()} CVEs on NVD ↗
            </a>
          </section>
        )}
      </FitMain>
      <SidePanel>
        <BlueCard action={'Open in Fix first  →'} onAction={onOpenFixFirst}>
          {r?.fixedIn
            ? `Upgrade ${c.name} to ${r.fixedIn} or later. That closes all ${r.kev.length} bug${r.kev.length === 1 ? '' : 's'} attackers are using.`
            : r?.kev.length
              ? `${r.kev.length} of its bugs are being used in attacks. Check ${c.vendor}’s advisories for a fixed version.`
              : r?.cveCount
                ? 'No known attacks on these CVEs yet. Plan an update.'
                : c.cpe
                  ? 'No known CVEs for this version. Nothing to fix right now.'
                  : 'No known CVEs found. Add a CPE name for this component so we can match it to NIST’s list exactly.'}
        </BlueCard>
        <SideBox tone="red" icon="software/bell-red" title={`Why it’s #${rank}`}>
          <FactRow label="Rank in this SBOM" value={`#${rank} of ${ranked.length}`} />
          <FactRow label="On CISA KEV since" value={kevSince ? new Date(kevSince).toLocaleDateString('en-GB', { month: 'short', year: 'numeric' }) : 'Not on KEV'} />
          <FactRow label="Highest chance of attack (EPSS)" value={r ? r.epssMax.toFixed(2) : '—'} />
          <p className="text-[13px] leading-[19px] text-ink-muted">Severity says how bad an attack could be. We rank by how likely one is: attacks seen first, then EPSS.</p>
        </SideBox>
        <button type="button" onClick={() => onScreen({ name: 'ask', id: c.id })} className="flex w-full shrink-0 cursor-pointer items-center justify-center gap-2 rounded-full border border-ai bg-purple-soft py-3 text-base font-semibold text-purple-ink hover:brightness-95">
          ✦ Ask why it’s #{rank}
        </button>
        <SideBox tone="teal" icon="software/queue-blue" title="Component facts">
          <FactRow label="Vendor" value={c.vendor ?? '—'} />
          <FactRow label="Version" value={c.version} />
          <FactRow label="Fixed in" value={r?.fixedIn ?? 'See vendor advisory'} />
          <FactRow label="Found by" value={methods.length ? methodText(methods).replace(/^./, (x) => x.toUpperCase()) : 'No match'} />
        </SideBox>
      </SidePanel>
    </>
  )
}

function MatchStep({ n, children }) {
  return (
    <div className="flex items-center gap-3">
      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-blue text-xs font-semibold text-white">{n}</span>
      <p className="text-sm leading-5 text-ink">{children}</p>
    </div>
  )
}

/* ── Ask why ───────────────────────────────────────────────────────────── */
// Answers are templates filled in the browser with the facts on screen (no backend
// route, no AI model), and the page says so: nothing here claims to be Granite.
function facts(c, ranked) {
  const r = c.risk
  return {
    c,
    rank: ranked.indexOf(c) + 1,
    epss: r?.epssMax ?? 0,
    cvss: r?.maxCvss ?? 0,
    kev: r?.kev.length ?? 0,
    ransomware: r?.top.some((t) => t.kev?.ransomware) ?? false,
  }
}

function pickContrast(a, ranked) {
  const checked = ranked.filter((c) => c.risk && c !== a.c)
  const similar = checked.filter((c) => Math.abs(c.risk.maxCvss - a.cvss) <= 0.5 && ranked.indexOf(c) > ranked.indexOf(a.c))
  return facts(similar.at(-1) ?? checked.at(-1) ?? ranked.at(-1), ranked)
}

function CompareCard({ f, strong }) {
  const ok = (cond, yes, no) => ({ good: cond, text: cond ? yes : no })
  const points = [
    ok(f.kev > 0, `Already being attacked (${f.kev} on CISA’s KEV list)`, 'No attacks seen on CISA’s KEV list'),
    ok(f.epss >= 0.1, `High predicted chance of attack (EPSS ${f.epss.toFixed(2)})`, `Low predicted chance of attack (EPSS ${f.epss.toFixed(2)})`),
    ...(f.ransomware ? [ok(true, 'Used in ransomware campaigns, per CISA', '')] : []),
  ]
  return (
    <div className={`flex min-w-0 flex-1 flex-col gap-2.5 rounded-[20px] px-[22px] py-[18px] ${strong ? 'bg-brand text-white' : 'bg-green-soft text-ink'}`}>
      <div className="flex items-end gap-3">
        <span className="text-[40px] leading-none font-light">#{f.rank}</span>
        <span className="flex min-w-0 flex-col">
          <span className="truncate text-sm font-semibold">
            {f.c.name} {f.c.version}
          </span>
          <span className={`text-xs ${strong ? 'text-white' : 'text-ink-muted'}`}>{f.kev || f.epss >= 0.1 ? 'Likely to be attacked' : 'Unlikely to be attacked'}</span>
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {[
          ['Chance of attack', f.epss.toFixed(2)],
          ['CVSS severity', f.cvss],
        ].map(([l, v]) => (
          <span key={l} className={`rounded-full px-2.5 py-1 text-xs ${strong ? 'border border-white' : 'bg-card'}`}>
            {l} <b className="ml-1 text-sm">{v}</b>
          </span>
        ))}
      </div>
      {points.map((p) => (
        <p key={p.text} className="flex items-center gap-2 text-[13px]">
          <span aria-hidden="true" className={`flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] ${strong ? 'bg-white text-blue' : 'bg-card text-ink-muted'}`}>
            {p.good ? '↑' : '✕'}
          </span>
          {p.text}
        </p>
      ))}
    </div>
  )
}

function AskWhy({ ranked, focusId, onScreen, onOpenFixFirst }) {
  const focus = ranked.find((c) => c.id === focusId) ?? ranked[0]
  const a = facts(focus, ranked)
  const b = pickContrast(a, ranked)
  const [extra, setExtra] = useState([])
  const [draft, setDraft] = useState('')
  const listRef = useRef(null)
  useEffect(() => {
    if (extra.length) listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [extra])

  const answer = (q) => {
    const lower = q.toLowerCase()
    if (lower.includes('riskiest'))
      return `By attacks seen, then chance of attack: ${ranked
        .slice(0, 3)
        .map((c, i) => `#${i + 1} ${c.name} (${c.risk?.kev.length ?? 0} on KEV)`)
        .join(', ')}.`
    if (lower.includes('#2')) {
      const [x, y] = [facts(ranked[1], ranked), facts(ranked[2], ranked)]
      return `${x.c.name} has ${x.kev} CVE${x.kev === 1 ? '' : 's'} on CISA’s KEV list and ${y.c.name} has ${y.kev}${x.kev === y.kev ? `; then chance of attack decides it (${x.epss.toFixed(2)} vs ${y.epss.toFixed(2)})` : ''}.`
    }
    if (lower.includes('changed')) return 'This is your first upload of this file, so there’s no earlier version to compare with yet.'
    return 'I can only answer the suggested questions. These answers are built from the facts on screen, not by an AI model, so free-form questions aren’t supported.'
  }
  const ask = (q) => {
    if (!q.trim()) return
    setExtra((m) => [...m, ['you', q], ['granite', answer(q)]])
    setDraft('')
  }

  return (
    <>
      <main className="flex h-full min-w-0 flex-1 flex-col gap-4 pt-2">
        <div className="flex shrink-0 items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <PageTitle title="Ask why" subtitle="Ask why anything is ranked where it is. Answers use only the facts shown." />
          </div>
          <button type="button" onClick={onOpenFixFirst} className="shrink-0 cursor-pointer rounded-full border border-line bg-card px-4 py-2.5 text-sm font-medium text-ink hover:bg-page">
            Back to Fix first
          </button>
        </div>
        <section className="flex min-h-0 w-full flex-1 flex-col rounded-[24px] bg-card px-7 pt-6 pb-5">
          <div ref={listRef} className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto pr-1">
            <Bubble>
              Why is {a.c.name} ranked above {b.c.name}? Their CVSS scores are {Math.abs(a.cvss - b.cvss) <= 0.5 ? 'almost the same' : `${a.cvss} and ${b.cvss}`}.
            </Bubble>
            <Answer>
              <p className="text-sm text-ink">
                Both would be bad if attacked, but {a.c.name} is {a.kev > b.kev || a.epss > b.epss ? 'far more likely to be attacked' : 'ranked higher on the facts we have'}. That’s what we rank on.
              </p>
              <div className="flex gap-3">
                <CompareCard f={a} strong />
                <CompareCard f={b} />
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-ink-muted">
                Based on
                {['CISA KEV', 'FIRST EPSS', 'NIST NVD'].map((s) => (
                  <span key={s} className="rounded-full bg-blue-soft px-2 py-0.5 text-blue-ink">{s}</span>
                ))}
                <button type="button" onClick={onOpenFixFirst} className="cursor-pointer font-semibold text-blue-ink hover:underline">
                  Open {a.c.name} in Fix first ↗
                </button>
                <button type="button" onClick={() => onScreen({ name: 'component', id: a.c.id })} className="cursor-pointer font-semibold text-blue-ink hover:underline">
                  {a.c.name} details ↗
                </button>
              </div>
            </Answer>
            <Bubble>So is CVSS useless?</Bubble>
            <Answer note>
              <p className="text-sm text-ink">
                No. CVSS says how bad an attack would be. Chance of attack says how likely one is. {a.c.name} is high on {a.cvss >= 7 ? 'both' : 'likelihood'}, so it comes first.
              </p>
            </Answer>
            {extra.map(([who, text], i) =>
              who === 'you' ? (
                <Bubble key={i}>{text}</Bubble>
              ) : (
                <Answer key={i} note>
                  <p className="text-sm text-ink">{text}</p>
                </Answer>
              ),
            )}
          </div>
          <div className="flex shrink-0 items-center gap-2 pt-4 text-xs text-ink-muted">
            Try asking
            {['What changed this week?', 'Which software is riskiest?', 'Why is #2 above #3?'].map((q) => (
              <button key={q} type="button" onClick={() => ask(q)} className="cursor-pointer rounded-full bg-purple-soft px-3 py-1.5 text-ink hover:brightness-95">
                {q}
              </button>
            ))}
          </div>
          <form onSubmit={(e) => (e.preventDefault(), ask(draft))} className="mt-3 flex shrink-0 items-center gap-2 rounded-full border border-line-strong py-1.5 pr-1.5 pl-4">
            <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Ask a question…" aria-label="Ask a question" className="min-w-0 flex-1 bg-transparent text-sm text-ink outline-none placeholder:text-ink-muted" />
            <button type="submit" aria-label="Send" className="flex size-8 cursor-pointer items-center justify-center rounded-full bg-blue hover:bg-primary-strong">
              <Icon name="fixfirst/arrow-up-white" className="size-4" />
            </button>
          </form>
        </section>
      </main>
      <SidePanel>
        <BlueCard action={'Open in Fix first  →'} onAction={onOpenFixFirst}>
          Fix {a.c.name} first. We rank by how likely an attack is, not only by how bad it would be.
        </BlueCard>
        <SideBox tone="teal" icon="software/eye-teal" title="Side by side">
          <div className="grid grid-cols-[1fr_auto_auto] gap-x-4 gap-y-1.5 text-sm">
            <span />
            <span className="text-xs text-ink-muted">{a.c.name}</span>
            <span className="text-xs text-ink-muted">{b.c.name}</span>
            {[
              ['Rank', `#${a.rank}`, `#${b.rank}`],
              ['Attack chance', a.epss.toFixed(2), b.epss.toFixed(2)],
              ['CVSS', a.cvss, b.cvss],
              ['On KEV list', a.kev ? 'Yes' : 'No', b.kev ? 'Yes' : 'No'],
            ].map(([l, x, y]) => (
              <div key={l} className="contents">
                <span className="text-ink-muted">{l}</span>
                <span className="text-right font-semibold text-ink">{x}</span>
                <span className="text-right font-semibold text-ink">{y}</span>
              </div>
            ))}
          </div>
        </SideBox>
        <SideBox tone="purple" icon="software/eye-purple" title="About these answers">
          <p className="text-[13px] leading-[19px] text-ink-muted">
            These answers are filled in from the facts on screen (CISA KEV, FIRST EPSS, NIST NVD) by fixed rules. No AI model writes them, so they can’t be wrong about the facts, but they only cover the suggested questions.
          </p>
        </SideBox>
      </SidePanel>
    </>
  )
}

function Bubble({ children }) {
  return <p className="max-w-[70%] self-end rounded-[18px] bg-brand px-4 py-2.5 text-sm text-white">{children}</p>
}

function Answer({ children, note }) {
  return (
    <div className="flex gap-3">
      <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-ai">
        <Icon name="fixfirst/icon-idea" className="size-4" />
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-2.5">
        <p className="text-xs text-ink-muted">
          <b className="text-sm text-ink">Answer</b> · from the facts shown
        </p>
        {children}
        {note && <p className="text-xs text-purple-ink">Built from the facts on screen, not by an AI model.</p>}
      </div>
    </div>
  )
}
