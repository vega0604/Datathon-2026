# Handoff: build the Insights → Severity page (Before the Breach)

You are picking up frontend work on **Before the Breach**, our IBM-track project for the Sheridan Datathon 2026 (Nov 7–8). Read this whole file before editing. It is self-contained: everything gathered so far (repo layout, conventions, the full Figma spec, chart numbers, asset IDs, Linear tickets) is below.

**Your task:** implement the Figma frame **"V5 · Insights · Severity · Light"** as the `severity` section of the existing Insights view in `frontend/`, reusing the components and tokens already in the repo. Then verify it against the Figma screenshot.

---

## 1. Project context (why this page exists)

- Challenge (repo `README.md`): predict which CVEs attackers will exploit and show engineers what to fix first and why. Answer key is CISA's KEV list. Benchmark: `scoreboard_2026.csv`, 72,670 CVEs, we submit `top500.csv`. Public baselines catch 6–8 in the top 500.
- Judging: Discovery 35%, Data use 25%, Communication 25%, Impact 15%. This page is mostly **Communication**: each chart states its finding in the title and ends with a one-sentence takeaway.
- App name: "Before the Breach", subtitle "Vulnerability triage". Demo user: Jane Doe, Security lead.

## 2. Repo and frontend conventions (follow these, don't invent new ones)

Repo root: `Datathon-2026/` (has `backend/` Python/uv and `frontend/`). **Only change `frontend/`.** Never commit data or CSVs.

Frontend stack (`frontend/package.json`):
- React 19, **plain JSX (no TypeScript)**, Vite 8, **Tailwind v4** via `@tailwindcss/vite`, React Compiler via babel preset, ESLint (`npm run lint`).
- Fonts are self-hosted via `@fontsource/ibm-plex-sans` (300/400/600) and `ibm-plex-mono`, imported in `src/main.jsx`. Don't add Google Fonts links.

Layout of `frontend/src/`:
```
App.jsx                         page state: 'insights' | 'fixFirst' (no router)
views/InsightsSummary.jsx       Insights view; holds `section` state from the sidebar
views/FixFirstQueue.jsx         Fix first view (uses className "theme-v5")
components/insights/AppHeader.jsx       header; prop iconDir='insights' (V4) | 'fixfirst' (V5 icons)
components/insights/InsightsSidebar.jsx sidebar; sub-nav from data/insights.js → insightsNav
components/insights/NextStepsPanel.jsx  right panel, currently hard-wired to Summary content
components/insights/CoverageCard.jsx    good pattern: chart drawn as SVG with viewBox so it scales
components/insights/SideColumn.jsx, ThemeToggle.jsx (visual only; dark does nothing yet)
data/insights.js                user, coverage, kpis, versusPublic, aboutData, insightsNav
data/queue.js                   Fix first sample data + totals (sidebar pills use totals.open/critical)
lib/Icon.jsx                    <Icon name="insights/kpi-eye" className="size-4" /> → /icons/insights/kpi-eye.svg
index.css                       @theme tokens, type-label / type-body / type-body-compact utilities,
                                custom variants `short:` (max-height 820px) and `wide:` (min-width 1440px),
                                and the `.theme-v5` class that swaps in the V5 palette
```
Static Figma assets live in `frontend/public/icons/<group>/` and are served at `/icons/...` through `Icon`/`iconUrl`. `scripts/fetch-figma-assets.mjs` (`npm run fetch-assets`) downloads them; it currently has ONE hard-coded asset prefix for the Fix-first frame.

How the Severity section is reached today: `InsightsSummary.jsx` renders `<SummaryContent>` when `section === 'summary'`, and an **empty `<main aria-label={section}>` for every other section**. Severity's sidebar id is `'severity'`.

Uncommitted work exists in the repo (modified FixFirstQueue, queue.js, index.css, AppHeader, ThemeToggle; new `public/icons/fixfirst/`; deleted `components/Header.jsx`, `Highlights.jsx`). Don't revert or reformat any of it. Ask the user before committing. Commit style: `SHE-90 feat(web): add severity insights section`.

## 3. Figma source

- File: **Datathon 2026**, key `3TP44uGMhwnf9d0wufWqIL`
- Frame: **node `221:376`**, "V5 · Insights · Severity · Light"
- URL: https://www.figma.com/design/3TP44uGMhwnf9d0wufWqIL/Datathon-2026?node-id=221-376
- If you have the Figma MCP, call `get_design_context` on `221:376` (with a screenshot) for fresh code and asset URLs, and use the screenshot as the visual target. Everything below came from that call on 2026-11-07.

### Token mapping: Figma V5 variable → existing Tailwind class
The frame uses the **V5 palette**. Put `theme-v5` on the Insights view's root div (as FixFirstQueue does) so these resolve correctly. Then check that Summary still looks right. If it doesn't, scope `theme-v5` to the Severity section only.

| Figma variable | Value | Use this class |
|---|---|---|
| surface/page | #f5f7fb | `bg-page` |
| surface/card | #fff | `bg-card` |
| surface/subtle | #eef1f7 | `bg-subtle` |
| border/subtle | #e2e6ee | `border-line` / `bg-line` |
| text/primary | #1f2633 | `text-ink` |
| text/secondary | #5a6377 | `text-ink-muted` |
| text/on-brand | #fff | `text-white` |
| brand/primary, chart/series-1 | #0f62fe | `bg-blue` / `text-blue` |
| brand/soft | #eaf2ff | `bg-blue-soft` |
| brand/strong-text | #0043ce | `text-blue-ink` |
| ai/primary | #8a3ffc | `bg-ai` |
| ai/soft | #f4eeff | `bg-purple-soft` |
| ai/strong-text | #6929c4 | `text-purple-ink` |
| accent/teal-soft | #d9fbfb | `bg-green-soft` |
| accent/teal-ink | #005d5d | `text-green-ink` |
| status/critical-strong | #da1e28 | `bg-crit` (under theme-v5) |
| chart/context | #a7afbf | `bg-line-strong` (under theme-v5) |
| status tag text | #161616 | `text-text-primary` |
| card shadow `0 12 32 -6 rgba(15,23,41,.07), 0 1 3 0 rgba(15,23,41,.05)` | | `shadow-float` |

Type (Carbon, IBM Plex Sans): label 12/16 +0.32 → `type-label`; body-compact 14/18 +0.16 → `type-body-compact`; body 14/20 +0.16 → `type-body`; body-02 16/24 → `text-base leading-6`; heading-03 20/28 → `text-xl leading-7`; page title 44/52 Light → copy Summary's `text-[clamp(30px,3vw,44px)] leading-[1.18] font-light`.

### Frame structure (1512-wide design; screenshot is the target)
```
Header (same as existing AppHeader; use iconDir="fixfirst" for V5 icons)
Body: flex gap-20 p-20
├─ Sidebar 220w  (existing InsightsSidebar; "Severity" sub-item is current)
├─ Main flex-1, pt-8, gap-20
│   ├─ Title "Severity isn’t enough"
│   │  Sub  "Severity scores alone miss most attacks. Our ranking flags them earlier."
│   │  (No "Download charts" button on this frame.)
│   └─ Analysis panel: bg-card rounded-[32px] p-24 shadow-float, fills height
│       └─ Row gap-20:
│           ├─ Chart card A (340w, bg-page rounded-24 p-24 gap-16)  Severity vs exploitation · SHE-61
│           └─ Chart card B (flex-1, bg-page rounded-24 p-24 gap-16) Lead time · SHE-67
└─ Next steps panel 320w, bg-card rounded-24 p-24 gap-20 shadow-float
    ├─ "What to do" card: bg-blue rounded-24 p-24, flex-1 (fills spare height), justify-between
    ├─ "How to read this" box: bg-green-soft rounded-20 p-20 gap-10
    └─ "About this data" box: bg-purple-soft border border-line rounded-20 p-20 gap-10
```

### Sidebar differences in V5
In the V5 frame each sub-nav chip has its own colour and icon colour. The repo currently uses `bg-blue-soft` for all of them.

| id | label | chip bg | Figma icon asset |
|---|---|---|---|
| summary | Summary | blue-soft | 3b54c |
| catch-rate | Catch rate | green-soft (teal) | 2bc72 |
| severity | Severity | purple-soft (ai) | 7f89d |
| timing | Time to attack | blue-soft | 9b5ef |
| vendors | Vendors | green-soft | c1726 |
| bug-types | Bug types | purple-soft | 8e5b7 |
| model | Model check | blue-soft | f8c0b |

Current item: `bg-blue-soft`, label `font-semibold text-blue-ink`. Nav icons: Fix first queue e7a37 (already = `fixfirst/nav-queue`), Insights target 45bf3 (already = `fixfirst/nav-target`). Fix first pills: 38 (blue-soft) and 6 (crit). These already come from `totals`. Update `insightsNav` chips/icons only if you move the Insights view to V5; it's shared with Summary.

### Chart card A: "Severity alone misses most attacks" (SHE-61)
- Title (text-xl/28, ink): **Severity alone misses most attacks**
- Subtitle (type-body, ink-muted): **Share reaching KEV, by CVSS band**
- Plot box 292×291. Four bars, 46 wide, x = 13.5, 86.5, 159.5, 232.5. Each has a white track (`bg-card`, rounded-23) from y=45.55 to the bottom (height 245.452). Bars are bottom-aligned at y=291.

| Band | CVSS | KEV share | Bar height | Bar fill |
|---|---|---|---|---|
| Critical | 9.0 to 10 | 1.9% | 186.544 | solid `bg-ai`, rounded-23 |
| High | 7.0 to 8.9 | 0.7% | 68.727 | hatched SVG asset d75cb |
| Medium | 4.0 to 6.9 | 0.2% | 19.636 | hatched SVG asset 9dc42 |
| Low | 0.1 to 3.9 | 0.04% | 7.591 | hatched SVG asset 2b407 |

- Value labels (type-body-compact semibold, ink) are centred over High/Medium/Low, with label top = bar top − 25.44.
- Critical has no value label. Instead a tooltip pill (`bg-purple-soft rounded-12 px-12 py-8`, `type-body-compact font-semibold text-purple-ink`) reads **"1.9% reach KEV"** at left −13.5, top 53.3. It overhangs the plot's left edge on purpose.
- X axis below the plot: 4 equal columns, each with a **status tag** above the CVSS range (type-label, ink-muted).
  - Status tag: `bg-subtle rounded-12 px-8 py-4 gap-4`, a 12px shape icon, then the label (type-label, `text-text-primary`). Shapes: Critical ad03e, High 3f48b, Medium 257ee, Low 5da3e. Critical and High already exist as `public/icons/status-critical.svg` and `status-high.svg` (same asset ids).
  - Figma rule: "Status is never colour alone: each variant pairs a Carbon status colour with a distinct shape, a 1px text/primary outline and a text label."
- **Takeaway** box (purple variant): `bg-purple-soft rounded-12 p-16 gap-12`, 16px idea icon (asset 12931), then "Takeaway" (type-label, text-blue-ink) and the body text (text-base leading-6, ink):
  > Critical CVEs reach KEV about 10× as often as Medium ones, yet 98% of them are never exploited.

### Chart card B: "We flag most exploited CVEs weeks before CISA" (SHE-67)
- Title: **We flag most exploited CVEs weeks before CISA**. Subtitle: **2025 KEV entries, by days between our top-K flag and the KEV listing**
- Legend pills (`bg-card rounded-full px-12 py-6 gap-8`, 12px swatch rounded-4, type-label ink):
  - "Flagged before KEV": swatch `bg-blue`
  - "Flagged after KEV": swatch `bg-line-strong` (#a7afbf)
- Plot box 440×351.
  - Baseline (0) at y=314.33. Gridlines every 5 CVEs = 52.39px (y = 314.33, 261.94, 209.55, 157.16, 104.78, 52.39), from x=21.46, width 418.537. Baseline uses asset 65bcf, the others a3264.
  - Y labels 0–25 (type-label, ink-muted), right-aligned to x≈17.3, vertically centred on their line.
- Bars are 37.561 wide, at x = 44.54 + i×83.7, with height = count × 10.478:

| Bucket | Count | Bar fill | Dot (12px, centred on bar top) | Value label |
|---|---|---|---|---|
| After listing | 9 | hatched grey asset ded77 | grey dot facaa | "9" |
| 0 to 7 days | 14 | hatched blue asset 1304e | blue dot 754b0 | "14" |
| 8 to 30 days | 22 | solid `bg-blue` rounded-28 | blue dot 754b0 | none (tooltip) |
| 31 to 90 days | 18 | hatched blue asset 8c963 | blue dot 754b0 | "18" |
| Over 90 days | 7 | hatched blue asset f835b | blue dot 754b0 | "7" |

  - Value labels: type-body-compact semibold ink, centred, top = bar top − 33.88.
  - X labels: type-label ink-muted, centred under each bar at y=327.28.
  - Peak tooltip at left 146.78, top 21.15: `bg-blue-soft rounded-12 px-12 py-8 gap-2 text-blue-ink`, with "Peak · median 19 days early" (type-label) and **"22 CVEs"** (type-body-compact semibold).
- Takeaway (blue variant, `bg-blue-soft`, same structure as above):
  > Our model raised the flag before CISA for about 9 in 10 of the KEV entries it caught, a median of 19 days early.

### Next steps panel (Severity version)
- **What to do** card (bg-blue, rounded-24, p-24, flex-1, flex-col justify-between, overflow hidden):
  - Pill: "What to do" (white 1px border, rounded-full px-12 py-6, type-label white).
  - Text (text-xl leading-7, white): **Don’t sort by severity score alone. The Fix first order flags threats weeks before CISA does.**
  - Button at the bottom: white rounded-full px-20 py-12, text-base leading-6 semibold `text-blue`, label `Open Fix first  →` (two spaces, `whitespace-pre`). Wire it to `onOpenFixFirst`.
  - Decorations (absolute, `pointer-events-none`, drawn on top): ring 260px asset 419e1 at (150, −120); ring 160px asset 184b1 at (−70, 120); dot 8px asset 2990a at (220, 208); dot 6px asset 10678 at (248, 256).
- **How to read this** (bg-green-soft): 28px white chip with a 15px eye icon (asset 54436), title "How to read this" (text-base leading-6 semibold `text-green-ink`), then body (type-body ink):
  > Left: the share of each severity band that later got attacked. Right: how many days before CISA’s listing we flagged them.
- **About this data** (bg-purple-soft, border-line): 28px white chip with a 16px data icon (asset 68bf6), title "About this data" (semibold `text-purple-ink`), then rows (type-body: label ink-muted flex-1, value semibold ink). The rows are exactly the existing `aboutData` export (Trained on 2024 CVEs · Tested on 2025 CVEs · CVEs scored 72,670).
- There is no "Download this chart" button on this frame.

`NextStepsPanel` is currently hard-wired to Summary's content (compact What-to-do, "Versus public scores", "Download this chart"). Either make it configurable (the What-to-do text, the size, and which fact boxes to show) or add a `SeverityNextSteps` component that reuses `FactBox`. Don't break Summary.

## 4. Assets

Asset URL prefix for this frame (it differs from the Fix-first prefix in the current script):
```
https://www.figma.com/api/mcp/asset/ee03c974-ecc2-4a3c-8931-7b2ec5af53a4/<id>.<ext>
```
**These links expire around 2026-11-14.** If they 404, re-run `get_design_context` on `221:376` to get fresh URLs. Never reference these URLs at runtime. Download them into `public/icons/insights-v5/` (or `insights/severity/`) and use `<Icon name=...>`.

| Suggested local name | id | Where it's used |
|---|---|---|
| sev-bar-high.svg | d75cb | card A High bar |
| sev-bar-medium.svg | 9dc42 | card A Medium bar |
| sev-bar-low.svg | 2b407 | card A Low bar |
| status-medium.svg | 257ee | status tag (critical ad03e / high 3f48b already in `public/icons/`) |
| status-low.svg | 5da3e | status tag |
| icon-idea.svg | 12931 | takeaway icon (check whether it matches `fixfirst/icon-idea.svg` first) |
| grid-baseline.svg | 65bcf | card B 0-line |
| grid-line.svg | a3264 | card B other gridlines |
| lead-bar-after.svg | ded77 | card B After listing |
| lead-bar-0-7.svg | 1304e | card B 0 to 7 days |
| lead-bar-31-90.svg | 8c963 | card B 31 to 90 days |
| lead-bar-over-90.svg | f835b | card B Over 90 days |
| lead-dot-grey.svg | facaa | card B dot on After listing |
| lead-dot-blue.svg | 754b0 | card B dots on the other 4 bars |
| todo-ring-lg.svg | 419e1 | What to do decoration |
| todo-ring-sm.svg | 184b1 | What to do decoration |
| todo-dot-8.svg | 2990a | What to do decoration |
| todo-dot-6.svg | 10678 | What to do decoration |
| read-eye.svg | 54436 | How to read this chip |
| about-data.svg | 68bf6 | About this data chip |
| sub-target.svg | 3b54c | V5 sidebar Summary |
| sub-shield-teal.svg | 2bc72 | V5 sidebar Catch rate |
| sub-arrow-ai.svg | 7f89d | V5 sidebar Severity |
| sub-bell.svg | 9b5ef | V5 sidebar Time to attack |
| sub-queue-teal.svg | c1726 | V5 sidebar Vendors |
| sub-eye-ai.svg | 8e5b7 | V5 sidebar Bug types |
| sub-shield-blue.svg | f8c0b | V5 sidebar Model check |

Header assets (sun 6725a, moon a5b3f, notifications f4afc, plus 65891, avatar d6f9b.png) are the same as the existing `fixfirst/` set, so use `AppHeader iconDir="fixfirst"`.

Extend `scripts/fetch-figma-assets.mjs` so each entry can carry its own prefix and output subfolder (or add a second ASSETS block for this frame). Then run `npm run fetch-assets` and confirm every file is non-empty. Don't redraw, inline or alter any SVG. Keep each SVG's own width and height; size the slot to match.

## 5. Data

The chart numbers above are **sample values from the Figma design**. Linear SHE-61 (severity vs exploitation) and SHE-67 (lead-time analysis) are still in Backlog, so the backend doesn't produce them yet. There is no `/api/charts` route yet (backend routes: health, meta, sboms).

Add a `severity` export to `src/data/insights.js` holding the bands (label, range, share, value) and lead-time buckets (label, count, flaggedBefore), plus the takeaways. Add a comment like the existing ones: "sample values until SHE-61 / SHE-67 land". Compute bar heights from the values with the same scales as Figma:
- Card A: Critical 1.9% → 186.544px, so ≈98.2 px per 1%. The low bands look slightly larger than linear; keep Figma's heights as given, or use a minimum visible height of about 7.6px.
- Card B: 10.478 px per CVE.

Make sure the tooltip and label positions follow the data.

Related Linear issues (team "sheridan-minions"), useful if you're asked to fill the other Insights sections later. **Do not design those sections yourself**; they need Figma frames first.
- SHE-90 Insights page (frontend): every SHE-9 chart rendered with a one-sentence takeaway. Backend plans to serve `GET /api/charts/{name}` (Plotly JSON or PNG from `outputs/charts/`).
- SHE-9 children: SHE-60 chart theme · SHE-61 severity vs exploitation · SHE-62 time-to-KEV curve · SHE-63 vendor treemap · SHE-64 CWE bubble chart · SHE-65 coverage curve vs baselines · SHE-66 leakage chart · SHE-67 lead time · SHE-68 UMAP (stretch) · SHE-69 export charts.
- Likely mapping (unconfirmed): Catch rate→SHE-65, Severity→SHE-61 + SHE-67, Time to attack→SHE-62, Vendors→SHE-63, Bug types→SHE-64, Model check→SHE-66.

## 6. Implementation plan

1. Read the files listed in §2 so your code matches their patterns.
2. Download the assets (§4).
3. Add the `severity` data to `data/insights.js`.
4. Create `components/insights/StatusTag.jsx` and `components/insights/Takeaway.jsx` (tone: `'ai' | 'brand'`). Fix first may already have similar pieces in `components/WhyPanel.jsx` or `QueueTable.jsx`; reuse them if so.
5. Create `components/insights/SeverityChart.jsx` and `LeadTimeChart.jsx`. Draw the plots like `CoverageCard`, as an SVG with a viewBox of the Figma plot size (292×291, 440×351) so they scale down on short or narrow screens. Use `<rect>` for solid bars and tracks, `<image href={iconUrl(...)}>` for the hatched bars, dots and gridlines, and `<text>` for labels. Tooltips can be HTML positioned over the SVG.
6. Make the Next steps panel show the Severity version (§3).
7. In `InsightsSummary.jsx`, render `<SeverityContent onOpenFixFirst=…>` when `section === 'severity'`. Keep the empty `<main>` for the other unbuilt sections.
8. Apply `theme-v5` (see §3) and, if you do, the V5 sidebar chips and icons.
9. Responsive behaviour should match Summary: `min-w-[1024px]`, `h-screen`, the `xl:` / `short:` spacing steps, and no page scroll at 1440×900 or 1512×982.

## 7. Done when

- At 1512 wide, Severity matches the Figma screenshot: layout, copy (curly quotes ’ and the × sign), colours, every asset in its slot, and the tooltip positions.
- Summary and Fix first look the same as before.
- No `figma.com/api/mcp/asset` URLs in `src/`; every asset file in `public/icons/` is non-empty.
- `npm run lint` and `npm run build` pass. The sidebar switches Summary ↔ Severity, and "Open Fix first →" opens the queue.
- The status tag shows a shape plus a label, never colour alone. Plots have an `aria-label` that summarises the values.

## 8. Notes

- An earlier standalone prototype of this page was built in the wrong repo (`~/nodenode/frontend/before-the-breach/`, TypeScript, before we found this project). Don't copy it. This file has everything from it, and you can delete that folder.
- The Figma logo is still a dashed "Logo" placeholder, which already matches `AppHeader`.
- Dark mode isn't designed yet. Leave `ThemeToggle` as it is.
