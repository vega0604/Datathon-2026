import { useContext, useMemo, useRef, useState } from 'react'
import ReactApexChart from 'react-apexcharts'
import { IconDarkContext } from '../../lib/iconTheme'

// react-apexcharts ships CommonJS only; Vite's dev server hands back the module
// object instead of the component, so unwrap `.default` when it's there.
const Chart = ReactApexChart.default ?? ReactApexChart

// Coverage curve for Model overview, drawn with ApexCharts. Colours are the ones
// from the Figma "Catch rate" frame (light + dark): blue line and soft area for
// our model, grey dashed baselines, V5 line/ink tokens for grid and labels.
const PALETTE = {
  light: {
    model: '#0f62fe',
    baseline: '#a7afbf',
    grid: '#e2e6ee', // --color-line
    axis: '#a7afbf', // --color-line-strong
    ref: '#1f2633', // --color-ink
    ink: '#1f2633',
    muted: '#5a6377', // --color-ink-muted
    calloutBg: '#d9fbfb', // --color-green-soft
    calloutInk: '#005d5d', // --color-green-ink
  },
  dark: {
    model: '#4589ff',
    baseline: '#a7afbf',
    grid: '#2c3443',
    axis: '#5a6377',
    ref: '#e9ecf3',
    ink: '#e9ecf3',
    muted: '#a7afbf',
    calloutBg: '#0b2e30',
    calloutInk: '#3ddbd9',
  },
}

// Our model is solid; the baselines keep distinct dash patterns as in Figma.
const DASH = [0, 6, 2, 4]
const STEP = 100 // CVEs between curve points
const X_MAX = 5000
const Y_MAX = 80
const SNAP = 10 // the marker moves in steps of 10 CVEs
const KEY_STEP = 100 // arrow keys move it by 100 CVEs

const kLabel = (v) => (v === 0 ? '0' : `${Math.round(v / 100) / 10}k`)
const font = "'IBM Plex Sans', system-ui, sans-serif"
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v))

/** Value of a curve sampled every STEP CVEs, at any x (linear between points). */
function valueAt(curve, x) {
  const i = clamp(Math.floor(x / STEP), 0, curve.length - 2)
  const t = clamp((x - i * STEP) / STEP, 0, 1)
  return curve[i] + t * (curve[i + 1] - curve[i])
}

/** The plot area's position and visible range, read from Apex after each draw. */
function readPlot(chart) {
  const g = chart.w.globals
  return {
    left: g.translateX,
    top: g.translateY,
    width: g.gridWidth,
    height: g.gridHeight,
    minX: g.minX,
    maxX: g.maxX,
    minY: g.minY,
    maxY: g.maxY,
  }
}

const samePlot = (a, b) => a && b && Object.keys(a).every((k) => a[k] === b[k])

const reducedMotion =
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

export function CatchRateChart({ series, top500 }) {
  const dark = useContext(IconDarkContext)
  const c = dark ? PALETTE.dark : PALETTE.light

  // Where the marker sits (CVEs fixed), and the plot box it moves in. It follows
  // the mouse while hovering the plot and eases back to top500.at on leave.
  const [at, setAt] = useState(top500.at)
  const [hovering, setHovering] = useState(false)
  const [plot, setPlot] = useState(null)
  const plotRef = useRef(null)

  const curve = series[0].curve
  const caught = valueAt(curve, at)

  // Options only change with the theme or data, so dragging never redraws Apex.
  const { options, chartSeries } = useMemo(() => {
    const syncPlot = (chart) => {
      const next = readPlot(chart)
      setPlot((prev) => (samePlot(prev, next) ? prev : next))
    }

    // End-of-line labels, nudged apart where the baselines bunch up.
    const endLabels = series.map((s, i) => ({
      x: X_MAX,
      y: s.curve.at(-1),
      marker: { size: 0, strokeWidth: 0, fillColor: 'transparent', strokeColor: 'transparent' },
      label: {
        text: `${s.label} · ${s.value}%`,
        textAnchor: 'start',
        offsetX: 10,
        offsetY: i === 0 ? 14 : 12 + [0, 6, 14][i - 1],
        borderWidth: 0,
        style: {
          background: 'transparent',
          color: i === 0 ? c.ink : c.muted,
          fontSize: i === 0 ? '14px' : '12px',
          fontWeight: i === 0 ? 600 : 400,
          fontFamily: font,
        },
      },
    }))

    return {
      chartSeries: series.map((s, i) => ({
        name: s.label,
        type: i === 0 ? 'area' : 'line',
        data: s.curve.map((y, j) => [j * STEP, y]),
      })),
      options: {
        chart: {
          type: 'line',
          stacked: false,
          fontFamily: font,
          foreColor: c.muted,
          background: 'transparent',
          parentHeightOffset: 0,
          zoom: { type: 'x', enabled: true, autoScaleYaxis: true },
          toolbar: {
            show: true,
            autoSelected: 'zoom',
            tools: { download: false, selection: false, pan: false, zoom: true, zoomin: true, zoomout: true, reset: true },
          },
          animations: { enabled: !reducedMotion, speed: 700 },
          // Keep the marker overlay lined up after resizes and zooms.
          events: { mounted: syncPlot, updated: syncPlot },
        },
        theme: { mode: dark ? 'dark' : 'light' },
        colors: [c.model, c.baseline, c.baseline, c.baseline],
        stroke: { curve: 'smooth', width: [3, 2, 2, 2], dashArray: DASH, lineCap: 'round' },
        fill: {
          type: ['gradient', 'solid', 'solid', 'solid'],
          gradient: {
            shadeIntensity: 1,
            inverseColors: false,
            opacityFrom: 0.24,
            opacityTo: 0,
            stops: [0, 90, 100],
          },
        },
        dataLabels: { enabled: false },
        markers: { size: 0, hover: { size: 4 } },
        legend: { show: false }, // the page shows legend pills above the chart
        grid: {
          borderColor: c.grid,
          strokeDashArray: 0,
          xaxis: { lines: { show: false } },
          yaxis: { lines: { show: true } },
          // Room on the right for the end-of-line labels.
          padding: { top: 0, right: 150, bottom: 0, left: 4 },
        },
        xaxis: {
          type: 'numeric',
          min: 0,
          max: X_MAX,
          tickAmount: 5,
          labels: { formatter: kLabel, style: { colors: c.muted, fontSize: '12px' } },
          axisBorder: { show: true, color: c.axis },
          axisTicks: { show: false },
          title: { text: 'CVEs fixed', style: { color: c.muted, fontSize: '12px', fontWeight: 400 } },
          tooltip: { enabled: false },
        },
        yaxis: {
          min: 0,
          max: Y_MAX,
          tickAmount: 4,
          labels: { formatter: (v) => `${Math.round(v)}%`, style: { colors: c.muted, fontSize: '12px' } },
        },
        // The green callout follows the mouse instead of Apex's tooltip.
        tooltip: { enabled: false },
        annotations: { points: endLabels },
      },
    }
  }, [series, dark, c])

  // Pointer → CVEs. Uses the plot box's on-screen rect, so it stays right
  // under the page's CSS zoom (useFitHeight) too.
  // (Visible x range read up front: the React Compiler pre-reads values the
  // handler uses, and `plot` is still null before Apex's first draw.)
  const minX = plot?.minX ?? 0
  const maxX = plot?.maxX ?? X_MAX
  const reset = () => {
    setHovering(false)
    setAt(top500.at)
  }

  // Follow the mouse while it's over the plot area; leave it → back to the default.
  const onPointerMove = (e) => {
    const rect = plotRef.current?.getBoundingClientRect()
    if (!rect) return
    const inside =
      e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom
    if (!inside) {
      if (hovering) reset()
      return
    }
    const f = (e.clientX - rect.left) / rect.width
    const x = minX + f * (maxX - minX)
    setHovering(true)
    setAt(clamp(Math.round(x / SNAP) * SNAP, 0, X_MAX))
  }
  const onKeyDown = (e) => {
    const delta = { ArrowLeft: -KEY_STEP, ArrowDown: -KEY_STEP, ArrowRight: KEY_STEP, ArrowUp: KEY_STEP }[e.key]
    if (e.key === 'Home') setAt(0)
    else if (e.key === 'End') setAt(X_MAX)
    else if (delta) setAt((v) => clamp(v + delta, 0, X_MAX))
    else return
    e.preventDefault()
  }

  // Marker position inside the plot box (hidden when zoomed out of view).
  const fx = plot ? (at - plot.minX) / (plot.maxX - plot.minX) : 0
  const fy = plot ? 1 - (caught - plot.minY) / (plot.maxY - plot.minY) : 0
  const inView = plot && fx >= 0 && fx <= 1
  const share = ((at / top500.queueSize) * 100).toFixed(1)
  const flip = fx > 0.55 // callout goes left of the line near the right edge
  // Snap to the mouse while hovering; glide when returning to the default spot.
  const glide = hovering || reducedMotion ? undefined : 'left 350ms ease, top 350ms ease, transform 350ms ease'

  return (
    <div className="relative h-full w-full" onPointerMove={onPointerMove} onPointerLeave={reset}>
      <div className="absolute inset-0">
        <Chart key={dark ? 'dark' : 'light'} options={options} series={chartSeries} type="line" height="100%" width="100%" />
      </div>

      {plot && (
        <div
          ref={plotRef}
          className="pointer-events-none absolute"
          style={{ left: plot.left, top: plot.top, width: plot.width, height: plot.height }}
        >
          {inView && (
            <>
              {/* Reference line */}
              <div className="absolute top-0 bottom-0 w-px" style={{ left: `${fx * 100}%`, background: c.ref, transition: glide }} />

              {/* Callout */}
              <div
                className="absolute top-2 flex flex-col gap-0.5 rounded-xl px-3 py-2 whitespace-nowrap"
                style={{
                  left: `${fx * 100}%`,
                  transform: flip ? 'translateX(calc(-100% - 12px))' : 'translateX(12px)',
                  background: c.calloutBg,
                  color: c.calloutInk,
                  transition: glide,
                }}
              >
                <span className="type-label">
                  Fix {at.toLocaleString()} ({share}%)
                </span>
                <span className="text-sm leading-[18px] font-semibold tracking-body">
                  Catch {Math.round(caught)}% of exploited CVEs
                </span>
              </div>

              {/* Marker: same 7px-radius dot with a 3px white ring as before. Mouse
                  hover moves it; it stays focusable so arrow keys move it too. */}
              <div
                role="slider"
                tabIndex={0}
                aria-label="CVEs fixed"
                aria-valuemin={0}
                aria-valuemax={X_MAX}
                aria-valuenow={at}
                aria-valuetext={`Fix ${at.toLocaleString()} CVEs, catch ${Math.round(caught)}% of exploited CVEs`}
                className="absolute flex size-8 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full outline-none focus-visible:ring-2 focus-visible:ring-offset-0"
                style={{ left: `${fx * 100}%`, top: `${fy * 100}%`, '--tw-ring-color': c.model, transition: glide }}
                onKeyDown={onKeyDown}
              >
                <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
                  <circle cx="10" cy="10" r="7" fill={c.model} stroke="#ffffff" strokeWidth="3" />
                </svg>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
