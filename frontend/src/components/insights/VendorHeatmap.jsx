import { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy'
import { AnimatePresence, MotionConfig, motion } from 'motion/react'
import { SHADE } from './vendorShades'

const GAP = 6 // px between cells

/** Tracks an element's content size. */
function useSize(ref) {
  const [size, setSize] = useState({ width: 0, height: 0 })
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      setSize({ width: Math.floor(width), height: Math.floor(height) })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return size
}

// Picks a label that fits the cell without truncating: the full name, then the full name
// in a smaller font, then the short name. null hides it (the tooltip still has the name).
// Widths are rough per-character estimates for IBM Plex Sans semibold.
function fitLabel(cell, w) {
  const room = w - 20
  if (cell.name.length * 8.4 <= room) return { text: cell.name, small: false }
  if (cell.name.length * 7.2 <= room) return { text: cell.name, small: true }
  if (cell.short && cell.short.length * 8.4 <= room) return { text: cell.short, small: false }
  return null
}

/**
 * Vendor heatmap: box size = CVE count, shade = share reaching KEV.
 * Layout is computed from the data (squarified treemap) and fills its parent.
 */
export function VendorHeatmap({ cells }) {
  const ref = useRef(null)
  const { width, height } = useSize(ref)
  const [hovered, setHovered] = useState(null)

  const leaves = useMemo(() => {
    if (!width || !height) return []
    const root = hierarchy({ children: cells })
      .sum((d) => d.cves ?? 0)
      .sort((a, b) => b.value - a.value)
    treemap().tile(treemapSquarify).size([width, height]).paddingInner(GAP).round(true)(root)
    return root.leaves()
  }, [cells, width, height])

  const active = leaves.find((l) => l.data.name === hovered)

  return (
    <MotionConfig reducedMotion="user">
      <div ref={ref} className="relative h-full w-full" onMouseLeave={() => setHovered(null)}>
        {leaves.map((leaf, i) => {
          const c = leaf.data
          const w = leaf.x1 - leaf.x0
          const h = leaf.y1 - leaf.y0
          const label = fitLabel(c, w)
          const showValue = label && h >= 44
          const dimmed = hovered && hovered !== c.name
          return (
            <motion.div
              key={c.name}
              role="img"
              aria-label={`${c.name}: ${c.cves.toLocaleString()} CVEs, ${c.kev} reach KEV`}
              className={`absolute flex cursor-default flex-col gap-0.5 overflow-hidden rounded-[14px] px-2.5 py-2 ${SHADE[c.shade]}`}
              style={{ zIndex: hovered === c.name ? 2 : 1 }}
              initial={{ opacity: 0, scale: 0.92, x: leaf.x0, y: leaf.y0, width: w, height: h }}
              animate={{ opacity: dimmed ? 0.7 : 1, scale: 1, x: leaf.x0, y: leaf.y0, width: w, height: h }}
              whileHover={{ scale: 1.03 }}
              transition={{
                default: { type: 'spring', stiffness: 260, damping: 28 },
                opacity: { duration: 0.2, delay: i * 0.03 },
                scale: { type: 'spring', stiffness: 300, damping: 22, delay: hovered ? 0 : i * 0.03 },
              }}
              onMouseEnter={() => setHovered(c.name)}
            >
              {label && (
                <span className={`${label.small ? 'type-label' : 'type-body-compact'} whitespace-nowrap font-semibold`}>
                  {label.text}
                </span>
              )}
              {showValue && <span className="type-label">{c.kev}</span>}
            </motion.div>
          )
        })}

        <AnimatePresence>
          {active && (
            <motion.div
              key="tip"
              className="pointer-events-none absolute z-10 flex flex-col gap-0.5 rounded-xl bg-card px-3 py-2 whitespace-nowrap shadow-float"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 4 }}
              transition={{ duration: 0.15 }}
              style={tipPosition(active, width)}
            >
              <span className="type-body-compact font-semibold text-ink">{active.data.name}</span>
              <span className="type-label text-ink-muted">
                {active.data.cves.toLocaleString()} CVEs · {active.data.kev} reach KEV
              </span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </MotionConfig>
  )
}

// Places the tooltip above the hovered cell, or inside its top edge when the cell touches the top.
function tipPosition(leaf, width) {
  const cx = (leaf.x0 + leaf.x1) / 2
  const above = leaf.y0 > 56
  return {
    left: Math.min(Math.max(cx, 80), width - 80),
    top: above ? leaf.y0 - 8 : leaf.y0 + 8,
    translate: above ? '-50% -100%' : '-50% 0',
  }
}
