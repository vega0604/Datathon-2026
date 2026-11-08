import { useLayoutEffect } from 'react'

/**
 * Guarantees a container never needs to scroll or clip. After layout it measures
 * how much taller its content is than the space it has; if it doesn't fit, it
 * sets `--fit` (< 1) on the container, which children use as CSS `zoom`
 * (`[&>*]:[zoom:var(--fit,1)]`), shrinking them just enough to fit.
 *
 * It looks at three things, so it works for column and row layouts alike:
 *  - the children stacked in a column (sum of heights + gaps),
 *  - the container's own overflow (scrollHeight),
 *  - lists inside it that would otherwise scroll (overflow-y: auto).
 *    Mark a list with `data-fit-scroll` to let it scroll instead of shrinking the page.
 * Re-checks when the container resizes and once web fonts have loaded.
 */
export function useFitHeight(ref) {
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => {
      const cs = getComputedStyle(el)
      const pad = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom)
      const avail = el.clientHeight - pad
      let need = el.scrollHeight - pad
      if (cs.flexDirection === 'column') {
        const kids = [...el.children].filter((k) => k.getBoundingClientRect().height > 0)
        const gaps = (parseFloat(cs.rowGap) || 0) * Math.max(0, kids.length - 1)
        need = Math.max(need, kids.reduce((sum, k) => sum + k.getBoundingClientRect().height, 0) + gaps)
      }
      let inner = 0
      for (const d of el.querySelectorAll('*')) {
        if (d.hasAttribute('data-fit-scroll')) continue // this list is allowed to scroll
        const oy = getComputedStyle(d).overflowY
        if ((oy === 'auto' || oy === 'scroll') && d.scrollHeight > d.clientHeight + 1) inner = Math.max(inner, d.scrollHeight - d.clientHeight)
      }
      return { avail, need: Math.max(need, avail + inner) }
    }
    const fit = () => {
      el.style.setProperty('--fit', '1')
      let zoom = 1
      // Zoom doesn't scale every part exactly (gaps, borders), so refine a few times.
      for (let i = 0; i < 4; i++) {
        const { avail, need } = measure()
        if (need <= avail + 1) break
        zoom = Math.max(0.5, zoom * (avail / need))
        el.style.setProperty('--fit', String(Math.floor(zoom * 1000) / 1000))
      }
    }
    fit()
    const ro = new ResizeObserver(fit)
    ro.observe(el)
    document.fonts?.ready.then(fit)
    return () => ro.disconnect()
  }, [ref])
}
