import { useLayoutEffect } from 'react'

/**
 * Guarantees a flex-column container never needs to scroll. After layout it
 * measures its visible children; if they don't fit, it sets `--fit` (< 1) on the
 * container, which children use as CSS `zoom`, shrinking them just enough to fit.
 * Re-checks when the container resizes and once web fonts have loaded.
 */
export function useFitHeight(ref) {
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const fit = () => {
      el.style.setProperty('--fit', '1')
      const cs = getComputedStyle(el)
      const avail = el.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom)
      const kids = [...el.children].filter((k) => k.getBoundingClientRect().height > 0)
      const gaps = (parseFloat(cs.rowGap) || 0) * Math.max(0, kids.length - 1)
      const content = kids.reduce((sum, k) => sum + k.getBoundingClientRect().height, 0)
      const zoom = content > 0 ? Math.min(1, (avail - gaps) / content) : 1
      el.style.setProperty('--fit', String(Math.floor(zoom * 1000) / 1000))
    }
    fit()
    const ro = new ResizeObserver(fit)
    ro.observe(el)
    document.fonts?.ready.then(fit)
    return () => ro.disconnect()
  }, [ref])
}
