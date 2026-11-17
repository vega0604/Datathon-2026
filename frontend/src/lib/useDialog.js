import { useEffect, useRef } from 'react'

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Accessible behaviour for a modal (menu drawer, details sheet, chart popup):
 *  - moves focus into it when it opens, and back to where it was when it closes,
 *  - keeps Tab / Shift+Tab inside it,
 *  - closes on Esc,
 *  - stops the page behind it from scrolling.
 * `ref` points at the dialog element; pass `active` false to switch it off.
 */
export function useDialog(ref, onClose, active = true) {
  const closeRef = useRef(onClose)
  useEffect(() => {
    closeRef.current = onClose
  })

  useEffect(() => {
    if (!active) return
    const el = ref.current
    if (!el) return
    const previous = document.activeElement
    const items = () => [...el.querySelectorAll(FOCUSABLE)].filter((n) => n.offsetParent !== null || n === document.activeElement)
    const auto = el.querySelector('[autofocus]') ?? items()[0] ?? el
    if (auto === el && !el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1')
    auto.focus({ preventScroll: true })

    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        closeRef.current?.()
        return
      }
      if (e.key !== 'Tab') return
      const list = items()
      if (!list.length) return e.preventDefault()
      const first = list[0]
      const last = list.at(-1)
      if (e.shiftKey && (document.activeElement === first || !el.contains(document.activeElement))) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey, true)

    const { overflow } = document.body.style
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey, true)
      document.body.style.overflow = overflow
      if (previous && typeof previous.focus === 'function' && document.contains(previous)) previous.focus({ preventScroll: true })
    }
  }, [ref, active])
}
