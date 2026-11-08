import { useState } from 'react'

/**
 * Open/close state for a card's popup. `open(e)` takes the click event so the popup
 * is rendered inside the same themed view (.theme-v5 / .theme-dark) as the card.
 */
export function useExpand() {
  const [target, setTarget] = useState(null)
  return {
    target,
    open: (e) => setTarget(e.currentTarget.closest('.theme-v5') ?? document.body),
    close: () => setTarget(null),
  }
}
