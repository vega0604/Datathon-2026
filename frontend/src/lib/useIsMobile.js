import { useSyncExternalStore } from 'react'

// Same breakpoint as the `mobile:` variant in index.css (phones and portrait tablets).
export const MOBILE_QUERY = '(max-width: 1023px)'

const media = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(MOBILE_QUERY) : null

/** True while the window is in the mobile layout. Non-React code can read `isMobile()`. */
export const isMobile = () => Boolean(media?.matches)

const subscribe = (onChange) => {
  media?.addEventListener('change', onChange)
  return () => media?.removeEventListener('change', onChange)
}

export function useIsMobile() {
  return useSyncExternalStore(subscribe, isMobile, () => false)
}
