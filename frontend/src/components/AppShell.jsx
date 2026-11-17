import { useLayoutEffect, useRef, useState } from 'react'
import { AppHeader } from './insights/AppHeader'
import { Sidebar } from './Sidebar'
import { IconDarkContext } from '../lib/iconTheme'
import { useDialog } from '../lib/useDialog'
import { useIsMobile } from '../lib/useIsMobile'
import { Icon } from '../lib/Icon'

/**
 * The frame every page shares: theme classes, header, sidebar and the content area.
 * Desktop (>= 1024px): fixed-height window with the sidebar on the left, as in Figma.
 * Mobile (< 1024px): the page scrolls, content is one column and the sidebar opens
 * as a slide-out menu from the header's menu button.
 */
export function AppShell({ theme = 'light', onThemeChange, onHome, sidebar, children }) {
  const dark = theme === 'dark'
  const mobile = useIsMobile()
  const [menuOpen, setMenuOpen] = useState(false)
  const close = () => setMenuOpen(false)
  const rootRef = useRef(null)
  usePageBackground(rootRef, dark)

  // In the menu, picking a destination also closes the menu.
  const andClose = (fn) => fn && ((...args) => (close(), fn(...args)))
  const menuSidebar = {
    ...sidebar,
    onSectionChange: andClose(sidebar.onSectionChange),
    onOpenFixFirst: andClose(sidebar.onOpenFixFirst),
    onOpenInsights: andClose(sidebar.onOpenInsights),
    onUpload: andClose(sidebar.onUpload),
    software: sidebar.software && { ...sidebar.software, onSelect: andClose(sidebar.software.onSelect) },
  }

  return (
    <IconDarkContext.Provider value={dark}>
      <div ref={rootRef} className={`theme-v5 ${dark ? 'theme-dark' : ''} flex h-screen min-h-[560px] flex-col bg-page font-sans mobile:h-auto mobile:min-h-dvh`}>
        <a
          href="#content"
          className="sr-only rounded-full bg-blue px-4 py-2 text-sm font-semibold text-white focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[70]"
        >
          Skip to content
        </a>
        <AppHeader iconDir="fixfirst" theme={theme} onThemeChange={onThemeChange} onHome={onHome} onMenu={() => setMenuOpen(true)} menuOpen={menuOpen && mobile} />

        <div
          id="content"
          tabIndex={-1}
          className="flex min-h-0 w-full flex-1 items-start gap-4 overflow-hidden p-4 outline-none wide:gap-5 wide:p-5 compact:py-3 mobile:flex-col mobile:items-stretch mobile:gap-4 mobile:overflow-visible mobile:px-3 mobile:pt-4 mobile:pb-8 sm:mobile:px-5"
        >
          {!mobile && <Sidebar {...sidebar} />}
          {children}
        </div>

        {mobile && menuOpen && (
          <MenuDrawer onClose={close}>
            <Sidebar {...menuSidebar} variant="drawer" />
          </MenuDrawer>
        )}
      </div>
    </IconDarkContext.Provider>
  )
}

/**
 * Gives <html> and <body> the current skin's page colour. The theme classes live on
 * the app's root div, so without this the document behind it stays light: on phones
 * that shows as a white strip below the content when the browser toolbar collapses,
 * in the overscroll bounce, and in Safari's translucent toolbar (which tints itself
 * from the page background). Also sets theme-color and color-scheme to match.
 */
function usePageBackground(rootRef, dark) {
  useLayoutEffect(() => {
    const root = rootRef.current
    if (!root) return
    const page = getComputedStyle(root).getPropertyValue('--color-page').trim()
    if (!page) return
    for (const el of [document.documentElement, document.body]) el.style.backgroundColor = page
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
    let meta = document.querySelector('meta[name="theme-color"]')
    if (!meta) {
      meta = document.createElement('meta')
      meta.name = 'theme-color'
      document.head.appendChild(meta)
    }
    meta.content = page
  }, [rootRef, dark])
}

function MenuDrawer({ onClose, children }) {
  const ref = useRef(null)
  useDialog(ref, onClose)
  return (
    <div className="backdrop-in fixed inset-0 z-50 bg-black/40 dark:bg-black/60" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={ref}
        id="mobile-menu"
        role="dialog"
        aria-modal="true"
        aria-label="Menu"
        className="drawer-in flex h-full w-[min(300px,86vw)] flex-col bg-card shadow-panel"
      >
        <div className="flex shrink-0 items-center justify-between border-b border-line px-4 py-3">
          <p className="text-base font-semibold text-ink">Menu</p>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close menu"
            className="flex size-11 cursor-pointer items-center justify-center rounded-full border border-line hover:bg-page"
          >
            <Icon name="fixfirst/icon-close" className="size-4" />
          </button>
        </div>
        <div className="min-h-0 flex-1">{children}</div>
      </div>
    </div>
  )
}

/**
 * Full-screen sheet for detail panels on mobile (e.g. a Fix first row's details).
 * `label` names the dialog for screen readers.
 */
export function MobileSheet({ label, onClose, children }) {
  const ref = useRef(null)
  useDialog(ref, onClose)
  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-label={label}
      className="sheet-in fixed inset-0 z-50 overflow-y-auto overscroll-contain bg-card font-sans"
    >
      {children}
    </div>
  )
}
