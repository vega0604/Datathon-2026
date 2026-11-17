import logoLight from '../../assets/logolight.png'
import logoDark from '../../assets/logodark.png'
import { iconUrl } from '../../lib/Icon'
import { useMe } from '../../lib/api'
import { ThemeToggle } from './ThemeToggle'

// iconDir picks the icon set: 'insights' (V4 colours) or 'fixfirst' (V5 colours).
// On mobile (< 1024px) `onMenu` adds a menu button that opens the sidebar as a drawer.
export function AppHeader({ iconDir = 'insights', theme, onThemeChange, onHome, onMenu, menuOpen = false }) {
  // /api/me (no login yet: the backend returns the user set in its .env).
  const { data: user } = useMe()
  return (
    <header className="flex w-full shrink-0 items-center gap-4 border-b border-line bg-card px-6 py-3.5 mobile:sticky mobile:top-0 mobile:z-30 mobile:gap-2 mobile:px-3 mobile:py-2 sm:mobile:gap-3 sm:mobile:px-5">
      <div className="flex items-center gap-3 mobile:gap-1.5">
        {onMenu && (
          <button
            type="button"
            onClick={onMenu}
            aria-label="Open menu"
            aria-haspopup="dialog"
            aria-expanded={menuOpen}
            aria-controls={menuOpen ? 'mobile-menu' : undefined}
            className="hidden size-11 shrink-0 cursor-pointer items-center justify-center rounded-full text-ink hover:bg-page mobile:flex"
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" aria-hidden="true">
              <path d="M3 5.5h14M3 10h14M3 14.5h14" />
            </svg>
          </button>
        )}
        {/* Wordmark: the dark-outlined version on light backgrounds, the light-outlined one in dark mode. */}
        {/* Clicking the logo goes home (Insights → Summary). */}
        <button
          type="button"
          onClick={onHome}
          aria-label="Hunch, go to home"
          title="Home"
          className="shrink-0 cursor-pointer rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue"
        >
          <img src={theme === 'dark' ? logoDark : logoLight} alt="" width="464" height="124" className="block h-9 w-auto max-sm:h-7" />
        </button>
      </div>

      <div className="h-px min-w-px flex-1" />

      <ThemeToggle iconDir={iconDir} theme={theme} onThemeChange={onThemeChange} />
      {/* No notifications bell: there's no alerting feature behind it yet. */}
      <div className="h-8 w-px shrink-0 bg-line max-sm:hidden" />
      <button type="button" aria-label={user?.name ? `${user.name}, account` : 'Account'} className="flex shrink-0 cursor-pointer items-center gap-2.5 pr-1 text-left">
        {/* avatar_url null keeps the bundled sample photo. */}
        <img src={user?.avatar_url ?? iconUrl(`${iconDir}/avatar-photo`, 'png')} alt="" width="40" height="40" className="size-10 shrink-0 rounded-full object-cover max-sm:size-9" />
        <span className="flex min-w-[96px] flex-col whitespace-nowrap max-sm:hidden" aria-hidden="true">
          <span className="text-sm leading-5 font-semibold text-ink">{user?.name ?? ' '}</span>
          <span className="text-xs leading-[17px] text-ink-muted">{user?.role ?? ' '}</span>
        </span>
        <span className="text-sm leading-5 text-ink-muted max-sm:hidden" aria-hidden="true">⌄</span>
      </button>
    </header>
  )
}
