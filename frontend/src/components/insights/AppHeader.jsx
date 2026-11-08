import logoLight from '../../assets/logolight.png'
import logoDark from '../../assets/logodark.png'
import { Icon, iconUrl } from '../../lib/Icon'
import { user } from '../../data/insights'
import { ThemeToggle } from './ThemeToggle'

// iconDir picks the icon set: 'insights' (V4 colours) or 'fixfirst' (V5 colours).
export function AppHeader({ iconDir = 'insights', theme, onThemeChange, onHome }) {
  return (
    <header className="flex w-full shrink-0 items-center gap-4 border-b border-line bg-card px-6 py-3.5">
      <div className="flex items-center gap-3">
        {/* Wordmark: the dark-outlined version on light backgrounds, the light-outlined one in dark mode. */}
        {/* Clicking the logo goes home (Insights → Summary). */}
        <button
          type="button"
          onClick={onHome}
          aria-label="hunch, go to home"
          title="Home"
          className="shrink-0 cursor-pointer rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue"
        >
          <img src={theme === 'dark' ? logoDark : logoLight} alt="" width="473" height="138" className="block h-9 w-auto" />
        </button>
      </div>

      <div className="h-px min-w-px flex-1" />

      <ThemeToggle iconDir={iconDir} theme={theme} onThemeChange={onThemeChange} />
      <button type="button" aria-label="Notifications" className="cursor-pointer rounded-full">
        <Icon name={`${iconDir}/button-notifications`} className="size-11" />
      </button>
      <div className="h-8 w-px shrink-0 bg-line" />
      <button type="button" className="flex cursor-pointer items-center gap-2.5 pr-1 text-left">
        <img src={iconUrl(`${iconDir}/avatar-photo`, 'png')} alt="" width="40" height="40" className="size-10 shrink-0" />
        <span className="flex flex-col whitespace-nowrap">
          <span className="text-sm leading-5 font-semibold text-ink">{user.name}</span>
          <span className="text-xs leading-[17px] text-ink-muted">{user.role}</span>
        </span>
        <span className="text-sm leading-5 text-ink-muted">⌄</span>
      </button>
    </header>
  )
}
