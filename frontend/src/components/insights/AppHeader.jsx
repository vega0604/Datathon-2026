import { Icon, iconUrl } from '../../lib/Icon'
import { user } from '../../data/insights'
import { ThemeToggle } from './ThemeToggle'

// iconDir picks the icon set: 'insights' (V4 colours) or 'fixfirst' (V5 colours).
export function AppHeader({ iconDir = 'insights', theme, onThemeChange }) {
  return (
    <header className="flex w-full shrink-0 items-center gap-4 border-b border-line bg-card px-6 py-3.5">
      <div className="flex items-center gap-3">
        {/* Logo placeholder until the real logo is ready */}
        <div className="flex h-10 items-center justify-center rounded-xl border-[1.5px] border-dashed border-blue-ink bg-blue-soft px-1.5">
          <span className="text-[9px] leading-[14px] font-semibold text-blue-ink">Logo</span>
        </div>
        <div className="flex flex-col whitespace-nowrap">
          <p className="text-base leading-[22px] font-semibold text-ink">Before the Breach</p>
          <p className="text-xs leading-[17px] text-ink-muted">Vulnerability triage</p>
        </div>
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
