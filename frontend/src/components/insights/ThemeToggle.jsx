import { Icon } from '../../lib/Icon'

const ON = 'border border-line bg-card shadow-[0px_1px_2px_0px_rgba(0,0,0,0.08)] cursor-default'
const OFF = 'cursor-pointer hover:bg-card/60'

// Light/dark switch from the V5 design. Pages that have a dark design pass
// onThemeChange; without it (Insights, no dark design yet) dark stays disabled.
export function ThemeToggle({ iconDir = 'insights', theme = 'light', onThemeChange }) {
  const dark = theme === 'dark'
  return (
    <div role="group" aria-label="Theme" className="flex shrink-0 gap-0.5 rounded-[22px] bg-subtle p-1">
      <button
        type="button"
        aria-pressed={!dark}
        aria-label="Light mode"
        onClick={() => onThemeChange?.('light')}
        className={`flex size-9 items-center justify-center rounded-[18px] ${dark ? OFF : ON}`}
      >
        <Icon name={`${iconDir}/icon-sun`} className="size-[18px]" />
      </button>
      <button
        type="button"
        aria-pressed={dark}
        aria-label={onThemeChange ? 'Dark mode' : 'Dark mode (coming soon)'}
        title={onThemeChange ? 'Dark mode' : 'Dark mode (coming soon)'}
        onClick={() => onThemeChange?.('dark')}
        className={`flex size-9 items-center justify-center rounded-[18px] ${dark ? ON : OFF}`}
      >
        <Icon name={`${iconDir}/icon-moon`} className="size-[18px]" />
      </button>
    </div>
  )
}
