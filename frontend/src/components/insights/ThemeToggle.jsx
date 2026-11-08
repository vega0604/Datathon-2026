import { Icon } from '../../lib/Icon'

// Light/dark switch from the V5 design. Visual only for now: light is always
// selected and the dark option does nothing until dark mode is implemented.
export function ThemeToggle() {
  return (
    <div role="group" aria-label="Theme" className="flex shrink-0 gap-0.5 rounded-[22px] bg-subtle p-1">
      <button
        type="button"
        aria-pressed="true"
        aria-label="Light mode"
        className="flex size-9 cursor-default items-center justify-center rounded-[18px] border border-line bg-card shadow-[0px_1px_2px_0px_rgba(0,0,0,0.08)]"
      >
        <Icon name="insights/icon-sun" className="size-[18px]" />
      </button>
      <button
        type="button"
        aria-pressed="false"
        aria-label="Dark mode (coming soon)"
        title="Dark mode (coming soon)"
        className="flex size-9 cursor-pointer items-center justify-center rounded-[18px]"
      >
        <Icon name="insights/icon-moon" className="size-[18px]" />
      </button>
    </div>
  )
}
