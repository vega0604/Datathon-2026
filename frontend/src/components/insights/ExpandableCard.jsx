import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { Icon } from '../../lib/Icon'

// Card header shared by the chart cards: icon + short title, the finding underneath,
// and an optional expand button on the right.
export function CardHead({ icon, title, subtitle, onExpand, onClose }) {
  return (
    <div className="flex shrink-0 items-start justify-between gap-3">
      <div className="flex min-w-0 flex-col gap-1">
        <div className="flex items-center gap-2.5">
          <Icon name={icon} className="size-5" />
          <h2 className="text-lg leading-7 whitespace-nowrap text-ink">{title}</h2>
        </div>
        {subtitle && <p className="type-label text-ink-muted">{subtitle}</p>}
      </div>
      {onExpand && (
        <RoundButton label={`Expand ${title}`} onClick={onExpand}>
          {/* Arrows out to the corners */}
          <path d="M11 3h6v6M9 17H3v-6M17 3l-6 6M3 17l6-6" />
        </RoundButton>
      )}
      {onClose && (
        <RoundButton label="Close" onClick={onClose} autoFocus>
          <path d="M5 5l10 10M15 5L5 15" />
        </RoundButton>
      )}
    </div>
  )
}

function RoundButton({ label, onClick, autoFocus, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      autoFocus={autoFocus}
      className="flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-full bg-card text-ink-muted hover:text-ink focus-visible:outline-2 focus-visible:outline-blue"
    >
      <svg width="16" height="16" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {children}
      </svg>
    </button>
  )
}

/**
 * Large popup for a chart. Closes on the ✕ button, Esc, or a click outside.
 * It's a plain overlay rather than <dialog> so the chart mounts visible and
 * measures its real size on first draw.
 */
export function ChartPopup({ expand, icon, title, subtitle, size = 'w-[min(1200px,94vw)]', children }) {
  const { target, close } = expand
  useEffect(() => {
    if (!target) return
    const onKey = (e) => e.key === 'Escape' && close()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [target, close])

  if (!target) return null
  return createPortal(
    <div
      className="chart-fade fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-6 font-sans"
      onMouseDown={(e) => e.target === e.currentTarget && close()}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`flex h-[min(780px,90vh)] ${size} flex-col gap-4 rounded-[28px] bg-page p-6 shadow-panel`}
      >
        <CardHead icon={icon} title={title} subtitle={subtitle} onClose={close} />
        {children}
      </div>
    </div>,
    target,
  )
}
