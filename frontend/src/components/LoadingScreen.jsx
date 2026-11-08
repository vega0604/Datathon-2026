import logoLight from '../assets/logolight.png'
import logoDark from '../assets/logodark.png'

// Branded loading screen. The wordmark is "scanned in" by a light sweeping
// across it, while contour rings ripple out behind it like the fingerprint
// lines inside the letters. Styles and keyframes live in index.css (`.loader-*`).
//
// Use it full-screen while the app starts (see App.jsx), or later while an API
// call is in flight: <LoadingScreen theme={theme} />.

// Ring colours: the three hues in the logo's contour lines.
const RINGS = [
  { r: 120, color: 'var(--color-chart-1)', delay: '0s' },
  { r: 120, color: 'var(--color-chart-2)', delay: '0.9s' },
  { r: 120, color: 'var(--color-ai)', delay: '1.8s' },
]

export function LoadingScreen({ theme = 'light', leaving = false }) {
  const dark = theme === 'dark'
  const logo = dark ? logoDark : logoLight

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Hunch is loading"
      className={`theme-v5 ${dark ? 'theme-dark' : ''} loader-root fixed inset-0 z-50 flex flex-col items-center justify-center bg-page font-sans ${leaving ? 'loader-leave' : ''}`}
    >
      <div className="relative flex h-[260px] w-[min(520px,86vw)] items-center justify-center">
        {/* Ripples behind the wordmark */}
        <svg viewBox="-260 -130 520 260" className="absolute inset-0 size-full overflow-visible" aria-hidden="true">
          {RINGS.map((ring) => (
            <ellipse
              key={ring.delay}
              className="loader-ring"
              rx={ring.r * 1.9}
              ry={ring.r}
              fill="none"
              stroke={ring.color}
              strokeWidth="1.5"
              style={{ animationDelay: ring.delay }}
            />
          ))}
        </svg>

        {/* Wordmark: a faint copy underneath, the full-colour copy revealed by the scan */}
        <div className="relative w-[min(340px,62vw)]">
          <img src={logo} alt="" width="464" height="124" className="block h-auto w-full opacity-15 grayscale" />
          <img src={logo} alt="" width="464" height="124" className="loader-reveal absolute inset-0 block h-auto w-full" />
          <span className="loader-scan pointer-events-none absolute -inset-y-3 w-[3px] rounded-full" aria-hidden="true" />
        </div>
      </div>

    </div>
  )
}
