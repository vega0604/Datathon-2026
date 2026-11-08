// Icons exported from Figma live in public/icons/ and are served from /icons/<name>.<ext>.
// Insights-view icons are in public/icons/insights/, so pass e.g. name="insights/kpi-eye".
export function iconUrl(name, ext = 'svg') {
  return `${import.meta.env.BASE_URL}icons/${name}.${ext}`
}

/** Renders a Figma-exported SVG at its design size. */
export function Icon({ name, className = 'size-4', alt = '' }) {
  const position = /(^|\s)absolute(\s|$)/.test(className) ? '' : 'relative'
  return (
    <span className={`${position} block shrink-0 ${className}`} aria-hidden={alt ? undefined : true}>
      <img alt={alt} src={iconUrl(name)} className="absolute inset-0 block size-full max-w-none" />
    </span>
  )
}
