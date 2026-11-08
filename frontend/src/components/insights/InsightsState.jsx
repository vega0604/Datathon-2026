import { useEffect } from 'react'

// While the API builds insights.json (first start after a fresh clone) it answers 503;
// the page checks again on its own until the numbers are there.
const RETRY_MS = 15_000

/** Loading and error states shared by the Insights pages: renders `children(data)`
 *  once the request has data (cached data shows at once on later visits). */
export function InsightsState({ query, children }) {
  const building = query.error?.status === 503
  const { reload } = query
  useEffect(() => {
    if (!building) return
    const t = setInterval(reload, RETRY_MS)
    return () => clearInterval(t)
  }, [building, reload])

  if (query.data) return children(query.data)
  return (
    <main className="flex h-full min-w-0 flex-1 items-center justify-center" role="status">
      <div className="flex max-w-[420px] flex-col items-center gap-3 rounded-[28px] bg-card p-10 text-center shadow-float">
        {query.error ? (
          <>
            <p className="text-lg text-ink">{building ? 'These insights aren’t ready yet' : 'We couldn’t load these insights'}</p>
            <p className="type-body text-ink-muted">{query.error.message}</p>
            {building && <p className="type-label text-ink-muted">Checking again every 15 seconds.</p>}
            <button
              type="button"
              onClick={reload}
              className="mt-1 cursor-pointer rounded-full bg-blue px-5 py-2.5 text-sm font-semibold text-white hover:bg-primary-strong"
            >
              Try again
            </button>
          </>
        ) : (
          <p className="type-body text-ink-muted">Loading insights…</p>
        )}
      </div>
    </main>
  )
}
