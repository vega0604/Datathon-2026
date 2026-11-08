/** Loading and error states shared by the Insights pages: renders `children(data)`
 *  once the request has data (cached data shows at once on later visits). */
export function InsightsState({ query, children }) {
  if (query.data) return children(query.data)
  return (
    <main className="flex h-full min-w-0 flex-1 items-center justify-center" role="status">
      <div className="flex max-w-[420px] flex-col items-center gap-3 rounded-[28px] bg-card p-10 text-center shadow-float">
        {query.error ? (
          <>
            <p className="text-lg text-ink">We couldn’t load these insights</p>
            <p className="type-body text-ink-muted">{query.error.message}</p>
            <button
              type="button"
              onClick={query.reload}
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
