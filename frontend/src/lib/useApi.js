// A small request cache for the FastAPI backend, shared by every view.
//
// Entries live at module level, so switching between Fix first, Your software and
// Insights never refetches. Each key fetches at most once at a time (concurrent users
// share the request), cached data is returned at once and revalidated in the
// background when it is older than its TTL (stale-while-revalidate), and writes update
// the cache in place (`mutate`) instead of refetching large responses.
import { useCallback, useEffect, useSyncExternalStore } from 'react'

const entries = new Map() // key -> { data, error, promise, at, ttl, fetcher }
const listeners = new Map() // key -> Set<() => void>

function entry(key) {
  if (!entries.has(key)) entries.set(key, { data: undefined, error: null, promise: null, at: 0, ttl: 0, fetcher: null })
  return entries.get(key)
}

function notify(key) {
  for (const fn of listeners.get(key) ?? []) fn()
}

function subscribe(key, fn) {
  if (!listeners.has(key)) listeners.set(key, new Set())
  listeners.get(key).add(fn)
  return () => listeners.get(key)?.delete(fn)
}

/** Starts (or joins) the request for `key`. Resolves with the data; never rejects. */
export function load(key, fetcher, { force = false } = {}) {
  const e = entry(key)
  if (fetcher) e.fetcher = fetcher
  if (e.promise) return e.promise
  const fresh = e.data !== undefined && Date.now() - e.at < e.ttl
  if (fresh && !force) return Promise.resolve(e.data)
  if (!e.fetcher) return Promise.resolve(e.data)
  e.promise = e
    .fetcher()
    .then((data) => {
      Object.assign(e, { data, error: null, at: Date.now() })
      return data
    })
    .catch((error) => {
      e.error = error
      return e.data
    })
    .finally(() => {
      e.promise = null
      notify(key)
    })
  notify(key)
  return e.promise
}

/** Warms the cache before a view needs it (no re-render if nothing listens yet). */
export function prefetch(key, fetcher, ttl = 60_000) {
  const e = entry(key)
  e.ttl = Math.max(e.ttl, ttl)
  return load(key, fetcher)
}

/** Replaces (or updates with a function) the cached data for `key`. */
export function mutate(key, next) {
  const e = entry(key)
  e.data = typeof next === 'function' ? next(e.data) : next
  e.at = Date.now()
  e.error = null
  notify(key)
}

/** Applies `fn` to the cached data of every key that starts with `prefix` (for a
 *  write that touches several cached views of the same rows, e.g. searched queues). */
export function mutateMatching(prefix, fn) {
  for (const [key, e] of entries) if (key.startsWith(prefix) && e.data !== undefined) mutate(key, fn)
}

/** Forgets every key that starts with `prefix` (after a delete): no refetch. */
export function drop(prefix) {
  for (const key of [...entries.keys()]) {
    if (!key.startsWith(prefix)) continue
    entries.delete(key)
    notify(key)
  }
}

/** Drops cached data for every key that starts with `prefix`; listeners refetch. */
export function invalidate(prefix) {
  for (const [key, e] of entries) {
    if (!key.startsWith(prefix)) continue
    e.at = 0
    if (listeners.get(key)?.size) load(key)
    else entries.delete(key)
  }
}

const snapshots = new Map() // key -> last snapshot object, so useSyncExternalStore sees stable values

function snapshot(key) {
  const e = entry(key)
  const prev = snapshots.get(key)
  // Nothing yet and no error counts as loading, so the first render (before the
  // effect starts the request) shows the loading state, not an empty page.
  const loading = !!e.promise || (e.data === undefined && !e.error)
  if (prev && prev.data === e.data && prev.error === e.error && prev.loading === loading) return prev
  const next = { data: e.data, error: e.error, loading }
  snapshots.set(key, next)
  return next
}

/**
 * Reads `key` through the cache: `{ data, error, loading, reload }`.
 * `key` null skips the request (for example while no SBOM is selected).
 * ttl (ms): how long data counts as fresh; Infinity for data that only changes per model run.
 */
export function useApi(key, fetcher, { ttl = 60_000 } = {}) {
  const read = () => (key ? snapshot(key) : EMPTY)
  const state = useSyncExternalStore(
    useCallback((fn) => (key ? subscribe(key, fn) : () => {}), [key]),
    read,
    read,
  )
  useEffect(() => {
    if (!key) return
    const e = entry(key)
    e.ttl = ttl
    load(key, fetcher)
    // fetcher identity changes every render; the key is what defines the request.
  }, [key, ttl]) // eslint-disable-line react-hooks/exhaustive-deps
  const reload = useCallback(() => key && load(key, fetcher, { force: true }), [key]) // eslint-disable-line react-hooks/exhaustive-deps
  return { ...state, reload }
}

const EMPTY = { data: undefined, error: null, loading: false }
