import { useQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query"
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react"
import { useSyncExternalStore } from "react"
import { api, queryKeys, type Page, type Session, type SessionFilters } from "@/lib/api"
import { motionOff } from "@/lib/motion"

/** How many of the newest sessions are checked for arrivals. */
export const PEEK = 20
/** How often, while the tab is visible. */
const PEEK_MS = 30_000
/** How long the rows already shown glide down after new ones arrive (index.css [data-arriving]). */
const ARRIVING_MS = 400
/** The list's top counts as in view until the reader has scrolled this far past it. */
const TOP_SLACK = 160

/**
 * The sessions of `peek` (newest first) that the list does not show yet and that are not older
 * than its newest row. Empty when the list is empty (it has nothing to compare with).
 */
export function freshRows(peek: readonly Session[], shown: readonly Session[]): Session[] {
  const top = shown[0]
  if (!top) return []
  const have = new Set(shown.map((s) => s.session_id))
  return peek.filter((s) => !have.has(s.session_id) && s.started_at >= top.started_at)
}

function useScrolledPast(offset: number): boolean {
  const subscribe = useCallback((cb: () => void) => {
    window.addEventListener("scroll", cb, { passive: true })
    return () => window.removeEventListener("scroll", cb)
  }, [])
  return useSyncExternalStore(
    subscribe,
    () => window.scrollY > offset,
    () => false,
  )
}

type Sessions = InfiniteData<Page<Session>, string | null>

/**
 * New sessions for the Attacks list, without jumping it. Every 30 s the newest sessions with the
 * same filters are fetched (one small page). While the top of the list is in view they slide in
 * at once and the rows below glide down; once the reader has scrolled down they are held, and
 * `pending` feeds an "N new sessions" pill whose `show()` brings them in and scrolls back up.
 * A window that ends in the past (`until`) never gets new rows.
 */
export function useNewSessions({
  filters,
  rows,
  ready,
  listTop,
}: {
  filters: SessionFilters
  rows: readonly Session[]
  /** The list loaded (its first page is in). */
  ready: boolean
  /** Top of the list in document coordinates. */
  listTop: number
}) {
  const client = useQueryClient()
  const key = queryKeys.sessions(filters)
  const peekKey = [...key, "peek"]
  const threshold = Math.max(0, listTop - TOP_SLACK)
  const scrolled = useScrolledPast(threshold)
  const [arriving, setArriving] = useState<ReadonlySet<string>>(() => new Set())
  const timer = useRef(0)
  useEffect(() => () => window.clearTimeout(timer.current), [])

  /** Brings the held sessions of `peek` into the list. */
  const take = (peek: readonly Session[]) => {
    const shown = client.getQueryData<Sessions>(key)?.pages.flatMap((p) => p.items) ?? []
    const fresh = freshRows(peek, shown)
    if (fresh.length === 0) return
    setArriving(new Set(fresh.map((s) => s.session_id)))
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setArriving(new Set()), ARRIVING_MS)
    if (fresh.length >= PEEK) {
      // More arrived than one peek holds: the gap cannot be filled, so the list starts over.
      void client.refetchQueries({ queryKey: key, exact: true })
      return
    }
    client.setQueryData<Sessions>(key, (data) => {
      const [first, ...rest] = data?.pages ?? []
      if (!data || !first) return data
      return { ...data, pages: [{ ...first, items: [...fresh, ...first.items] }, ...rest] }
    })
  }
  // The latest `take` and threshold, for the callbacks below (query function, scroll listener).
  const latest = useRef({ take, threshold })
  useLayoutEffect(() => {
    latest.current = { take, threshold }
  })

  // The list itself was just loaded: the first check waits one interval, then repeats.
  const filterKey = JSON.stringify(filters)
  const [armedFor, setArmedFor] = useState<string | null>(null)
  useEffect(() => {
    if (!ready || filters.until) return
    const t = window.setTimeout(() => setArmedFor(filterKey), PEEK_MS)
    return () => window.clearTimeout(t)
  }, [ready, filterKey, filters.until])

  const peek = useQuery({
    queryKey: peekKey,
    queryFn: async () => {
      const page = await api.sessions(filters, null, PEEK)
      // Top of the list in view: new rows come in by themselves.
      if (window.scrollY <= latest.current.threshold) latest.current.take(page.items)
      return page
    },
    enabled: ready && !filters.until && armedFor === filterKey,
    refetchInterval: PEEK_MS,
  })

  // Back at the top by scrolling: whatever was held comes in.
  useEffect(() => {
    let above = window.scrollY <= latest.current.threshold
    const onScroll = () => {
      const now = window.scrollY <= latest.current.threshold
      if (now && !above) {
        const held = client.getQueryData<Page<Session>>(peekKey)?.items
        if (held) latest.current.take(held)
      }
      above = now
    }
    window.addEventListener("scroll", onScroll, { passive: true })
    return () => window.removeEventListener("scroll", onScroll)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the key is rebuilt on every render
  }, [client, filterKey])

  const fresh = useMemo(() => freshRows(peek.data?.items ?? [], rows), [peek.data, rows])

  const show = () => {
    take(peek.data?.items ?? [])
    window.scrollTo({ top: 0, behavior: motionOff() ? "auto" : "smooth" })
  }

  return {
    /** Held while the reader is further down. */
    pending: scrolled ? fresh.length : 0,
    /** At the cap, the pill says "20+". */
    more: fresh.length >= PEEK,
    show,
    /** Ids that just came in (they slide in). */
    arriving,
    /** True for a moment after rows came in: the list lets its rows glide. */
    gliding: arriving.size > 0,
  }
}
