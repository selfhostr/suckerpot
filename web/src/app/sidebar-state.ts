import { useCallback, useState } from "react"
import type { SectionId } from "./nav"

/** "collapsed" once the reader folded the desktop sidebar to its icon rail; expanded otherwise. */
export const SIDEBAR_KEY = "suckerpot.sidebar"
/** The sections the reader closed, as a JSON list of ids. Every section is open by default. */
export const SECTIONS_KEY = "suckerpot.nav.closed"

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key)
    else localStorage.setItem(key, value)
  } catch {
    // Storage blocked: the choice lasts until the page is reloaded.
  }
}

/** Whether the desktop sidebar is folded to its icon rail, remembered per browser. */
export function useSidebarCollapsed(): [boolean, (next: boolean) => void] {
  const [collapsed, setCollapsed] = useState(() => read(SIDEBAR_KEY) === "collapsed")
  const set = useCallback((next: boolean) => {
    setCollapsed(next)
    write(SIDEBAR_KEY, next ? "collapsed" : null)
  }, [])
  return [collapsed, set]
}

export function readClosedSections(): SectionId[] {
  const raw = read(SECTIONS_KEY)
  if (!raw) return []
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter(
      (v): v is SectionId => v === "observe" || v === "understand" || v === "defend",
    )
  } catch {
    return []
  }
}

/** Which sections of the expanded sidebar are open, remembered per browser. */
export function useOpenSections(): {
  isOpen: (id: SectionId) => boolean
  toggle: (id: SectionId) => void
} {
  const [closed, setClosed] = useState<SectionId[]>(readClosedSections)
  const toggle = useCallback((id: SectionId) => {
    setClosed((prev) => {
      const next = prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
      write(SECTIONS_KEY, next.length ? JSON.stringify(next) : null)
      return next
    })
  }, [])
  const isOpen = useCallback((id: SectionId) => !closed.includes(id), [closed])
  return { isOpen, toggle }
}
