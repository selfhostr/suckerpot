import { useEffect, useState, useSyncExternalStore, type RefObject } from "react"

function subscribeVisibility(cb: () => void) {
  document.addEventListener("visibilitychange", cb)
  return () => document.removeEventListener("visibilitychange", cb)
}

/** False while the tab is in the background. */
export function useDocumentVisible(): boolean {
  return useSyncExternalStore(
    subscribeVisibility,
    () => document.visibilityState !== "hidden",
    () => true,
  )
}

/**
 * True while the element is in the viewport and the tab is visible: the map runs its pulses and
 * dashes only then, so a map scrolled away or a background tab costs nothing. Without
 * IntersectionObserver (tests, old browsers) the element counts as on screen.
 */
export function useOnScreen(ref: RefObject<Element | null>): boolean {
  const visible = useDocumentVisible()
  const [inView, setInView] = useState(true)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof IntersectionObserver === "undefined") return
    const io = new IntersectionObserver((entries) => {
      const last = entries[entries.length - 1]
      if (last) setInView(last.isIntersecting)
    })
    io.observe(el)
    return () => io.disconnect()
  }, [ref])
  return visible && inView
}
