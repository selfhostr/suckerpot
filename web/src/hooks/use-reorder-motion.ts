import { useLayoutEffect, useRef, type RefObject } from "react"
import { calmMotion } from "@/lib/motion"

const MOVE_MS = 320
const ENTER_MS = 220
const MOVE_EASE = "cubic-bezier(0.4, 0, 0.2, 1)"
const ENTER_EASE = "cubic-bezier(0.22, 1, 0.36, 1)"

/**
 * Rows that change places glide to their new place (FLIP) instead of jumping, and a row that
 * joins fades in. For short ranked lists (a top 10) that reorder after a filter change: the
 * children of `ref` carry `data-flip="<key>"`; their offsets are read once after each reorder
 * and the move is played with the Web Animations API (transform and opacity only).
 * Nothing moves on the first render, under reduced or frozen motion, or on phones.
 */
export function useReorderMotion(ref: RefObject<HTMLElement | null>, keys: readonly string[]) {
  const last = useRef<Map<string, number> | null>(null)
  const signature = keys.join("\u0000")

  useLayoutEffect(() => {
    const root = ref.current
    if (!root) return
    const rows = Array.from(root.querySelectorAll<HTMLElement>(":scope > [data-flip]"))
    const now = new Map(rows.map((el) => [el.dataset.flip ?? "", el.offsetTop]))
    const before = last.current
    last.current = now
    if (!before || calmMotion() || typeof rows[0]?.animate !== "function") return
    for (const el of rows) {
      const was = before.get(el.dataset.flip ?? "")
      const top = now.get(el.dataset.flip ?? "") ?? 0
      if (was === undefined) {
        el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: ENTER_MS, easing: ENTER_EASE })
      } else if (Math.abs(was - top) >= 1) {
        el.animate([{ transform: `translateY(${was - top}px)` }, { transform: "none" }], {
          duration: MOVE_MS,
          easing: MOVE_EASE,
        })
      }
    }
  }, [ref, signature])
}
