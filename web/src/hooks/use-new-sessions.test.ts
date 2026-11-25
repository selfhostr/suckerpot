import { describe, expect, it } from "vitest"
import type { Session } from "@/lib/api"
import { freshRows } from "./use-new-sessions"

const s = (session_id: string, started_at: string) => ({ session_id, started_at }) as Session

describe("freshRows", () => {
  const top = s("b", "2026-11-25T10:00:00Z")
  const shown = [top, s("a", "2026-11-25T09:00:00Z")]

  it("keeps the sessions the list does not show, newer than its top row", () => {
    const peek = [s("d", "2026-11-25T10:02:00Z"), s("c", "2026-11-25T10:01:00Z"), ...shown]
    expect(freshRows(peek, shown).map((x) => x.session_id)).toEqual(["d", "c"])
  })

  it("ignores rows that are already listed or older than the top", () => {
    const peek = [top, s("old", "2026-11-25T08:00:00Z")]
    expect(freshRows(peek, shown)).toEqual([])
  })

  it("has nothing to compare with when the list is empty", () => {
    expect(freshRows([s("x", "2026-11-25T10:00:00Z")], [])).toEqual([])
  })
})
