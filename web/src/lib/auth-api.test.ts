import { afterEach, describe, expect, it, vi } from "vitest"
import { ApiError } from "@/lib/api"
import { LoginError, loginRequest, safeNext } from "./auth-api"

describe("safeNext", () => {
  it("keeps same-app paths", () => {
    expect(safeNext("/attacks?sensor=ssh#x")).toBe("/attacks?sensor=ssh#x")
  })
  it.each([
    null,
    undefined,
    "",
    "attacks",
    "//evil.example",
    "https://evil.example",
    "/\\evil",
    "/login",
    "/login?next=/a",
  ])("falls back for %s", (raw) => expect(safeNext(raw)).toBe("/"))
  it.each([
    "/a b",
    "/a\tb",
    "/a\nb",
    "/\u0000x",
    "/a\x7fb",
    "/.//evil.example",
    "/x/..//evil.example",
  ])("rejects whitespace, control characters and dot-segment tricks: %j", (raw) =>
    expect(safeNext(raw)).toBe("/"),
  )
  it("keeps encoded slashes, which stay inside the path", () => {
    expect(safeNext("/%2f%2fevil")).toBe("/%2f%2fevil")
  })
})

describe("loginRequest", () => {
  afterEach(() => vi.unstubAllGlobals())
  const reply = (status: number) =>
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(status === 204 ? null : "{}", { status })),
    )

  it("resolves on 204", async () => {
    reply(204)
    await expect(loginRequest("admin", "pw")).resolves.toBeUndefined()
  })
  it.each([
    [401, "invalid"],
    [429, "rate-limited"],
    [403, "origin"],
    [500, "network"],
  ])("maps %i to %s", async (status, reason) => {
    reply(status)
    await expect(loginRequest("a", "b")).rejects.toMatchObject({ reason })
  })
  it("maps a network failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")))
    await expect(loginRequest("a", "b")).rejects.toBeInstanceOf(LoginError)
  })
  it("never sends the CSRF header for login", async () => {
    reply(204)
    await loginRequest("a", "b")
    const init = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[1] as RequestInit
    expect(init.credentials).toBe("same-origin")
    expect(Object.keys(init.headers as object)).not.toContain("X-CSRF-Token")
  })
})

describe("ApiError", () => {
  it("is exported for status checks", () => {
    expect(new ApiError(401, "x").status).toBe(401)
  })
})
