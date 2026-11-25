import type { MouseEvent } from "react"
import type { DataRouter } from "react-router"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import {
  changesPage,
  installViewTransitions,
  markSubject,
  resetSubject,
  subjectName,
  subjectProps,
} from "./view-transitions"

const at = (pathname: string, search = "") => ({ pathname, search })

describe("changesPage", () => {
  it("animates a change of page, a detail page included", () => {
    expect(changesPage(at("/"), at("/attacks"))).toBe(true)
    expect(changesPage(at("/attackers"), at("/attackers/192.0.2.1"))).toBe(true)
  })

  it("does not animate filters or a ?tab= on the same page", () => {
    expect(changesPage(at("/attacks"), at("/attacks", "?sensor=ssh"))).toBe(false)
    expect(changesPage(at("/settings"), at("/settings", "?tab=keys"))).toBe(false)
  })
})

function byId(id: string): HTMLElement {
  const el = document.getElementById(id)
  if (!el) throw new Error(`no #${id}`)
  return el
}

function click(target: HTMLElement, init: Partial<MouseEvent<HTMLElement>> = {}) {
  return {
    button: 0,
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    currentTarget: target,
    ...init,
  } as MouseEvent<HTMLElement>
}

describe("shared element", () => {
  beforeEach(() => {
    resetSubject()
    document.body.innerHTML = `
      <div data-vt-row><a id="a"></a><span data-vt-subject="attacker:1"></span></div>
      <div data-vt-row><a id="b"></a><span data-vt-subject="attacker:2"></span></div>`
    // jsdom lays nothing out: report a box for every element.
    vi.spyOn(Element.prototype, "getClientRects").mockReturnValue([{}] as unknown as DOMRectList)
  })
  afterEach(() => vi.restoreAllMocks())

  it("names only the clicked row's element, and clears the previous one", () => {
    const [first, second] = document.querySelectorAll<HTMLElement>("[data-vt-subject]")
    markSubject("attacker:1", click(byId("a")))
    expect(first?.style.viewTransitionName).toBe("vt-subject")
    markSubject("attacker:2", click(byId("b")))
    expect(first?.style.viewTransitionName).toBe("")
    expect(second?.style.viewTransitionName).toBe("vt-subject")
  })

  it("leaves a modified click (new tab) alone", () => {
    markSubject("attacker:1", click(byId("a"), { metaKey: true }))
    const [first] = document.querySelectorAll<HTMLElement>("[data-vt-subject]")
    expect(first?.style.viewTransitionName).toBe("")
  })

  it("gives the name to no one until a navigation takes the subject", () => {
    expect(subjectName("attacker:1")).toBeUndefined()
    expect(subjectProps("attacker:1")).toEqual({
      "data-vt-subject": "attacker:1",
      style: { viewTransitionName: undefined },
    })
  })
})

describe("installViewTransitions", () => {
  function fakeRouter() {
    const state = {
      location: { pathname: "/attackers", search: "", hash: "", state: null, key: "a" },
    }
    const navigate = vi.fn<(to: unknown, opts?: unknown) => Promise<void>>(() => Promise.resolve())
    const router = {
      state,
      basename: "/",
      navigate,
      subscribe: () => () => undefined,
    } as unknown as DataRouter
    return { router, navigate }
  }

  beforeEach(() => {
    resetSubject()
    Object.defineProperty(document, "startViewTransition", {
      configurable: true,
      value: () => undefined,
    })
  })
  afterEach(() => {
    delete (document as { startViewTransition?: unknown }).startViewTransition
  })

  it("turns the transition on for page changes only", async () => {
    const { router, navigate } = fakeRouter()
    installViewTransitions(router)
    await router.navigate("/attackers/192.0.2.1")
    expect(navigate).toHaveBeenLastCalledWith("/attackers/192.0.2.1", { viewTransition: true })

    await router.navigate("?country=FR", { preventScrollReset: true })
    expect(navigate).toHaveBeenLastCalledWith("?country=FR", { preventScrollReset: true })
  })

  it("keeps a link's explicit opt-out", async () => {
    const { router, navigate } = fakeRouter()
    installViewTransitions(router)
    await router.navigate("/attacks", { viewTransition: false })
    expect(navigate).toHaveBeenLastCalledWith("/attacks", { viewTransition: false })
  })

  it("does nothing where the browser has no view transitions", async () => {
    delete (document as { startViewTransition?: unknown }).startViewTransition
    const { router, navigate } = fakeRouter()
    installViewTransitions(router)
    await router.navigate("/attacks")
    expect(navigate).toHaveBeenLastCalledWith("/attacks")
  })
})
